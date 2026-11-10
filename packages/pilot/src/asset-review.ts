// Full-asset LLM review — every reachable in-scope HTML document and first-party JavaScript bundle is
// fetched once, split into bounded chunks, and EACH chunk is sent to the model exactly once (a single
// non-agent completion per chunk — no context blow-up over a 1 MB bundle). The deterministic analyzer
// (analyze_js / probe_secrets) still runs as before; this pass exists for what pattern matching cannot
// see — hardcoded credentials that match no key format, hidden endpoints, debug routes, logic hints.
//
// Coverage is per-asset and honest: `complete` requires a non-truncated fetch AND every chunk answered
// by the model. An asset the model never saw (fetch error, budget, chunk failure) stays `complete:false`
// in the asset_reviewed ledger event — unreviewed is never laundered into "nothing found".

import { createHash } from "node:crypto";
import { checkKey, isInScope, type AssetKind, type AssetObservation, type AssetReview } from "@veritas/core";
import { extractJson, type LlmClient } from "@veritas/llm";
import { recordCheck, webOriginOf } from "./checks.js";
import { authHeaders, bumpHttp, type PilotSession } from "./tools.js";

export interface FetchedAsset {
  url: string;
  kind: AssetKind;
  body: string;
  bytes: number;
  truncated: boolean;
}

export interface AssetReviewOutput {
  reviews: AssetReview[];
  /** observations across all assets, flattened for the follow-up stage. */
  observations: Array<{ url: string } & AssetObservation>;
  /** asset URLs discovered but never fetched (queue cap) — recorded as unreviewed. */
  skipped: string[];
}

const CHUNK_CHARS = 24_000;
const MAX_ASSETS = 48;
const OBSERVATION_TYPES = new Set(["credential", "secret", "endpoint", "debug", "comment", "logic", "other"]);
const SAFE_LOCATOR = /^chunk [1-9]\d*, observation [1-9]\d*(?:, char (?:0|[1-9]\d*))?$/;

/** URLs in the ledger, checks, prompts and logs are locators, NOT replayable URLs with credentials.
 * The authorized fetch still uses the original URL; the analyst can re-fetch it under the run's auth.
 * Never put userinfo, query parameters (including unknown token names), or fragments in a ledger row. */
export function safeAssetUrl(raw: string): string {
  try {
    const u = new URL(raw);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return "[invalid asset URL]";
  }
}

const REVIEW_SYSTEM = `You are reviewing one chunk of a fetched asset from an AUTHORIZED security assessment of a web application.

Report ONLY what is literally present in this chunk — never guesses or general best-practice concerns. Look specifically for:
- hardcoded credentials (username+password pairs, default accounts) even when they match no known key format
- tokens, API keys, private keys, session secrets, signing keys, seeds/mnemonics
- hidden or undocumented endpoints, routes, debug/admin URLs, internal hosts
- commented-out logic, test hooks, feature flags that weaken security
- client-side logic that suggests exploitable behavior (price/role/permission fields sent by the client, skipped validation)

Respond with ONLY this JSON:
{"observations":[{"type":"credential|secret|endpoint|debug|comment|logic|other","detail":"what it is","evidence":"verbatim snippet <=200 chars","location":"offset hint or function name","investigation":"one concrete next request/check to verify it"}]}
If nothing notable is in this chunk, respond {"observations":[]}.`;

const chunkPrompt = (a: FetchedAsset, i: number, n: number, text: string): string =>
  `Asset: ${safeAssetUrl(a.url)} (${a.kind}, ${a.bytes} bytes, chunk ${i + 1}/${n}${a.truncated ? ", body TRUNCATED at fetch bound" : ""})\n\n${text}`;

/** Model prose is untrusted: secrets can appear in ANY of detail/evidence/location/investigation,
 * including unknown formats that cannot be reliably redacted by regex. Retain only a type and a
 * deterministic, bounded chunk/ordinal locator; the source asset, not model prose, is the evidence. */
const sanitizeObs = (raw: unknown, locator: string, chunk?: string, chunkStart = 0): AssetObservation | null => {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return null;
  const o = raw as Record<string, unknown>;
  if (typeof o.type !== "string" || !OBSERVATION_TYPES.has(o.type) ||
      typeof o.detail !== "string" || !o.detail.trim() ||
      ["evidence", "location", "investigation"].some((k) => o[k] !== undefined && typeof o[k] !== "string")) return null;
  // A literal snippet match provides a more precise locator without copying any part of that snippet
  // into the event, check, or follow-up prompt. The source is already bounded at fetch time.
  const position = chunk && typeof o.evidence === "string" && o.evidence.length > 0
    ? chunk.indexOf(o.evidence) : -1;
  const uniqueMatch = position >= 0 && chunk?.indexOf(o.evidence as string, position + 1) === -1;
  const safeLocation = uniqueMatch ? `${locator}, char ${chunkStart + position}` : locator;
  return {
    type: o.type,
    detail: `Potential ${o.type} at ${safeLocation}; inspect the authorized asset before verification`,
    location: safeLocation,
    investigation: "Re-fetch the in-scope asset and verify this lead with an authorized request.",
    status: "pending",
  };
};

/** Check identity must be reproducible by BOTH enrollment and resolve_asset_review(n). Index
 * disambiguates even two indistinguishable leads on the same asset/chunk; the safe locator lets
 * an analyst find each lead without ever putting model-supplied credential text in the check key. */
export function assetObservationResource(obs: { url: string; location?: string }, index: number): string {
  const locator = obs.location && SAFE_LOCATOR.test(obs.location) ? obs.location : `list observation ${index + 1}`;
  const key = JSON.stringify([safeAssetUrl(obs.url), locator, index]);
  return `asset-review:${createHash("sha256").update(key).digest("hex").slice(0, 24)}`;
}

/**
 * Build the review queue: unique page-ish screens (non-/api//rest paths) as HTML candidates, plus every
 * first-party .js/.mjs bundle referenced by the fetched HTML. Fetches are auth-headered and bounded.
 */
export async function collectAssets(s: PilotSession, opts?: { maxAssets?: number }): Promise<{ assets: FetchedAsset[]; skipped: string[] }> {
  const assets: FetchedAsset[] = [];
  const skipped: string[] = [];
  const cap = opts?.maxAssets ?? MAX_ASSETS;
  const seen = new Set<string>();
  const enqueue = async (url: string, kind: AssetKind, maxBodyBytes: number): Promise<boolean> => {
    if (seen.has(url)) return false;
    seen.add(url);
    if (!isInScope(url, s.scope)) return false;
    if (assets.length >= cap) { skipped.push(safeAssetUrl(url)); return false; }
    try {
      const r = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null, maxBodyBytes });
      bumpHttp(s, r.status, { active: false });
      if (r.status >= 400 || !r.body) return false;
      assets.push({ url, kind, body: r.body, bytes: r.bodyBytes ?? Buffer.byteLength(r.body), truncated: !!r.truncated });
      return true;
    } catch {
      return false;
    }
  };

  // HTML: screens that are plausibly documents (exclude obvious JSON API roots + static binary extensions).
  const pageUrls = new Set<string>();
  for (const sc of s.inv.screens()) {
    for (const raw of [sc.urlTemplate, ...sc.observedUrls]) {
      try {
        const u = new URL(raw);
        if (/^\/(api|rest|socket\.io)\//i.test(u.pathname)) continue;
        if (/\.(png|jpe?g|gif|ico|svg|woff2?|ttf|map|css|pdf|zip|kdbx|bak|yml|log|gg|pyc)(\?|$)/i.test(u.pathname)) continue;
        pageUrls.add(u.toString());
      } catch { /* skip */ }
    }
  }
  const scriptUrls = new Set<string>();
  for (const purl of [...pageUrls].sort()) {
    const before = assets.length;
    if (!(await enqueue(purl, "html", 4 * 1024 * 1024))) continue;
    const last = assets[assets.length - 1];
    if (!last || assets.length === before || !/<html|<!doctype/i.test(last.body.slice(0, 4096))) {
      // Not an HTML document after all — keep it out of the queue (JSON/XML endpoints are not prose assets).
      assets.splice(assets.length - 1, 1);
      continue;
    }
    for (const m of last.body.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
      try {
        if (!m[1]) continue;
        const abs = new URL(m[1], purl).toString();
        if (/\.m?js(\?|#|$)/i.test(abs) && isInScope(abs, s.scope) && !seen.has(abs)) scriptUrls.add(abs);
      } catch { /* skip */ }
    }
  }
  for (const jurl of [...scriptUrls].sort()) await enqueue(jurl, "js", 8 * 1024 * 1024);
  return { assets, skipped };
}

/** Send every chunk of every fetched asset to the model; append an asset_reviewed ledger event per asset. */
export async function reviewAssets(args: {
  session: PilotSession;
  llm: LlmClient;
  model?: string;
  assets: FetchedAsset[];
  skipped?: string[];
  onText?: (t: string) => void;
  /** abort mid-queue (budget/stop) — processed assets are still recorded. */
  shouldAbort?: () => boolean;
}): Promise<AssetReviewOutput> {
  const { session: s, llm } = args;
  const reviews: AssetReview[] = [];
  const observations: AssetReviewOutput["observations"] = [];
  for (const asset of args.assets) {
    if (args.shouldAbort?.()) break;
    const chunks: string[] = [];
    for (let off = 0; off < asset.body.length; off += CHUNK_CHARS) chunks.push(asset.body.slice(off, off + CHUNK_CHARS));
    const obs: AssetObservation[] = [];
    let analyzed = 0;
    const failedChunks: number[] = [];
    for (let i = 0; i < chunks.length; i++) {
      if (args.shouldAbort?.()) break;
      try {
        const chunk = chunks[i];
        if (chunk === undefined) continue;
        const r = await llm.complete({ system: REVIEW_SYSTEM, prompt: chunkPrompt(asset, i, chunks.length, chunk), model: args.model, timeoutMs: 120_000 });
        const parsed = extractJson(r.text);
        if (!parsed || typeof parsed !== "object" || Array.isArray(parsed) ||
            !Array.isArray((parsed as Record<string, unknown>).observations)) {
          throw new TypeError("invalid asset-review response");
        }
        const chunkObs: AssetObservation[] = [];
        for (const [j, raw] of (parsed as { observations: unknown[] }).observations.entries()) {
          const o = sanitizeObs(raw, `chunk ${i + 1}, observation ${j + 1}`, chunk, i * CHUNK_CHARS);
          if (!o) throw new TypeError("invalid asset-review observation");
          chunkObs.push(o);
        }
        obs.push(...chunkObs); // atomic per chunk: a malformed later observation cannot imply coverage
        analyzed++;
      } catch {
        failedChunks.push(i);
      }
    }
    const review: AssetReview = {
      url: safeAssetUrl(asset.url),
      kind: asset.kind,
      bytes: asset.bytes,
      fetchedComplete: !asset.truncated,
      chunksTotal: chunks.length,
      chunksAnalyzed: analyzed,
      complete: !asset.truncated && chunks.length > 0 && analyzed === chunks.length,
      observations: obs,
      analyzedAt: new Date().toISOString(),
    };
    reviews.push(review);
    for (const o of obs) observations.push({ url: review.url, ...o });
    s.store.appendEvent(s.assessmentId, { type: "asset_reviewed", payload: review });
    args.onText?.(`  [asset-review] ${asset.kind} ${review.url}: ${analyzed}/${chunks.length} chunks, ${obs.length} observation(s)${review.complete ? "" : " — INCOMPLETE"}`);
  }
  const skipped = (args.skipped ?? []).map(safeAssetUrl);
  if (skipped.length > 0) {
    s.store.appendEvent(s.assessmentId, {
      type: "note",
      payload: { message: `asset-review queue cap: ${skipped.length} asset(s) not fetched/reviewed: ${skipped.slice(0, 10).join(", ")}${skipped.length > 10 ? "…" : ""}` },
    });
  }
  return { reviews, observations, skipped };
}

/** Exact screen URL first; first in-scope screen on the asset's own origin otherwise. Screen templates
 * are often relative, so resolve them using that screen's absolute observed URLs (or targetUrl only
 * when no observed absolute URL exists). Never attribute an unrelated host's asset to this app. */
function screenForAssetUrl(s: PilotSession, url: string): string {
  if (!isInScope(url, s.scope)) return "pilot";
  let target: URL;
  try { target = new URL(url); } catch { return "pilot"; }
  let firstSameOrigin: string | null = null;
  for (const sc of [...s.inv.screens()].sort((a, b) => a.screenId.localeCompare(b.screenId))) {
    const observed: URL[] = [];
    for (const raw of sc.observedUrls) {
      try {
        const u = new URL(raw);
        if (isInScope(u.toString(), s.scope)) observed.push(u);
      } catch { /* relative observed URL has no authoritative origin */ }
    }
    const candidates = [...observed];
    try {
      const absoluteTemplate = new URL(sc.urlTemplate);
      candidates.push(absoluteTemplate);
    } catch {
      const bases = observed.length > 0 ? observed : [new URL(s.targetUrl)];
      for (const base of bases) {
        try { candidates.push(new URL(sc.urlTemplate, base)); } catch { /* invalid template */ }
      }
    }
    const eligible = candidates.filter((u) => u.origin === target.origin && isInScope(u.toString(), s.scope));
    if (eligible.some((u) => u.toString() === target.toString())) return sc.screenId;
    if (!firstSameOrigin && eligible.length > 0) firstSameOrigin = sc.screenId;
  }
  return firstSameOrigin ?? "pilot";
}

/**
 * Enroll every observation as a PLANNED check row (class "asset-review") and park the pending list on
 * the session. The follow-up stage resolves them via resolve_asset_review; any it never reaches stay
 * planned — the completion pass re-drives the owning screen with the detail as its goal.
 */
export function enrollObservations(s: PilotSession, observations: AssetReviewOutput["observations"]): void {
  const previous = new Map(s.store.checks(s.assessmentId).map((c) => [c.id, c]));
  s.pendingAssetObs = observations.map((raw, index) => {
    // Also sanitize caller-provided observations: these go into the follow-up goal in run.ts.
    const locator = raw.location && SAFE_LOCATOR.test(raw.location) ? raw.location : `list observation ${index + 1}`;
    const sanitized = sanitizeObs(raw, locator);
    // Invalid externally supplied leads cannot be marked verified from model prose. Keep them as
    // a generic, still-planned lead rather than copying untrusted fields into the ledger.
    const safeObs: { url: string } & AssetObservation = { url: safeAssetUrl(raw.url), ...(sanitized ?? {
      type: "other",
      detail: `Potential lead at ${locator}; inspect the authorized asset before verification`,
      location: locator,
      status: "pending" as const,
    }) };
    const screenId = screenForAssetUrl(s, raw.url);
    const target = `ASSET ${safeObs.url}`;
    const resource = assetObservationResource(safeObs, index);
    const context = {
      screenId,
      target,
      resource,
      // These are observation slots, not per-login executions: resolving after login or resume
      // must address the SAME key (the resolver must pass these identity dimensions as well).
      subject: "asset-review",
      principal: "",
      tenant: "",
      session: "",
      url: safeObs.url,
      checkClass: "asset-review",
    };
    const id = checkKey({ ...context, origin: webOriginOf(context.url, s.targetUrl) });
    const existing = previous.get(id);
    // An interrupted run can replay enrollment. A resolved check is the authoritative outcome;
    // never overwrite it with a fresh "planned" row on resume.
    const checkId = existing && existing.status !== "planned" ? existing.id : recordCheck(s, {
      ...context,
      status: "planned",
      reason: "asset-review observation pending verification",
      tool: "asset-review",
      detail: `[${safeObs.type}] ${safeObs.detail}${safeObs.investigation ? ` → ${safeObs.investigation}` : ""}`,
    });
    return { obs: safeObs, checkId, screenId };
  });
}
