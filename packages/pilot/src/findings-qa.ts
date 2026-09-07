// Independent QA of the agent's OWN findings — the pass Burp High+ already had (verifyBurpFindings)
// and diagnosis never did. The diagnosis model records what probe_* told it; that is not a second opinion.
// This runs after diagnosis, before report:
//   1. Mechanical oracles on cited evidence (HTML-length SQLi, people-picker / store-locator IDOR,
//      public-by-design client credentials, robots.txt/sitemap, versionless product-family A06, WAF block pages).
//      These do not ask the same model to agree — that is why Valero /search shipped as High.
//   2. Remaining High/Critical AND weak-oracle classes (idor/sqli/rce/session/csrf — "confirmed" on a length/status
//      differential, not a strong content marker) get an ADVERSARIAL DEEP-model panel: independent skeptics, each with
//      a different lens (exploitability / scanner-FP catalog / reproducibility) over the signal-centered RAW evidence,
//      majority-demotes. The first writeup is NOT shown (otherwise it rubber-stamps SharePoint-hive "2013").
// Demote-only: the review can DROP a false positive (→ suspected, info, [qa?] so it leaves the confirmed headline) but
// NEVER promote — the deterministic evidence floor stays the confirm authority, so an over-confident model can't talk a
// fake into "confirmed". This is the FP filter; it does not create findings the diagnosis never actually tested.

import type { AssessmentStore, Finding, Severity } from "@veritas/core";
import { findingVerdict } from "@veritas/core";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";
import type { EvidenceRecord, EvidenceStore } from "@veritas/scanner";
import { classifyCrossUserBody, impactOracle, isPublicByDesignClientCredential, isVersionlessComponentLead } from "@veritas/scanner";
import { looksBlocked, sqliHtmlLengthOnlyFp } from "./tools.js";
import { looksLikePublicWebFile } from "./disclosure.js";
import { consolidateFindings, qualifyFinding } from "./finding-review.js";

export interface FindingsQaDeps {
  store: AssessmentStore;
  assessmentId: string;
  evidence: EvidenceStore;
  /** Mutated in place (same objects as findingsByKey). */
  findings?: Finding[];
  llm?: LlmClient;
  model?: string;
  onText?: (t: string) => void;
}

export interface FindingsQaResult {
  checked: number;
  demoted: number;
  kept: number;
  merged: number;
  qualified: number;
}

export type QaJudgment = { demote: false } | { demote: true; reason: string };

const SKIP_CATEGORIES = new Set(["headers", "rate-limit", "misconfig"]);
const HIGH_PLUS = new Set<Severity>(["high", "critical"]);
// Confirmed classes whose oracle is a body-length/status differential (not a strong content marker). These are the
// FP-prone ones, so they get the skeptical Deep review at ANY severity — not just High+ — because a length-delta
// "confirmed" is exactly where a second opinion pays off (a medium IDOR/SQLi is where the mechanical floor is weakest).
const WEAK_ORACLE_CATEGORIES = new Set(["idor", "idor-write", "sqli", "rce", "session", "csrf"]);

export function categoryOfFinding(f: Finding): string {
  const m = /^\[([a-z0-9-]+)\]/i.exec(f.title);
  return (m?.[1] ?? "").toLowerCase();
}

function isBurp(f: Finding): boolean {
  return f.source.kind === "validator" && (f.source.validatorName === "burp" || f.source.validatorName.startsWith("burp"));
}

function alreadyQad(f: Finding): boolean {
  return /^\[qa[?✓]\]/.test(f.title) || /findings QA/i.test(f.description);
}

function bodiesOf(evidence: EvidenceStore, ids: string[]): { control: string; positives: string[]; controlStatus: number; positiveStatuses: number[]; recs: EvidenceRecord[] } | null {
  const recs: EvidenceRecord[] = [];
  for (const id of ids) {
    const r = evidence.records.find((x) => x.id === id);
    if (!r) return null;
    recs.push(r);
  }
  const control = recs.find((r) => r.kind === "negative_control") ?? recs[0];
  if (!control) return null;
  const positives = recs.filter((r) => r.kind === "positive_replay" && r !== control);
  if (positives.length === 0) return null;
  return { control: control.response.body, positives: positives.map((r) => r.response.body), controlStatus: control.response.status, positiveStatuses: positives.map((r) => r.response.status), recs };
}

/** Pure: scanner-style FPs. Confirmed probes, plus suspected A06 with no version. */
export function judgeConfirmedFinding(f: Finding, evidence: EvidenceStore): QaJudgment {
  if (isBurp(f) || alreadyQad(f)) return { demote: false };
  const cat = categoryOfFinding(f);
  if (SKIP_CATEGORIES.has(cat)) return { demote: false };
  const verdict = findingVerdict(f);

  if (cat === "vulnerable-component") {
    const recs: EvidenceRecord[] = [];
    for (const id of f.evidenceIds) {
      const r = evidence.records.find((x) => x.id === id);
      if (r) recs.push(r);
    }
    const writeup = `${f.title}\n${f.anomaly ?? ""}\n${f.description}`;
    const versionless =
      recs.length === 0 || recs.every((r) => isVersionlessComponentLead(writeup, r.response.headers, r.response.body));
    if (versionless)
      return {
        demote: true,
        reason:
          "product family / banner without a concrete version is not A06 — cannot attribute a CVE. Internet-exposed F5/WAF/VPN login is not a finding.",
      };
    if (verdict !== "confirmed") return { demote: false };
  }

  if (verdict !== "confirmed") return { demote: false };
  const got = bodiesOf(evidence, f.evidenceIds);
  if (!got) return { demote: false };

  if (cat === "sqli" && sqliHtmlLengthOnlyFp(got.control, got.positives, got.controlStatus, got.positiveStatuses))
    return { demote: true, reason: "HTML/text length-only SQLi (search/result-page variance) — not a JSON/XML boolean differential, SQL error, or time-based proof. Scanner-style false positive." };

  if ((cat === "idor" || cat === "idor-write") && got.positives.every((b) => classifyCrossUserBody(b).class === "public-directory"))
    return { demote: true, reason: "public directory (people-picker profile card, or store/location/dealer locator) — typically intended, not IDOR." };

  if (cat === "secret-exposure" && got.positives.every((b) => isPublicByDesignClientCredential(b)))
    return { demote: true, reason: "client credential is public by design (Maps JS key, Firebase web apiKey, or reCAPTCHA site key) — not a secret." };

  if (cat === "info-disclosure" && got.positives.every((b) => looksLikePublicWebFile(b)))
    return { demote: true, reason: "robots.txt / sitemap.xml is a public file; a Sitemap: line is not info-disclosure." };

  if (got.recs.every((r) => looksBlocked(r.response)))
    return { demote: true, reason: "cited responses are WAF/bot-challenge pages, not the application — length/status on a block page is not a finding." };

  return { demote: false };
}

const TRIAGE_SYSTEM =
  "You independently triage a vulnerability an automated pentest agent already recorded. Automated probes produce scanner-style false positives. Assume false_positive until the RAW HTTP evidence (status, headers, body) proves an exploitable effect or a concrete versioned banner that matches a known High/Critical CVE. You are NOT shown the original writeup — do not trust a title you cannot see.\n\n" +
  "Evidence format: a body may be shown as head + a window CENTERED on the signal (an impact marker, or the byte where the positive diverges from the control); `…[NB]…` marks omitted bytes, so absence of proof in-frame is meaningful. An 'impact-oracle flagged:' line lists what an automated oracle thinks leaked — treat it as a CLAIM to verify (a real exploited effect vs public-by-design / ambient noise), never as proof on its own.\n\n" +
  "Hard rules:\n" +
  "- An HTML search/marketing page whose length changes with the query is NOT SQL injection. false_positive.\n" +
  "- A tenant people-picker card (displayName + work email + photo + tenant) is NOT IDOR. false_positive.\n" +
  "- A public store/location/dealer locator (og:type place, Find a Station, sequential store ids, gas-station address and coordinates) is NOT IDOR. false_positive.\n" +
  "- A Google Maps JavaScript API key, Firebase web apiKey, or reCAPTCHA site key in client HTML/JS is public by design. NOT secret-exposure. false_positive.\n" +
  "- Endpoint names containing admin do not establish an authorization requirement. Check whether the returned configuration is intentionally consumed by the public frontend; a sibling route returning 401 does not prove this route must require admin.\n" +
  "- An accepted upload or script bytes served as an image do not prove browser execution. Negative deposits do not prove external payout. A token containing role=admin does not prove access to an admin-only operation without a valid low-privilege denial control.\n" +
  "- Ten failed logins only establish no throttling within that sample, not unlimited attempts. Hash disclosure is distinct from recovered plaintext or account takeover.\n" +
  "- robots.txt / sitemap.xml is a public file. NOT info-disclosure. false_positive.\n" +
  "- A product-family banner (Server: BigIP, VPN/WAF/APM) with no version is NOT a vulnerable-component. false_positive.\n" +
  "- A SharePoint hive path (/_layouts/15/, corev15.css) is NOT SharePoint Server 2013 and does not prove CVE-2019-0604. false_positive. Keep only if a build header (MicrosoftSharePointTeamServices: 15.0.0.xxxx) is in the evidence.\n" +
  "- A Server/X-Powered-By/script banner that includes a concrete version (Apache/2.4.49, PHP/7.4.3, jquery-1.12.4) IS a version-based lead — keep it (not false_positive) when that version is known-vulnerable. Do not invent a version from a URL path digit.\n" +
  "- A JSON or XML API whose TRUE vs FALSE SQL payloads return extra rows / a stable structured differential IS SQL injection. confirmed.\n" +
  "- A body containing TIME-BASED BLIND SQLi CONFIRMED IS SQL injection. confirmed.\n" +
  "- Phone, home address, SSN/DOB, or another user's order/hold/document in a cross-user body IS IDOR. confirmed.\n" +
  "Reply JSON only: {\"verdict\":\"confirmed\"|\"false_positive\",\"reason\":\"one sentence\"}.";

/** Show the reviewer the DISCRIMINATING slice of a body, NOT the boilerplate head. For a large page the first N chars
 *  are `<head>`/nav — useless, and the real proof (a leaked secret / PII / file content / reflected payload, or the
 *  region where the positive diverges from the control) sits deep in the body. Center a window on the SIGNAL: an impact
 *  marker if we have one, else the first byte where the positive diverges from the control. Head + signal-window + tail
 *  so the proof (or its absence) is actually in frame even for a 50KB response. Whitespace-collapsed for density. */
export function evidenceView(body: string, opts: { control?: string; marker?: string } = {}): string {
  const HEAD = 700;
  const WIN = 1400;
  const TAIL = 400;
  const WHOLE = 3800;
  const collapse = (s: string): string => s.replace(/\s+/g, " ").trim();
  if (body.length <= WHOLE) return collapse(body);
  let idx = opts.marker ? body.indexOf(opts.marker) : -1;
  if (idx < 0 && opts.control !== undefined) {
    const n = Math.min(body.length, opts.control.length);
    let i = 0;
    while (i < n && body[i] === opts.control[i]) i += 1;
    if (i < body.length) idx = i; // first byte where the positive diverges from the control
  }
  const head = collapse(body.slice(0, HEAD));
  const tail = collapse(body.slice(body.length - TAIL));
  if (idx < 0) return `${head} …[+${body.length - HEAD - TAIL}B omitted]… ${tail}`;
  const from = Math.max(HEAD, idx - WIN);
  const to = Math.min(body.length - TAIL, idx + WIN);
  return `${head} …[${from}B]… ${collapse(body.slice(from, to))} …[+${body.length - to}B]… ${tail}`;
}

const TRIAGE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "microsoftsharepointteamservices", "x-generator", "via", "content-type", "set-cookie", "location", "www-authenticate", "access-control-allow-origin", "access-control-allow-credentials"];

function headerGlance(headers: Record<string, string>): string {
  const lc: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lc[k.toLowerCase()] = v;
  const bits = TRIAGE_HEADERS.map((k) => (lc[k] ? `${k}: ${lc[k].slice(0, 80)}` : "")).filter(Boolean);
  return bits.length > 0 ? bits.join(" | ") : "(no version/server headers)";
}

/** The raw-evidence prompt every reviewer sees: category/severity + the control and each positive as
 *  header-glance + impact-oracle hits + a signal-centered body window (evidenceView). null when no bodies. */
function buildEvidencePrompt(f: Finding, evidence: EvidenceStore): string | null {
  const got = bodiesOf(evidence, f.evidenceIds);
  if (!got) return null;
  const ctrl = got.recs.find((r) => r.kind === "negative_control") ?? got.recs[0]!;
  const pos = got.recs.filter((r) => r.kind === "positive_replay" && r !== ctrl);
  const posLine = (r: EvidenceRecord, i: number): string => {
    // Re-run the impact oracle vs the control body so the window centers on the ACTUAL leaked marker (not the head),
    // and tell the reviewer what an automated oracle flagged — its job is to judge whether that is a real exploited
    // effect or public-by-design / ambient noise.
    const hits = impactOracle(r.response.body, { baselineBody: ctrl.response.body });
    const marker = hits[0]?.marker !== undefined ? String(hits[0]!.marker) : undefined;
    const impactStr = hits.length
      ? `\nimpact-oracle flagged: ${hits.slice(0, 3).map((h) => `${h.kind}=${JSON.stringify(String(h.marker).slice(0, 80))}`).join(", ")}`
      : "";
    return `positive#${i + 1}: status ${r.response.status} len ${r.response.body.length} ${headerGlance(r.response.headers)}${impactStr}\n${evidenceView(r.response.body, { control: ctrl.response.body, ...(marker ? { marker } : {}) })}`;
  };
  return (
    `category: ${categoryOfFinding(f) || "?"}\nseverity: ${f.severity}\n` +
    `control: status ${ctrl.response.status} len ${ctrl.response.body.length} ${headerGlance(ctrl.response.headers)}\n${evidenceView(ctrl.response.body)}\n` +
    pos.map(posLine).join("\n")
  );
}

// The adversarial panel: independent skeptics, each with a DIFFERENT lens over the SAME raw evidence. A single reviewer
// anchors on a plausible story; diverse lenses catch failure modes redundancy misses. A finding is demoted only when a
// MAJORITY refute. Demote-only, never promote — the deterministic evidence floor stays the confirm authority.
const REVIEW_LENSES: ReadonlyArray<{ key: string; guidance: string }> = [
  { key: "exploitability", guidance: "LENS — exploitability: verdict false_positive UNLESS the positive body carries a concrete exploited EFFECT the control does not — a leaked secret/PII, cross-user data, real file content, command/query output, or an unescaped payload in a live HTML context. A status flip, a body-length difference, or the input merely echoed back is NOT an exploited effect." },
  { key: "scanner-fp", guidance: "LENS — known scanner false positives: apply the catalog strictly. A public directory / people-picker / store-locator is not IDOR; a public-by-design client key (Maps/Firebase/reCAPTCHA) is not secret-exposure; robots.txt/sitemap is not info-disclosure; a product-family banner without a concrete version is not A06; a WAF/challenge page length is not a finding; an HTML search/marketing page whose length changes with the query is not SQLi. If the evidence matches any, false_positive." },
  { key: "reproducibility", guidance: "LENS — reproducibility & control: verdict false_positive UNLESS the negative control genuinely FAILS (or lacks the effect) AND the positives genuinely SUCCEED showing the SAME discriminating signal. If control and positive are ~indistinguishable, or the 'impact-oracle flagged' marker is actually present in the control too / is ambient, false_positive." },
];

/** One skeptic: a single Deep-model call with the base skeptical prompt + one lens. Returns fp/keep, or null on an
 *  unparseable/failed call (an abstention — it does not count toward the panel). */
async function reviewOnce(prompt: string, guidance: string, llm: LlmClient, model?: string): Promise<{ fp: boolean; reason: string } | null> {
  try {
    const res = await llm.complete({ prompt, system: `${TRIAGE_SYSTEM}\n\n${guidance}`, ...(model ? { model } : {}), timeoutMs: 60_000 });
    const parsed = extractJson(res.text) as { verdict?: string; reason?: string };
    if (parsed.verdict === "false_positive") return { fp: true, reason: (parsed.reason ?? "").slice(0, 200) };
    if (parsed.verdict === "confirmed") return { fp: false, reason: (parsed.reason ?? "").slice(0, 200) };
    return null; // abstain (unparseable)
  } catch {
    return null; // LLM/parse failure → abstain; mechanical oracles already ran
  }
}

async function adversarialReview(f: Finding, evidence: EvidenceStore, llm: LlmClient, model?: string): Promise<QaJudgment> {
  const prompt = buildEvidencePrompt(f, evidence);
  if (prompt === null) return { demote: false };
  const votes = (await Promise.all(REVIEW_LENSES.map((l) => reviewOnce(prompt, l.guidance, llm, model)))).filter(
    (v): v is { fp: boolean; reason: string } => v !== null,
  );
  if (votes.length < 2) return { demote: false }; // no quorum (< 2 skeptics answered) → keep; can't run a panel
  const fp = votes.filter((v) => v.fp);
  if (fp.length * 2 > votes.length) {
    const reasons = fp.map((v) => v.reason).filter(Boolean).slice(0, 2).join(" | ");
    return { demote: true, reason: `adversarial review — ${fp.length}/${votes.length} skeptics judged false positive${reasons ? `: ${reasons}` : ""}`.slice(0, 300) };
  }
  return { demote: false };
}

function demote(store: AssessmentStore, assessmentId: string, f: Finding, reason: string): void {
  f.verdict = "suspected";
  f.severity = "info";
  f.anomaly = reason;
  if (!f.title.startsWith("[qa?]")) f.title = `[qa?] ${f.title}`;
  f.description = `⚠ LIKELY FALSE POSITIVE — findings QA: ${reason}\n\n${f.description}`;
  store.upsertFinding(assessmentId, f);
  store.appendEvent(assessmentId, { type: "note", payload: { message: `⚠ findings QA ${f.id}: demoted — ${reason.slice(0, 200)}` } });
}

/** QA the agent's confirmed findings. Mechanical first, then skeptical AI on remaining High+. */
export async function triagePilotFindings(deps: FindingsQaDeps): Promise<FindingsQaResult> {
  const state = deps.store.loadAssessment(deps.assessmentId);
  const list = deps.findings ?? state?.findings ?? [];
  let qualified = 0;
  for (const f of list) {
    if (f.duplicateOf) continue;
    const reason = qualifyFinding(f, deps.evidence);
    if (reason) {
      qualified++;
      deps.store.upsertFinding(deps.assessmentId, f);
      deps.store.appendEvent(deps.assessmentId, { type: "note", payload: { message: `Findings review ${f.id}: ${reason}` } });
    }
  }
  const merged = consolidateFindings(list, deps.evidence);
  if (merged) {
    // Persist merged evidence before hiding any superseded row, including when the canonical row came later.
    for (const f of list.filter(f => !f.duplicateOf)) deps.store.upsertFinding(deps.assessmentId, f);
    for (const f of list.filter(f => f.duplicateOf)) deps.store.upsertFinding(deps.assessmentId, f);
  }
  let checked = 0;
  let demoted = 0;
  const leftover: Finding[] = [];
  for (const f of list) {
    if (f.duplicateOf || isBurp(f) || alreadyQad(f) || SKIP_CATEGORIES.has(categoryOfFinding(f))) continue;
    const v = findingVerdict(f);
    const a06suspect = v === "suspected" && categoryOfFinding(f) === "vulnerable-component";
    if (v !== "confirmed" && !a06suspect) continue;
    checked += 1;
    const j = judgeConfirmedFinding(f, deps.evidence);
    if (j.demote) {
      demote(deps.store, deps.assessmentId, f, j.reason);
      demoted += 1;
      deps.onText?.(`⚠ findings QA ${f.id}: ${j.reason.slice(0, 160)}`);
    } else if ((HIGH_PLUS.has(f.severity) || WEAK_ORACLE_CATEGORIES.has(categoryOfFinding(f))) && (v === "confirmed" || categoryOfFinding(f) === "vulnerable-component")) leftover.push(f);
  }
  if (deps.llm) {
    for (const f of leftover) {
      if (!HIGH_PLUS.has(f.severity) && !WEAK_ORACLE_CATEGORIES.has(categoryOfFinding(f))) continue;
      const j = await adversarialReview(f, deps.evidence, deps.llm, deps.model);
      if (j.demote) {
        demote(deps.store, deps.assessmentId, f, j.reason);
        demoted += 1;
        deps.onText?.(`⚠ findings QA (adversarial) ${f.id}: ${j.reason.slice(0, 160)}`);
      }
    }
  }
  return { checked, demoted, kept: checked - demoted, merged, qualified };
}
