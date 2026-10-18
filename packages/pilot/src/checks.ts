// Per-check execution ledger — pilot side. Every instrumented tool path records its REAL outcome
// through recordCheck(); the screen_done gate and the UI read these rows, never the model's
// self-reported coverage array. Plan rows ("planned") are written from the methodology and bound to
// concrete (target, param) slots so one execution cannot satisfy other inputs/roles.

import { createHash } from "node:crypto";
import { checkKey } from "@veritas/core";
import { normalizePath } from "@veritas/crawler";
import type { CheckExecution, CheckStatus } from "@veritas/core";
import type { PilotSession } from "./tools.js";

/** Opaque digest of the session material actually sent — same material ⇒ same ref; an account switch
 *  under the same cookie file / role name ⇒ a different ref. Irreversible; never persists raw creds.
 *  Callers pass the EFFECTIVE headers (defaults merged) so inherited Basic/Cookie/custom auth counts. */
export function sessionRefOf(headers: Readonly<Record<string, string>>): string {
  const canon = Object.entries(headers)
    .filter(([k]) => /^(cookie|authorization|x-|proxy-authorization)/i.test(k) || headersAuthRelevant(k))
    .map(([k, v]) => `${k.toLowerCase()}:${v}`)
    .sort()
    .join("\n");
  return createHash("sha256").update(canon).digest("hex").slice(0, 16);
}

/** Headers that carry identity/authorization even though they aren't cookie/authorization/x-*. */
function headersAuthRelevant(name: string): boolean {
  return /token|auth|session|api[-_]?key/i.test(name);
}

/** The web origin (https://host:port) a request was sent to — part of the check key. */
export function webOriginOf(url: string, base: string): string {
  try {
    return new URL(url, base).origin;
  } catch {
    return "";
  }
}

/** The ledger target for a request surface — same template normalization as inventory/dedup, so a
 *  probe against /orders/o10 lands on the plan slot for /orders/{id}. GraphQL ops get their
 *  operationKey appended ("POST /graphql#name:X:hash") so distinct POST /graphql ops stay distinct. */
export function checkTargetOf(method: string, url: string, base: string, operationKey?: string): string {
  let path: string;
  try {
    path = decodeURIComponent(new URL(url, base).pathname);
  } catch {
    path = url.split("?")[0] ?? url;
  }
  let template: string;
  try {
    template = normalizePath(path).template;
  } catch {
    template = path.toLowerCase();
  }
  return `${method.toUpperCase()} ${template}${operationKey ? `#${operationKey}` : ""}`;
}

/** The subject context stamped on a check row: the role label PLUS, when established, the verified
 *  principal and operator-declared tenant. Role names alone never identify a principal. */
export interface SubjectCtx {
  subject: string;
  principal?: string;
  tenant?: string;
}

export function subjectCtx(s: PilotSession, role: string | undefined): SubjectCtx {
  const subject = role ?? (s.currentRole || "unauth");
  return {
    subject,
    principal: s.sessionPrincipals?.get(subject)?.principal ?? s.rolePrincipals?.get(subject),
    tenant: s.roleTenants?.get(subject),
  };
}

export interface CheckWrite {
  /** Defaults to the screen currently being diagnosed. */
  screenId?: string;
  /** "GET /orders/{id}" style — build with checkTargetOf, or "*" for screen-level rows. */
  target: string;
  /** Parameter / JSON pointer exercised, when applicable. */
  param?: string;
  /** The concrete object exercised (id or AuthzObject.key) — object-scoped checks only. */
  resource?: string;
  /** Role label override (default: the session's current role). */
  subject?: string;
  /** Override principal/tenant (e.g. a compare leg explicitly tagged with the other subject). */
  principal?: string;
  tenant?: string;
  /** Effective headers actually sent (default = current session material) — digested into `session`. */
  sessionHeaders?: Record<string, string>;
  /** Precomputed session ref — used when the row inherits a proven execution's exact session identity. */
  session?: string;
  /** Origin override (else derived from `url`). */
  origin?: string;
  /** Request URL used for origin derivation. */
  url?: string;
  checkClass: string;
  status: CheckStatus;
  /** Concrete reason — REQUIRED for unverified/blocked/not-applicable. */
  reason?: string;
  tool: string;
  baselineOk?: boolean;
  evidenceIds?: string[];
  findingIds?: string[];
  detail?: string;
}

/** Persist one ledger row through the store (appends `check_recorded` → lastSeq moves → WS pushes).
 *  Returns the row key. Safe to call for every probe exit — upserts dedup by the deterministic key. */
export function recordCheck(s: PilotSession, w: CheckWrite): string {
  const subj = subjectCtx(s, w.subject);
  const headers = w.sessionHeaders ?? s.http.effectiveHeaders(authHdrs(s), true);
  const row: CheckExecution = {
    id: "",
    screenId: w.screenId ?? s.currentScreenId ?? "pilot",
    target: w.target,
    param: w.param,
    resource: w.resource,
    subject: w.subject !== undefined ? w.subject : subj.subject,
    principal: w.principal ?? subj.principal,
    tenant: w.tenant ?? subj.tenant,
    origin: w.origin ?? (w.url ? webOriginOf(w.url, s.targetUrl) : webOriginOf(s.targetUrl, s.targetUrl)),
    session: w.session ?? sessionRefOf(headers),
    checkClass: w.checkClass,
    status: w.status,
    reason: w.reason,
    baselineOk: w.baselineOk,
    tool: w.tool,
    evidenceIds: w.evidenceIds ?? [],
    findingIds: w.findingIds ?? [],
    detail: w.detail,
    finishedAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  row.id = checkKey(row);
  s.store.upsertCheck(s.assessmentId, row);
  return row.id;
}

/** The session headers the CURRENT role sends on the raw-http path (cookie + bearer; defaults are
 *  merged by effectiveHeaders inside recordCheck). */
function authHdrs(s: PilotSession): Record<string, string> {
  return { ...(s.currentCookie ? { cookie: s.currentCookie } : {}), ...(s.currentBearer ? { authorization: `Bearer ${s.currentBearer}` } : {}) };
}

export interface ProbeOutcome {
  status: CheckStatus;
  reason?: string;
  evidenceIds?: string[];
  baselineOk?: boolean;
}

/** Redirect-target patterns that mean "bounced to an auth wall", not an app response. A 3xx to one
 *  of these is a session/auth outcome — the payload was never evaluated by the endpoint. */
const AUTH_REDIRECT_PATH_RE = /(?:^|\/)(?:log[-_]?in|sign[-_]?in|sign[-_]?on|auth(?:entication|enticate)?|session(?:\/new)?|sso|oauth|account\/login|unauthorized|denied)(?:[\/?.#]|$)/i;

/** Is this response an auth-wall redirect? (3xx whose Location is a login/auth URL.) */
export function isAuthRedirect(res: { status: number; headers?: Record<string, string> }): boolean {
  if (res.status < 300 || res.status >= 400 || !res.headers) return false;
  for (const [k, v] of Object.entries(res.headers)) if (k.toLowerCase() === "location") return AUTH_REDIRECT_PATH_RE.test(v);
  return false;
}

/** A body that IS an auth wall rendered inline (no redirect needed): the session was refused to a
 *  login/denied page — including a 200 whose content is the login wall. The endpoint never evaluated
 *  the request. Same vocabulary as the browser-side login detector (tools.ts LOGIN_MARKERS). */
const AUTH_WALL_BODY_RE = /sign[\s-]?in|log[\s-]?in|\bpassword\b|unauthorized|access denied|forbidden|ログイン|サインイン|認証が必要|権限/i;

/** Does the response body read as an inline auth wall? (status-agnostic — a 200 login page included.) */
export function isAuthWallBody(res: { body?: string }): boolean {
  return AUTH_WALL_BODY_RE.test((res.body ?? "").slice(0, 4000));
}

/** A proxy/gateway/edge failure rendered in the body — an infra answer, never the application.
 *  Includes a "200" proxy error page and CDN bot-challenge interstitials. */
const INFRA_ERR_BODY_RE =
  /proxy (?:error|could not|did not|refused|timed? ?out)|ERR_PROXY|upstream (?:error|refused|timed? ?out|unavailable|connect)|bad gateway|gateway (?:timeout|error)|network is unreachable|connection (?:refused|reset|timed? ?out)|ECONNREFUSED|ETIMEDOUT|squid|zscaler|websense|blue ?coat|just a moment\.\.\.|challenges\.cloudflare\.com|cf-mitigated|attention required/i;

/** Does the response body read as an infra/proxy/CDN failure (never an application answer)? */
export function isInfraErrorBody(res: { body?: string }): boolean {
  return INFRA_ERR_BODY_RE.test((res.body ?? "").slice(0, 4000));
}

/** Did the request reach the application and get a real answer? False on 5xx (server couldn't
 *  answer — not a conclusive negative), proxy auth (407), session refusals (401/403), auth-wall
 *  redirects, and bodies that are themselves the auth wall or an infra error — status alone can't
 *  tell a 200 login page from the endpoint's real content. A 4xx input denial still "reached". */
export function legReachedApp(res: { status: number; headers?: Record<string, string>; body?: string }): boolean {
  if (res.status >= 500 || res.status === 407 || res.status === 401 || res.status === 403) return false;
  if (isAuthWallBody(res) || isInfraErrorBody(res)) return false;
  return !isAuthRedirect(res);
}

/** Input-level refusals where the request was rejected BEFORE the handler evaluated it — a 422
 *  "unprocessable" or a malformed-input 400 is silence about the check, not a conclusive negative.
 *  NOT included: 404 (the resource-level "no row" the SQLi FALSE control legitimately relies on)
 *  and 401/403 (already "not reached" — no authorization decision). */
const INPUT_REFUSED_STATUSES: ReadonlySet<number> = new Set([400, 405, 406, 408, 411, 413, 414, 415, 422, 429]);

/** Did the endpoint actually EVALUATE the input on this leg? Reaching an HTTP server is not reaching
 *  the check: an invalid-input refusal means the payload never ran, and a 200 login/proxy body means
 *  nothing evaluated it. A leg that wasn't evaluated leaves the outcome unverified — never clean. */
export function legEvaluatedInput(res: { status: number; headers?: Record<string, string>; body?: string }): boolean {
  return legReachedApp(res) && !INPUT_REFUSED_STATUSES.has(res.status);
}

/** A valid baseline leg: the endpoint served real content (2xx) to this session — not a redirect,
 *  denial, input error, auth wall, or infra failure. Only a valid baseline lets a negative
 *  conclusion become tested-clean. */
export function validAppBaseline(res: { status: number; headers?: Record<string, string>; body?: string }): boolean {
  return res.status >= 200 && res.status < 300 && legReachedApp(res);
}

/** Structured probe-result → check-status extraction.
 *
 *  Design rule: NEVER manufacture "clean" or "found" from prose. The probe's own JSON contract
 *  (`result` enum + `negativeControl`/`positiveReplays`/`baselineEvidenceId`/`evidenceIds`) decides —
 *  free-form verdict text is NEVER a security conclusion. Every invocation returns an outcome so the
 *  ledger keeps an honest row: uninstrumented/ambiguous exits become `unverified` (a visible gap),
 *  not a silent pass and never a fabricated clean.
 *
 *  Status rules:
 *  - `result:"confirmed"`  → found, ONLY with the evidence floor: a distinct negativeControl id +
 *    ≥2 distinct positiveReplay ids + the baseline leg's recorded response was a valid app response
 *    (validAppBaseline). A "confirmed" claim without that floor is `unverified`, not found.
 *  - `result:"clean"`      → tested-clean, only when the baseline leg is valid — an invalid baseline
 *    (control rejected / 4xx/5xx / auth redirect) makes the negative itself unverifiable → `unverified`.
 *  - `result:"suspected"`  → suspected (a visible lead).
 *  - `result:"blocked"`    → blocked; `blocked:true`/`skipped` field or BLOCKED/REFUSED text → blocked.
 *  - No `result` field (uninstrumented/ambiguous exits) → `unverified` — a visible gap, never a
 *    fabricated clean or found. Prose like "denied"/"rejected"/"CONFIRMED" inside free text can
 *    never make anything clean or found. */
export function extractProbeOutcome(s: PilotSession, text: string): ProbeOutcome {
  const head = text.slice(0, 2000);
  const firstLine = head.split("\n", 1)[0] ?? head;
  let j: Record<string, unknown> | null = null;
  try {
    const p = JSON.parse(text) as unknown;
    if (p && typeof p === "object" && !Array.isArray(p)) j = p as Record<string, unknown>;
  } catch {
    j = null;
  }
  // ── non-JSON exits: blocked markers are honored, everything else is a visible unverified ──
  if (j === null) {
    if (/^(BLOCKED|SKIPPED|REFUSED)\b/i.test(firstLine) || /\bout of scope\b/i.test(firstLine))
      return { status: "blocked", reason: firstLine.slice(0, 300) };
    return { status: "unverified", reason: firstLine.slice(0, 300) };
  }

  const verdict = String(j.verdict ?? j.note ?? "");
  const reason = () => (verdict || firstLine).slice(0, 300);
  const negId = typeof j.negativeControl === "string" ? j.negativeControl : undefined;
  const posIds = Array.isArray(j.positiveReplays) ? j.positiveReplays.filter((x): x is string => typeof x === "string") : [];
  const ids = new Set<string>();
  if (negId) ids.add(negId);
  for (const id of posIds) ids.add(id);
  if (typeof j.baselineEvidenceId === "string") ids.add(j.baselineEvidenceId);
  if (Array.isArray(j.evidenceIds)) for (const x of j.evidenceIds) if (typeof x === "string") ids.add(x);
  const evidenceIds = [...ids];

  // Baseline validity comes from the RECORDED response, not from text: the baseline leg (explicit
  // baselineEvidenceId, else the negative control) must be a real app response — a 2xx that reached
  // the app, never a rejection, error, or auth-wall redirect.
  const baseId = typeof j.baselineEvidenceId === "string" ? j.baselineEvidenceId : negId;
  const baseRec = baseId ? s.evidence.records.find((r) => r.id === baseId) : undefined;
  const baselineOk: boolean | undefined = baseRec ? validAppBaseline(baseRec.response) : undefined;

  // A "confirmed" outcome needs the confirmation floor in evidence — the probe's own legs, not words:
  // distinct negative control + ≥2 DISTINCT positive replays + a RECORDED valid baseline. A missing
  // baseline record (baselineOk undefined) is not a baseline — the claim stays unverified.
  const evidenceFloor = !!negId && posIds.length >= 2 && new Set(posIds).size === posIds.length;
  const confirmed = (r?: string): ProbeOutcome =>
    evidenceFloor && baselineOk === true
      ? { status: "found", reason: r ?? reason(), evidenceIds, baselineOk }
      : {
          status: "unverified",
          reason: `probe reported a confirm-style outcome without the evidence floor (distinct negativeControl + 2 distinct positiveReplays + a recorded valid baseline) — ${(r ?? reason()).slice(0, 200)}`,
          evidenceIds,
          baselineOk,
        };
  const clean = (r?: string): ProbeOutcome =>
    baselineOk === true
      ? evidenceIds.length === 0
        ? { status: "unverified", reason: `negative outcome without any recorded evidence — nothing to verify: ${(r ?? reason()).slice(0, 200)}` }
        : { status: "tested-clean", reason: r ?? reason(), evidenceIds, baselineOk }
      : { status: "unverified", reason: `negative outcome reported without a recorded valid baseline (control rejected or missing — cannot distinguish "held" from "never reached"): ${(r ?? reason()).slice(0, 200)}`, evidenceIds, baselineOk };

  // Only the structured `result` field is a security conclusion — no prose, no verdict strings.
  const result = typeof j.result === "string" ? j.result : undefined;
  if (result === "confirmed") return confirmed();
  if (result === "clean") return clean();
  if (result === "suspected") return { status: "suspected", reason: reason(), evidenceIds, baselineOk };
  if (result === "blocked") return { status: "blocked", reason: reason(), evidenceIds };
  if (result === "unverified") return { status: "unverified", reason: reason(), evidenceIds, baselineOk };

  // Handling flags (not security conclusions): a tool that couldn't run is blocked; a lead is suspected.
  if (j.blocked === true || j.skipped === true) return { status: "blocked", reason: reason(), evidenceIds };
  if (j.suspected === true) return { status: "suspected", reason: reason(), evidenceIds, baselineOk };
  return { status: "unverified", reason: reason(), evidenceIds, baselineOk };
}

/** Build a plan row (status "planned"). Slots bind (screen, class, target, param):
 *  - param-scoped:  target="*", param=<name>   — satisfied by any endpoint execution on that input
 *  - target-scoped: target="METHOD /tpl(#op)"  — satisfied by an execution on that surface
 *  - screen-level:  target="*", param=undefined — satisfied by any execution of that class */
export function makePlanRow(screenId: string, checkClass: string, target: string, param: string | undefined): CheckExecution {
  const row: CheckExecution = {
    id: "",
    screenId,
    target,
    param,
    subject: "",
    checkClass,
    status: "planned",
    tool: "methodology",
    evidenceIds: [],
    findingIds: [],
    updatedAt: new Date().toISOString(),
  };
  row.id = checkKey(row);
  return row;
}
