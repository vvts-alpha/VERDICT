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

export function subjectCtx(s: PilotSession, role: string | undefined, sessionRef?: string): SubjectCtx {
  const subject = role ?? (s.currentRole || "unauth");
  // A whoami result is a statement about the material that made THAT request, not a role
  // label. For another role, callers must supply the ref of the headers they actually sent.
  const ref = sessionRef ?? (subject === s.currentRole
    ? sessionRefOf(s.http.effectiveHeaders(authHdrs(s), true))
    : undefined);
  const cached = s.sessionPrincipals?.get(subject);
  // Operator declarations are only a fallback where no identity endpoint was configured:
  // if whoami was configured but a rotated session has not been verified, identity is unknown.
  return {
    subject,
    principal: cached && cached.sessionRef === ref && ref !== undefined
      ? cached.principal
      : !s.roleIdentityUrls?.has(subject) ? s.rolePrincipals?.get(subject) : undefined,
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
  reasonCode?: CheckExecution["reasonCode"];
  tool: string;
  baselineOk?: boolean;
  evidenceIds?: string[];
  findingIds?: string[];
  detail?: string;
  /** Invocation start, captured before the tool performs any async work (not at persistence time). */
  startedAt?: string;
}

/** Persist one ledger row through the store (appends `check_recorded` → lastSeq moves → WS pushes).
 *  Returns the row key. Safe to call for every probe exit — upserts dedup by the deterministic key. */
export function recordCheck(s: PilotSession, w: CheckWrite): string {
  const headers = w.sessionHeaders ?? s.http.effectiveHeaders(authHdrs(s), true);
  // If both are present, the actual sent headers outrank a claimed precomputed ref.
  const session = w.sessionHeaders ? sessionRefOf(w.sessionHeaders) : w.session ?? sessionRefOf(headers);
  const subj = subjectCtx(s, w.subject, session);
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
    session,
    checkClass: w.checkClass,
    status: w.status,
    reason: w.reason,
    reasonCode: w.reasonCode,
    baselineOk: w.baselineOk,
    tool: w.tool,
    evidenceIds: w.evidenceIds ?? [],
    findingIds: w.findingIds ?? [],
    detail: w.detail,
    startedAt: w.startedAt,
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
  reasonCode?: CheckExecution["reasonCode"];
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

/** An inline login wall needs form structure, not a word in ordinary application text.
 *  A password field alone may be an account settings/change-password form; require login
 *  action/title or a credential identity field in the same form. */
export function isAuthWallBody(res: { body?: string }): boolean {
  const body = (res.body ?? "").slice(0, 32_000);
  for (const [form] of body.matchAll(/<form\b[^>]*>[\s\S]*?<\/form\s*>/gi)) {
    const password = /<input\b[^>]*\btype\s*=\s*["']?password(?:["'\s/>])/i.test(form);
    const identity = /<input\b[^>]*\btype\s*=\s*["']?email(?:["'\s/>])/i.test(form) ||
      /<input\b[^>]*\b(?:name|id)\s*=\s*["']?(?:user(?:name|id)?|email|login|account)(?:["'\s/>])/i.test(form);
    const authAction = AUTH_REDIRECT_PATH_RE.test(/<form\b[^>]*\baction\s*=\s*["']?([^"'\s>]+)/i.exec(form)?.[1] ?? "");
    const authLabel = /<(?:button|input)\b[^>]*(?:log[\s-]?in|sign[\s-]?in)/i.test(form) ||
      /<title\b[^>]*>\s*(?:log[\s-]?in|sign[\s-]?in)\b/i.test(body);
    if ((authAction && /<input\b/i.test(form)) || (password && (identity || authLabel)) ||
        (identity && authLabel)) return true;
  }
  return false;
}

/** High-confidence proxy/edge interstitials. A page DISCUSSING proxies or login is not one. */
export function isInfraErrorBody(res: { body?: string }): boolean {
  const body = (res.body ?? "").slice(0, 16_000);
  return /SOCKS:\s*(?:Host unreachable|connection (?:refused|failed|timed out))|ERR_(?:PROXY|TUNNEL)_CONNECTION_FAILED/i.test(body) ||
    /<title\b[^>]*>\s*(?:Burp Suite|Proxy Error|Bad Gateway)\s*<\/title>/i.test(body) &&
      /(?:error|unreachable|upstream|connection|SOCKS|gateway)/i.test(body) ||
    /<title\b[^>]*>\s*(?:Just a moment(?:\.\.\.)?|Attention Required!?\s*\|\s*Cloudflare)\s*<\/title>/i.test(body) &&
      /(?:cloudflare|challenge|checking your browser)/i.test(body) ||
    /<title\b[^>]*>\s*(?:Access Denied|Request Blocked)\s*<\/title>/i.test(body) &&
      /(?:cloudflare|akamai|imperva|incapsula|sucuri|\bWAF\b|bot (?:protection|challenge)|request (?:was )?blocked)/i.test(body) ||
    /challenges\.cloudflare\.com\/(?:turnstile|cdn-cgi\/challenge-platform)/i.test(body);
}

/** A 200 from an edge challenge or proxy auth is not an application response. These headers
 *  describe the response itself; a server brand alone (e.g. Cloudflare as CDN) does not. */
function responseIsInterstitial(res: { headers?: Record<string, string> }): boolean {
  const headers = Object.fromEntries(Object.entries(res.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v.toLowerCase()]));
  return headers["cf-mitigated"] === "challenge" ||
    headers["x-sucuri-block"] !== undefined ||
    headers["proxy-authenticate"] !== undefined ||
    headers["www-authenticate"] !== undefined;
}

/** A 200 JSON error envelope can also mean an auth denial. Only exact machine error codes
 *  with no returned data count; ordinary app prose containing these words does not. */
function structuredAuthDenial(res: { body?: string }): boolean {
  try {
    const json = JSON.parse(res.body ?? "") as unknown;
    if (!json || typeof json !== "object" || Array.isArray(json)) return false;
    const envelope = json as Record<string, unknown>;
    if (envelope.data !== undefined && envelope.data !== null) return false;
    const codes: unknown[] = [envelope.error, envelope.code];
    if (envelope.error && typeof envelope.error === "object")
      codes.push((envelope.error as Record<string, unknown>).code);
    if (Array.isArray(envelope.errors))
      for (const error of envelope.errors)
        if (error && typeof error === "object")
          codes.push((error as Record<string, unknown>).code, (error as { extensions?: { code?: unknown } }).extensions?.code);
    return codes.some((code) => typeof code === "string" &&
      /^(?:unauthorized|forbidden|access_denied|authentication_required|unauthenticated|not_authenticated)$/i.test(code));
  } catch {
    return false;
  }
}

/** Did the request reach the application and get a real answer? False on 5xx (server couldn't
 *  answer — not a conclusive negative), proxy auth (407), session refusals (401/403), auth-wall
 *  redirects, and structured denials, login forms or infra interstitials — status alone can't
 *  tell a 200 login page from the endpoint's real content. A 4xx input denial still "reached". */
export function legReachedApp(res: { status: number; headers?: Record<string, string>; body?: string }): boolean {
  if (res.status >= 500 || res.status === 407 || res.status === 401 || res.status === 403) return false;
  if (responseIsInterstitial(res) || structuredAuthDenial(res) || isAuthWallBody(res) || isInfraErrorBody(res)) return false;
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
  // A zero-byte 200 has no application answer to test against; 204/205 explicitly mean no content.
  return res.status >= 200 && res.status < 300 && (res.status === 204 || res.status === 205 || !!res.body?.trim()) && legReachedApp(res);
}

/** The final response must still be for the requested endpoint, not a successfully followed
 *  redirect to an unrelated 200 page. Missing/malformed provenance is ambiguous. */
function reachedTarget(requestedUrl: string, finalUrl: string): boolean {
  try {
    const requested = new URL(requestedUrl);
    const final = new URL(finalUrl);
    return requested.origin === final.origin &&
      requested.pathname.replace(/\/$/, "") === final.pathname.replace(/\/$/, "") &&
      requested.search === final.search;
  } catch {
    return false;
  }
}

/** Structured probe-result → check-status extraction. The tool's explicit result and the
 * evidence store are authoritative; free-form prose, including response bodies, cannot supply
 * a security verdict, baseline validity, reason code, or session/liveness classification.
 * In particular, a recorded 2xx response plus a structured clean result is necessary for
 * tested-clean; a confirm-style result still needs the existing distinct control/replay floor.
 * The code is optional on old ledger rows and never contains tool text or credentials. */
export function extractProbeOutcome(s: PilotSession, text: string): ProbeOutcome {
  let j: Record<string, unknown> | null = null;
  try {
    const p = JSON.parse(text) as unknown;
    if (p && typeof p === "object" && !Array.isArray(p)) j = p as Record<string, unknown>;
  } catch {
    j = null;
  }
  // A legacy BLOCKED marker is a tool exit status, not proof of an authentication or
  // liveness problem. Do not persist its free-form suffix (it may contain request secrets).
  if (j === null) {
    const blocked = /^(BLOCKED|SKIPPED|REFUSED)\b/i.test(text);
    return {
      status: blocked ? "blocked" : "unverified",
      reason: blocked ? "Tool returned a blocked exit without a structured result" : "Tool returned no structured result",
      reasonCode: "missing-result-contract",
    };
  }

  const idOf = (v: unknown): string | undefined => typeof v === "string" && v.length > 0 ? v : undefined;
  const negId = idOf(j.negativeControl);
  const posIds = Array.isArray(j.positiveReplays) ? j.positiveReplays.map(idOf).filter((x): x is string => x !== undefined) : [];
  const explicitBaseId = idOf(j.baselineEvidenceId);
  const baseId = explicitBaseId ?? negId;
  const ids = new Set<string>();
  if (negId) ids.add(negId);
  for (const id of posIds) ids.add(id);
  if (explicitBaseId) ids.add(explicitBaseId);
  if (Array.isArray(j.evidenceIds)) for (const x of j.evidenceIds) {
    const id = idOf(x);
    if (id) ids.add(id);
  }
  const singleId = idOf(j.evidenceId);
  if (singleId) ids.add(singleId);
  const recorded = new Set(s.evidence.records.map((r) => r.id));
  const allRecorded = [...ids].every((id) => recorded.has(id));
  // Ledger evidenceIds are references to persisted evidence, never unverified tool-supplied ids.
  const evidenceIds = [...ids].filter((id) => recorded.has(id));

  const baseRec = baseId ? s.evidence.records.find((r) => r.id === baseId) : undefined;
  const baselineOk: boolean | undefined = baseRec
    ? validAppBaseline(baseRec.response) && reachedTarget(baseRec.request.url, baseRec.response.finalUrl)
    : undefined;
  const gap = (reasonCode: NonNullable<ProbeOutcome["reasonCode"]>, reason: string): ProbeOutcome =>
    ({ status: "unverified", reasonCode, reason, evidenceIds, baselineOk });
  const missingBaseline = (): ProbeOutcome | undefined => {
    if (!baseRec) return gap("missing-evidence", "Probe has no recorded baseline evidence");
    if (!baselineOk) return gap("invalid-baseline", "Recorded baseline did not return a usable response from the target endpoint");
    return undefined;
  };

  // Structured conclusions cannot bypass the recorded baseline / evidence floor, even when the
  // tool supplies a verdict string. Keep finding confirmation itself in record_finding unchanged.
  if (j.result === "clean" || j.result === "confirmed") {
    const missing = missingBaseline();
    if (missing) return missing;
    if (!allRecorded) return gap("missing-evidence", "Probe cited evidence ids absent from the evidence store");
    if (j.result === "clean")
      return { status: "tested-clean", reason: "Probe reported clean with a recorded 2xx baseline", evidenceIds, baselineOk };
    const evidenceFloor = !!negId && posIds.length >= 2 &&
      new Set(posIds).size === posIds.length && !posIds.includes(negId);
    if (!evidenceFloor)
      return gap("missing-evidence", "Confirmed result lacks a distinct negative control and two distinct positive replays");
    if (posIds.some((id) => {
      const rec = s.evidence.records.find((r) => r.id === id)!;
      // Redirects can be the effect (e.g. open redirect), but a bounce to login
      // or an edge/auth 200 is not proof of a positive exploit replay.
      return isAuthRedirect(rec.response) ||
        rec.response.status >= 200 && rec.response.status < 300 &&
        (!validAppBaseline(rec.response) || !reachedTarget(rec.request.url, rec.response.finalUrl));
    })) return gap("unstable-response", "Positive replay returned an interstitial or a non-target response");
    return { status: "found", reason: "Probe reported confirmed with a recorded baseline and distinct control/replays", evidenceIds, baselineOk };
  }
  // A tool may explicitly name a known category for its own inconclusive exit. Never derive one
  // from verdict/reason/note strings; unknown codes (including secrets) are ignored.
  const typedCode = ((): ProbeOutcome["reasonCode"] => {
    switch (j.reasonCode) {
      case "invalid-baseline":
      case "missing-evidence":
      case "missing-result-contract":
      case "missing-prerequisite":
      case "unstable-response":
      case "unknown": return j.reasonCode;
      default: return undefined;
    }
  })();
  const explicitCode: ProbeOutcome["reasonCode"] =
    typedCode ?? (j.unstableResponse === true ? "unstable-response" : j.missingPrerequisite === true ? "missing-prerequisite" : "unknown");
  const codeReason: Record<NonNullable<ProbeOutcome["reasonCode"]>, string> = {
    "invalid-baseline": "Probe reported an invalid baseline",
    "missing-evidence": "Probe reported missing required evidence",
    "missing-result-contract": "Probe returned no usable result contract",
    "missing-prerequisite": "Probe could not run without a required prerequisite",
    "unstable-response": "Probe reported unstable or inconsistent replays",
    unknown: "Probe reported an inconclusive result without a structured cause",
  };
  // An explicit baseline record can independently explain an unverified attempt. A failed
  // *negative control* alone cannot: a denied control is intentional in many probe contracts.
  if (j.result === "unverified" && explicitBaseId) {
    const missing = missingBaseline();
    if (missing) return missing;
  }
  if (j.result === "unverified" && !allRecorded)
    return gap("missing-evidence", "Probe cited evidence ids absent from the evidence store");
  if (j.result === "unverified") return gap(explicitCode, codeReason[explicitCode ?? "unknown"]);
  if (j.result === "blocked" || j.blocked === true || j.skipped === true)
    return { status: "blocked", reasonCode: explicitCode, reason: explicitCode === "unknown" ? "Probe reported blocked without a structured cause" : codeReason[explicitCode ?? "unknown"], evidenceIds };
  if (j.result === "suspected" || j.suspected === true)
    return { status: "suspected", reason: "Probe reported a suspected lead", evidenceIds, baselineOk };
  if (j.result === "not-applicable")
    return { status: "not-applicable", reason: "Probe reported this check is not applicable", evidenceIds, baselineOk };
  return gap("missing-result-contract", "Tool returned no recognized structured result");
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
