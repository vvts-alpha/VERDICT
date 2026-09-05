// Burp Suite Professional REST API (v0.1) client — programmatically start an active scan and import issues.
// Default http://127.0.0.1:1337. The API key is a URL-path prefix (/<key>/v0.1/...). No dependencies (Node's global fetch).
// The integration is opt-in and additive only (called only from the burp-scan command; behaviour is unchanged if unused).

import type { BurpIssue } from "./burp.js";

/**
 * Pick the best Burp scan configuration (named config) from the surface mapped during survey (heuristic).
 * Crawl strategy is decided by surface breadth, audit depth by scale. An explicit --config overrides this instead of using it.
 * The names are Burp's built-in default configs (an operator-saved custom config name works too; specify it via --config).
 * Structural typing: anything with screens (AssessmentState-compatible) can be passed (avoids a core dependency).
 */
export function pickBurpConfigs(state: { screens: ReadonlyArray<{ apis: ReadonlyArray<unknown> }> }): { configs: string[]; reason: string } {
  const screens = state.screens.length;
  const apis = state.screens.reduce((n, s) => n + s.apis.length, 0);
  const configs: string[] = [];
  let crawl: string;
  if (screens > 40) {
    configs.push("Crawl strategy - fastest");
    crawl = "large surface → fastest crawl";
  } else if (screens <= 8) {
    configs.push("Crawl strategy - most complete");
    crawl = "small surface → most complete crawl";
  } else {
    crawl = "medium surface → Burp default crawl";
  }
  let audit: string;
  if (screens > 80) {
    configs.push("Audit checks - critical issues only");
    audit = "very large → critical-issues-only audit (bound time)";
  } else {
    configs.push("Audit checks - all except time-based detection methods");
    audit = "full audit (skips slow time-based checks)";
  }
  return { configs, reason: `${screens} screens / ${apis} APIs — ${crawl}; ${audit}` };
}

/** Collapse Burp seed URLs by "path + set of query-param names". Value differences (/login?next=A vs ?next=B) fold into one
 *  to prevent generating a flood of scans against the same endpoint. Keep the first concrete URL as representative (Burp fuzzes the values).
 *  ※ the hash (#/route) is already stripped by the caller — SPA route differences are passed separately as distinct URLs. */
export function dedupSeedUrls(urls: ReadonlyArray<string>): string[] {
  const byKey = new Map<string, string>();
  for (const raw of urls) {
    let key: string;
    try {
      const u = new URL(raw);
      const names = [...new Set([...u.searchParams.keys()].map((k) => k.toLowerCase()))].sort();
      key = `${u.origin}${u.pathname.toLowerCase()}?${names.join(",")}`;
    } catch {
      key = raw;
    }
    if (!byKey.has(key)) byKey.set(key, raw);
  }
  return [...byKey.values()];
}

export interface BurpScanRequest {
  signal?: AbortSignal;
  /** Burp REST base. e.g. http://127.0.0.1:1337 */
  base: string;
  /** API key (User options → Misc → REST API). Becomes the URL-path prefix. */
  apiKey?: string;
  /** Seed URLs (in scope; Burp crawls + audits from here). */
  urls: string[];
  /** named scan configuration (multiple allowed). Crawl speed and audit content can be layered from separate presets.
   *  e.g. ["Crawl strategy - fastest", "Audit checks - critical issues only"].
   *  Speed is "Crawl strategy - fastest|faster|normal|more complete|most complete"; audit weight is
   *  decided by "Audit checks - ...". Merged last-wins. */
  configs?: string[];
  /** Burp Resource pool name (optional). Max concurrent requests and inter-request delay = effective throughput/throttle. */
  resourcePool?: string;
  /** Credentials for authenticated scanning (optional; Burp learns the login form and audits while authenticated). */
  logins?: Array<{ username: string; password: string }>;
  /** Layer operator-provided CustomConfiguration (JSON string) over the named config (last-wins).
   *  e.g. your usual scan policy (audit policy) / a session-handling rule for session injection.
   *  The schema is version-dependent, so VERDICT does not generate it; pass the config exported from Burp as-is
   *  (the caller has already substituted {{COOKIE}}/{{BEARER}} into the values). */
  customConfigs?: string[];
}

function apiUrl(base: string, apiKey: string | undefined, path: string): string {
  const root = base.replace(/\/+$/, "");
  return apiKey ? `${root}/${apiKey}${path}` : `${root}${path}`;
}

/** Location header of POST /v0.1/scan → task id. Handles both the "/v0.1/scan/3" form and a bare "3" (the on-device variant). */
export function parseTaskId(location: string): string | null {
  const m = /(\d+)\s*$/.exec((location ?? "").trim());
  return m && m[1] ? m[1] : null;
}

/** Start an active scan → returns task_id. Picks the id from the Location header (or the body if absent). */
export async function startBurpScan(req: BurpScanRequest): Promise<string> {
  const body: Record<string, unknown> = { urls: req.urls };
  const scanConfigs: Array<Record<string, unknown>> = (req.configs ?? []).map((name) => ({ type: "NamedConfiguration", name }));
  // The operator's CustomConfiguration is layered after the named config (last-wins; the policy/session rule takes effect last).
  for (const cfg of req.customConfigs ?? []) scanConfigs.push({ type: "CustomConfiguration", config: cfg });
  if (scanConfigs.length) body.scan_configurations = scanConfigs;
  if (req.resourcePool) body.resource_pool = req.resourcePool;
  if (req.logins?.length) body.application_logins = req.logins;
  const res = await fetch(apiUrl(req.base, req.apiKey, "/v0.1/scan"), {
    method: "POST",
    ...(req.signal ? { signal: req.signal } : {}),
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (res.status !== 201 && !res.ok) {
    throw new Error(`Burp REST start failed: ${res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`);
  }
  const fromLoc = parseTaskId(res.headers.get("location") ?? "");
  if (fromLoc) return fromLoc;
  try {
    const j = (await res.json()) as { task_id?: string | number };
    if (j.task_id != null) return String(j.task_id);
  } catch {
    /* body not JSON */
  }
  throw new Error(`Burp REST start: could not determine task id (location='${res.headers.get("location") ?? ""}')`);
}

export interface BurpScanStatus {
  /** crawling | auditing | succeeded | failed | paused | ... */
  status: string;
  /** crawl+audit progress 0..100. */
  progress: number;
  issueEvents: number;
  issues: BurpIssue[];
}

interface BurpRestIssue {
  name?: string;
  origin?: string;
  path?: string;
  severity?: string;
  description?: string;
  remediation?: string;
  evidence?: unknown;
}

/** Fetch the scan status + the issues found so far (cumulative). */
export async function getBurpScan(base: string, apiKey: string | undefined, taskId: string, signal?: AbortSignal): Promise<BurpScanStatus> {
  const res = await fetch(apiUrl(base, apiKey, `/v0.1/scan/${encodeURIComponent(taskId)}`), signal ? { signal } : {});
  if (!res.ok) throw new Error(`Burp REST status failed: ${res.status}`);
  const j = (await res.json()) as {
    scan_status?: string;
    scan_metrics?: { crawl_and_audit_progress?: number };
    issue_events?: Array<{ type?: string; issue?: BurpRestIssue }>;
  };
  const events = j.issue_events ?? [];
  return {
    status: j.scan_status ?? "unknown",
    progress: j.scan_metrics?.crawl_and_audit_progress ?? 0,
    issueEvents: events.length,
    issues: restIssuesToBurpIssues(events),
  };
}

function b64(s: string): string {
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return s;
  }
}

/** REST request/response is an array of {data:<base64>} segments (or a string). Decode and concatenate. */
function reconstruct(segs: unknown): string {
  if (typeof segs === "string") return segs;
  if (!Array.isArray(segs)) return "";
  let out = "";
  for (const s of segs) {
    const d = (s as { data?: unknown }).data;
    if (typeof d === "string") out += b64(d);
  }
  return out;
}

function redact(raw: string): string {
  return raw.replace(/^(Cookie|Authorization|Set-Cookie):.*$/gim, "$1: <redacted>").slice(0, 8000);
}

function stripTags(s: string): string {
  return s
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function firstEvidence(evidence: unknown): { request: string; response: string } {
  const arr = Array.isArray(evidence) ? evidence : [];
  for (const e of arr) {
    const rr = (e as { request_response?: { request?: unknown; response?: unknown } }).request_response;
    if (rr) return { request: redact(reconstruct(rr.request)), response: redact(reconstruct(rr.response)) };
  }
  return { request: "", response: "" };
}

/** REST issue_events → the existing BurpIssue shape (rides the same merge path as XML import). Pure; throws no exceptions. */
export function restIssuesToBurpIssues(events: ReadonlyArray<{ type?: string; issue?: BurpRestIssue }>): BurpIssue[] {
  const out: BurpIssue[] = [];
  for (const ev of events) {
    if (ev.type && ev.type !== "issue_found") continue; // ignore issue_resolved etc.
    const it = ev.issue;
    if (!it || !it.name) continue;
    const { request, response } = firstEvidence(it.evidence);
    out.push({
      name: it.name,
      host: it.origin ?? "",
      path: it.path ?? "/",
      severity: it.severity ?? "info",
      detail: stripTags(it.description ?? ""),
      background: stripTags(it.remediation ?? ""),
      request,
      response,
    });
  }
  return out;
}
