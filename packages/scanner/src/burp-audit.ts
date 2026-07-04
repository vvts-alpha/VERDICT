// Client for the VERDICT Audit REST extension (separate port, default 1338). Calls the tools/burp-audit-ext/ API.
// Unlike standard Burp REST (1337), it submits authenticated raw HTTP requests as-is (the session is embedded in the request).
// → If VERDICT sends a raw request carrying a live Cookie/Bearer, it can actively scan while authenticated.

import type { BurpIssue } from "./burp.js";

export interface BurpAuditConn {
  /** e.g. http://172.29.176.1:1338 */
  base: string;
  /** X-Scan-Token (required when AUTH_TOKEN is set on the extension side). */
  token?: string;
}

export interface AuditSubmit {
  host: string;
  port: number;
  secure: boolean;
  /** "active" | "passive" */
  auditMode: string;
  /** CRLF-delimited raw HTTP request (including Cookie/Bearer/body). */
  request: string;
}

function url(conn: BurpAuditConn, path: string): string {
  return `${conn.base.replace(/\/+$/, "")}${path}`;
}
function headers(conn: BurpAuditConn, extra: Record<string, string> = {}): Record<string, string> {
  return { ...(conn.token ? { "X-Scan-Token": conn.token } : {}), ...extra };
}

/** Submit one raw request to Audit. Returns the Audit key (host:port). */
export async function submitAudit(conn: BurpAuditConn, s: AuditSubmit): Promise<string> {
  const res = await fetch(url(conn, "/scan"), {
    method: "POST",
    headers: headers(conn, { "content-type": "application/json" }),
    body: JSON.stringify({ host: s.host, port: s.port, secure: s.secure, audit_mode: s.auditMode, request: s.request }),
  });
  if (!res.ok) throw new Error(`audit /scan failed: ${res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`);
  const j = (await res.json()) as { host?: string };
  return j.host ?? `${s.host}:${s.port}`;
}

export interface AuditHostStatus {
  host: string;
  status: string;
  requestsMade: number;
  errors: number;
}

/** Audit progress for all hosts. */
export async function getAuditStatusAll(conn: BurpAuditConn): Promise<AuditHostStatus[]> {
  const res = await fetch(url(conn, "/status"), { headers: headers(conn) });
  if (!res.ok) throw new Error(`audit /status failed: ${res.status}`);
  const j = (await res.json()) as { hosts?: Array<{ host?: string; status?: string; requests_made?: number; errors?: number }> };
  return (j.hosts ?? []).map((h) => ({ host: h.host ?? "", status: h.status ?? "unknown", requestsMade: h.requests_made ?? 0, errors: h.errors ?? 0 }));
}

/** Fetch captured issues (since=epoch ms for the run delta). Convert to BurpIssue shape to ride the existing merge path. */
export async function getAuditIssues(conn: BurpAuditConn, opts: { since?: number; host?: string } = {}): Promise<BurpIssue[]> {
  const qs = new URLSearchParams({ evidence: "true" });
  if (opts.since != null) qs.set("since", String(opts.since));
  if (opts.host) qs.set("host", opts.host);
  const res = await fetch(url(conn, `/issues?${qs.toString()}`), { headers: headers(conn) });
  if (!res.ok) throw new Error(`audit /issues failed: ${res.status}`);
  const j = (await res.json()) as { issues?: AuditRestIssue[] };
  return auditIssuesToBurpIssues(j.issues ?? []);
}

/** Clear the extension's accumulation (don't mix in past issues before a run). */
export async function resetAudit(conn: BurpAuditConn): Promise<void> {
  await fetch(url(conn, "/reset"), { method: "POST", headers: headers(conn) }).catch(() => {});
}

interface AuditRestIssue {
  found_at?: number;
  name?: string;
  severity?: string;
  confidence?: string;
  url?: string;
  detail?: string;
  evidence?: Array<{ request_b64?: string; response_b64?: string }>;
}

function b64decode(s: string | undefined): string {
  if (!s) return "";
  try {
    return Buffer.from(s, "base64").toString("utf8");
  } catch {
    return "";
  }
}
function redact(raw: string): string {
  return raw.replace(/^(Cookie|Authorization|Set-Cookie):.*$/gim, "$1: <redacted>").slice(0, 8000);
}

/** /issues JSON → BurpIssue[]. Drop FALSE_POSITIVE, and redact Cookie/Authorization in the evidence req/resp. */
export function auditIssuesToBurpIssues(issues: ReadonlyArray<AuditRestIssue>): BurpIssue[] {
  const out: BurpIssue[] = [];
  for (const it of issues) {
    if (!it.name) continue;
    if ((it.severity ?? "").toUpperCase() === "FALSE_POSITIVE") continue;
    const ev = it.evidence?.[0];
    let host = "";
    let path = "/";
    try {
      const u = new URL(it.url ?? "");
      host = u.origin;
      path = u.pathname;
    } catch {
      /* keep defaults */
    }
    out.push({
      name: it.name,
      host,
      path,
      severity: it.severity ?? "info",
      detail: `${it.detail ?? ""}${it.confidence ? ` (confidence: ${it.confidence})` : ""}`.trim(),
      background: "",
      request: redact(b64decode(ev?.request_b64)),
      response: redact(b64decode(ev?.response_b64)),
    });
  }
  return out;
}

/** Build a raw HTTP request string (CRLF). Content-Length is computed automatically from body.
 *  pathWithQuery=the request target, hostHeader=the Host value (host:port), sessionHeaders=Cookie/Authorization etc. */
export function buildRawRequest(o: {
  method: string;
  pathWithQuery: string;
  hostHeader: string;
  headers?: Record<string, string>;
  body?: string | null;
  contentType?: string;
}): string {
  const lines: string[] = [`${o.method.toUpperCase()} ${o.pathWithQuery} HTTP/1.1`, `Host: ${o.hostHeader}`];
  const hdrs = { ...(o.headers ?? {}) };
  for (const [k, v] of Object.entries(hdrs)) lines.push(`${k}: ${v}`);
  const hasBody = o.body != null && o.body.length > 0;
  if (hasBody) {
    lines.push(`Content-Type: ${o.contentType ?? "application/json"}`);
    lines.push(`Content-Length: ${Buffer.byteLength(o.body as string, "utf8")}`);
  }
  lines.push("Accept: */*");
  return lines.join("\r\n") + "\r\n\r\n" + (hasBody ? (o.body as string) : "");
}
