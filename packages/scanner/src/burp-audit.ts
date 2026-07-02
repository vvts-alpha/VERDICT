// VERDICT Audit REST 拡張(別ポート、既定 1338)のクライアント。tools/burp-audit-ext/ の API を叩く。
// 標準 Burp REST(1337)と違い、認証済みの生 HTTP リクエストをそのまま投入する(セッションはリクエスト内包)。
// → VERDICT が live Cookie/Bearer を載せた生リクエストを送れば認証下を能動スキャンできる。

import type { BurpIssue } from "./burp.js";

export interface BurpAuditConn {
  /** 例 http://172.29.176.1:1338 */
  base: string;
  /** X-Scan-Token(拡張側で AUTH_TOKEN 設定時に必須)。 */
  token?: string;
}

export interface AuditSubmit {
  host: string;
  port: number;
  secure: boolean;
  /** "active" | "passive" */
  auditMode: string;
  /** CRLF 区切りの生 HTTP リクエスト(Cookie/Bearer/body 込み)。 */
  request: string;
}

function url(conn: BurpAuditConn, path: string): string {
  return `${conn.base.replace(/\/+$/, "")}${path}`;
}
function headers(conn: BurpAuditConn, extra: Record<string, string> = {}): Record<string, string> {
  return { ...(conn.token ? { "X-Scan-Token": conn.token } : {}), ...extra };
}

/** 生リクエストを 1 件 Audit に投入。Audit キー(host:port)を返す。 */
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

/** 全ホストの Audit 進捗。 */
export async function getAuditStatusAll(conn: BurpAuditConn): Promise<AuditHostStatus[]> {
  const res = await fetch(url(conn, "/status"), { headers: headers(conn) });
  if (!res.ok) throw new Error(`audit /status failed: ${res.status}`);
  const j = (await res.json()) as { hosts?: Array<{ host?: string; status?: string; requests_made?: number; errors?: number }> };
  return (j.hosts ?? []).map((h) => ({ host: h.host ?? "", status: h.status ?? "unknown", requestsMade: h.requests_made ?? 0, errors: h.errors ?? 0 }));
}

/** 捕捉 issue を取得(since=epoch ms で run 差分)。BurpIssue 形にして既存マージ経路に乗せる。 */
export async function getAuditIssues(conn: BurpAuditConn, opts: { since?: number; host?: string } = {}): Promise<BurpIssue[]> {
  const qs = new URLSearchParams({ evidence: "true" });
  if (opts.since != null) qs.set("since", String(opts.since));
  if (opts.host) qs.set("host", opts.host);
  const res = await fetch(url(conn, `/issues?${qs.toString()}`), { headers: headers(conn) });
  if (!res.ok) throw new Error(`audit /issues failed: ${res.status}`);
  const j = (await res.json()) as { issues?: AuditRestIssue[] };
  return auditIssuesToBurpIssues(j.issues ?? []);
}

/** 拡張の蓄積をクリア(run 前に過去 issue を混ぜない)。 */
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

/** /issues の JSON → BurpIssue[]。FALSE_POSITIVE は捨て、証拠の req/resp は Cookie/Authorization を伏字に。 */
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

/** 生 HTTP リクエスト文字列(CRLF)を組む。Content-Length は body から自動算出。
 *  pathWithQuery=リクエストターゲット, hostHeader=Host 値(host:port), sessionHeaders=Cookie/Authorization 等。 */
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
