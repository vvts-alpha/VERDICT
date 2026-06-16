// Burp Suite Professional REST API (v0.1) クライアント — 能動スキャンをプログラムから起動し、issue を取り込む。
// 既定 http://127.0.0.1:1337。API キーは URL パスのプレフィックス(/<key>/v0.1/...)。依存無し(Node の global fetch)。
// 連携はオプトイン・追加のみ(burp-scan コマンドからのみ呼ばれる。未使用なら挙動不変)。

import type { BurpIssue } from "./burp.js";

export interface BurpScanRequest {
  /** Burp REST のベース。例 http://127.0.0.1:1337 */
  base: string;
  /** API キー(User options → Misc → REST API)。URL パスのプレフィックスになる。 */
  apiKey?: string;
  /** シードURL(スコープ内。Burp はここから crawl + audit する)。 */
  urls: string[];
  /** named scan configuration(複数可)。クロール速度と監査内容を別々のプリセットで重ねられる。
   *  例: ["Crawl strategy - fastest", "Audit checks - critical issues only"]。
   *  速度は "Crawl strategy - fastest|faster|normal|more complete|most complete" で、監査の重さは
   *  "Audit checks - ..." で決める。後勝ちでマージされる。 */
  configs?: string[];
  /** Burp の Resource pool 名(任意)。最大同時リクエスト数とリクエスト間ディレイ＝実スループット/throttle。 */
  resourcePool?: string;
  /** 認証スキャン用の資格情報(任意。Burp がログインフォームを学習して認証下を監査)。 */
  logins?: Array<{ username: string; password: string }>;
}

function apiUrl(base: string, apiKey: string | undefined, path: string): string {
  const root = base.replace(/\/+$/, "");
  return apiKey ? `${root}/${apiKey}${path}` : `${root}${path}`;
}

/** POST /v0.1/scan の Location ヘッダ → task id。"/v0.1/scan/3" 形式と bare "3"(実機の版)の両対応。 */
export function parseTaskId(location: string): string | null {
  const m = /(\d+)\s*$/.exec((location ?? "").trim());
  return m && m[1] ? m[1] : null;
}

/** 能動スキャンを開始 → task_id を返す。Location ヘッダ(無ければ body)から id を拾う。 */
export async function startBurpScan(req: BurpScanRequest): Promise<string> {
  const body: Record<string, unknown> = { urls: req.urls };
  if (req.configs?.length) body.scan_configurations = req.configs.map((name) => ({ type: "NamedConfiguration", name }));
  if (req.resourcePool) body.resource_pool = req.resourcePool;
  if (req.logins?.length) body.application_logins = req.logins;
  const res = await fetch(apiUrl(req.base, req.apiKey, "/v0.1/scan"), {
    method: "POST",
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
  /** crawl+audit の進捗 0..100。 */
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

/** スキャン状態 + これまでに見つかった issue(累積)を取得。 */
export async function getBurpScan(base: string, apiKey: string | undefined, taskId: string): Promise<BurpScanStatus> {
  const res = await fetch(apiUrl(base, apiKey, `/v0.1/scan/${taskId}`));
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

/** REST の request/response は {data:<base64>} セグメント配列(または文字列)。デコードして連結する。 */
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

/** REST の issue_events → 既存 BurpIssue 形(XML 取り込みと同じマージ経路に乗せる)。pure・例外を投げない。 */
export function restIssuesToBurpIssues(events: ReadonlyArray<{ type?: string; issue?: BurpRestIssue }>): BurpIssue[] {
  const out: BurpIssue[] = [];
  for (const ev of events) {
    if (ev.type && ev.type !== "issue_found") continue; // issue_resolved 等は無視
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
