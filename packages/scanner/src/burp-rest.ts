// Burp Suite Professional REST API (v0.1) クライアント — 能動スキャンをプログラムから起動し、issue を取り込む。
// 既定 http://127.0.0.1:1337。API キーは URL パスのプレフィックス(/<key>/v0.1/...)。依存無し(Node の global fetch)。
// 連携はオプトイン・追加のみ(burp-scan コマンドからのみ呼ばれる。未使用なら挙動不変)。

import type { BurpIssue } from "./burp.js";

/**
 * survey でマップした surface から最適な Burp スキャン構成(named config)を選ぶ(ヒューリスティック)。
 * クロール戦略は面の広さで、監査深度は規模で決める。--config を明示した時はこれを使わず上書きする。
 * 名前は Burp ビルトインの既定構成(操作者が保存したカスタム構成名でも可。その場合は --config で指定)。
 * 構造的型: screens を持つもの(AssessmentState 互換)なら何でも渡せる(core 依存を避ける)。
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

/** Burp の seed URL を「パス + クエリ param 名の集合」で畳む。値違い(/login?next=A と ?next=B)を1本に
 *  まとめ、同一エンドポイントへの大量スキャン生成を防ぐ。最初に出た具体 URL を代表に残す(値は Burp が fuzz する)。
 *  ※ hash(#/route)は呼び出し側で除去済み — SPA のルート差は別 URL のまま分けて渡す。 */
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
  /** operator 提供の CustomConfiguration(JSON 文字列)を named config に重ねる(後勝ち)。
   *  例: 普段使う scan policy(監査ポリシー)/ セッション注入の session-handling rule。
   *  スキーマはバージョン依存なので AMRAAM は生成せず、Burp から export した設定をそのまま渡す
   *  (値は呼び出し側で {{COOKIE}}/{{BEARER}} を差し込み済み)。 */
  customConfigs?: string[];
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
  const scanConfigs: Array<Record<string, unknown>> = (req.configs ?? []).map((name) => ({ type: "NamedConfiguration", name }));
  // operator の CustomConfiguration は named config の後に重ねる(後勝ち。policy/session rule を最後に効かせる)。
  for (const cfg of req.customConfigs ?? []) scanConfigs.push({ type: "CustomConfiguration", config: cfg });
  if (scanConfigs.length) body.scan_configurations = scanConfigs;
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
