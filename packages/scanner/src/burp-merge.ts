// Burp issue(XML or REST 由来)を既存 run へマージする共通ロジック。
// 既存 finding と (粗カテゴリ × 正規化エンドポイント) で重複排除し、スコープ外は捨てる。
// CLI(burp-import / burp-scan)と server(アップロード取り込み API)の両方がこれを使う。
// 層を壊さないため、エンドポイント正規化(crawler の normalizePath)は依存注入(pathTemplate)で受ける。

import type { AssessmentStore, Finding, ScopePolicy, Severity } from "@veritas/core";
import { isInScope } from "@veritas/core";
import { EvidenceStore } from "./evidence.js";
import { coarseCategory, burpSeverity } from "./burp.js";
import type { BurpIssue } from "./burp.js";

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const maxSeverity = (a: Severity, b: Severity): Severity => (SEV_RANK[b] > SEV_RANK[a] ? b : a);

export interface MergeBurpOptions {
  /** finding id の接頭辞(既定 "b")。burp-import="b" / burp-scan も "b"。 */
  prefix?: string;
  /** エンドポイントをテンプレ化して重複排除キーに使う(既定: 恒等)。CLI/server は normalizePath を渡す。 */
  pathTemplate?: (path: string) => string;
}

export interface MergeBurpResult {
  added: number;
  skipped: number;
  oos: number;
}

/** state は findings(既存重複判定)と scope(in-scope 判定)だけ参照する。 */
export function mergeBurpIssues(
  store: Pick<AssessmentStore, "upsertFinding">,
  id: string,
  state: { findings: ReadonlyArray<Finding>; scope: ScopePolicy },
  artifactsDir: string,
  issues: ReadonlyArray<BurpIssue>,
  opts: MergeBurpOptions = {},
): MergeBurpResult {
  const prefix = opts.prefix ?? "b";
  const tmpl = opts.pathTemplate ?? ((p) => p);
  const evidence = new EvidenceStore(artifactsDir);
  const keyOf = (cat: string, path: string): string => {
    try {
      return `${cat}::${tmpl(path)}`;
    } catch {
      return `${cat}::${path}`;
    }
  };
  const existing = new Set<string>();
  for (const f of state.findings) {
    const ep = /(\/[A-Za-z0-9_{}/.-]+)/.exec(f.title)?.[1] ?? "/";
    existing.add(keyOf(coarseCategory(f.title), ep));
  }
  let added = 0;
  let skipped = 0;
  let oos = 0;

  // 1) in-scope のみ残す(URL/パスを確定)。out-of-scope は捨てる。
  const inScope: Array<{ issue: BurpIssue; url: string; path: string }> = [];
  for (const issue of issues) {
    let url: string;
    try {
      url = new URL(issue.path || "/", issue.host).toString();
    } catch {
      url = issue.host;
    }
    if (!isInScope(url, state.scope)) {
      oos += 1;
      continue;
    }
    let path: string;
    try {
      path = new URL(url).pathname;
    } catch {
      path = issue.path || "/";
    }
    inScope.push({ issue, url, path });
  }

  // 2) issue 名でグループ化。Burp は同一 issue(例 "CORS: arbitrary origin trusted")を URL ごとに吐くので、
  //    per-URL の重複を **1 finding(影響 URL リスト付き)** に畳む。レポートの水増し(53→実質~20)を解消する。
  const groups = new Map<string, Array<{ issue: BurpIssue; url: string; path: string }>>();
  for (const it of inScope) {
    const g = groups.get(it.issue.name) ?? [];
    g.push(it);
    groups.set(it.issue.name, g);
  }

  // 3) グループごとに 1 finding(既存 claude-pilot finding と (粗カテゴリ × パス) で重複排除)。
  for (const members of groups.values()) {
    const first = members[0]!;
    const key = keyOf(coarseCategory(first.issue.name), first.path);
    if (existing.has(key)) {
      skipped += members.length;
      continue;
    }
    existing.add(key);
    added += 1;
    const severity = members.map((m) => burpSeverity(m.issue.severity)).reduce(maxSeverity);
    const urls = [...new Set(members.map((m) => m.url))];
    // 代表 URL は文末 "@ <url>" に置く(verifyBurpFindings の endpointOf 抽出を壊さない)。残りは前置の注記に列挙。
    const more = urls.length > 1 ? ` [+${urls.length - 1} more URL(s): ${urls.slice(1, 6).join(", ")}${urls.length > 6 ? ", …" : ""}]` : "";
    const ev = evidence.record({
      screenId: "burp",
      validator: "burp",
      kind: "positive_replay",
      request: { method: "GET", url: first.url, headers: {}, body: first.issue.request || null },
      response: { status: 0, finalUrl: first.url, durationMs: 0, headers: {}, body: first.issue.response },
      note: first.issue.name,
    });
    store.upsertFinding(id, {
      id: `${prefix}-${String(added).padStart(3, "0")}`,
      screenId: null,
      title: `[burp] ${first.issue.name}${urls.length > 1 ? ` (${urls.length} URLs)` : ""}`,
      severity,
      source: { kind: "validator", validatorName: "burp" },
      description: `${(first.issue.detail || first.issue.background).slice(0, 600)}${more} @ ${first.url}`,
      reproSteps: "Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。",
      evidenceIds: [ev.id],
      scopeBasis: "burp scan (in-scope)",
    });
  }
  return { added, skipped, oos };
}
