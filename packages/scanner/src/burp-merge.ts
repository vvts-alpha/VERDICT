// Burp issue(XML or REST 由来)を既存 run へマージする共通ロジック。
// 既存 finding と (粗カテゴリ × 正規化エンドポイント) で重複排除し、スコープ外は捨てる。
// CLI(burp-import / burp-scan)と server(アップロード取り込み API)の両方がこれを使う。
// 層を壊さないため、エンドポイント正規化(crawler の normalizePath)は依存注入(pathTemplate)で受ける。

import type { AssessmentStore, Finding, ScopePolicy } from "@veritas/core";
import { isInScope } from "@veritas/core";
import { EvidenceStore } from "./evidence.js";
import { coarseCategory, burpSeverity } from "./burp.js";
import type { BurpIssue } from "./burp.js";

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
    const key = keyOf(coarseCategory(issue.name), path);
    if (existing.has(key)) {
      skipped += 1;
      continue;
    }
    existing.add(key);
    added += 1;
    const ev = evidence.record({
      screenId: "burp",
      validator: "burp",
      kind: "positive_replay",
      request: { method: "GET", url, headers: {}, body: issue.request || null },
      response: { status: 0, finalUrl: url, durationMs: 0, headers: {}, body: issue.response },
      note: issue.name,
    });
    store.upsertFinding(id, {
      id: `${prefix}-${String(added).padStart(3, "0")}`,
      screenId: null,
      title: `[burp] ${issue.name}`,
      severity: burpSeverity(issue.severity),
      source: { kind: "validator", validatorName: "burp" },
      description: `${(issue.detail || issue.background).slice(0, 600)} @ ${url}`,
      reproSteps: "Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。",
      evidenceIds: [ev.id],
      scopeBasis: "burp scan (in-scope)",
    });
  }
  return { added, skipped, oos };
}
