// 初期状態を組み立てる純粋ヘルパ。PolicyEngine/BudgetGuard 本体は後続マイルストン。

import type { BudgetState } from "./types/budget.js";
import type { ScopeMode, ScopePolicy } from "./types/scope.js";
import { registrableDomain } from "./etld.js";

/** "unrestricted" モードが inScopeHosts に置くワイルドカード(hostMatches が全一致扱い)。 */
const UNRESTRICTED_HOST = "*";

/** runs/<assessment_id>/ に使える、ソート可能で人に優しい id */
export function newAssessmentId(now: Date = new Date()): string {
  const t = now.getTime().toString(36);
  const r = Math.random().toString(36).slice(2, 8);
  return `a-${t}-${r}`;
}

/** 保守的な既定予算。実時間/リクエスト数を主軸に(DESIGN §13: コストは Max サブスクで定額)。 */
export function defaultBudget(now: Date = new Date()): BudgetState {
  return {
    limits: {
      maxTokens: 5_000_000,
      maxWallClockMs: 60 * 60 * 1000, // 1h
      maxTotalRequests: 5_000,
      maxRequestsPerTarget: 2_000,
    },
    startedAt: now.toISOString(),
    tokensUsed: 0,
    totalRequests: 0,
    requestsPerTarget: {},
  };
}

/**
 * シード URL 群 + モードから既定スコープを導出(DESIGN §4.2/§5)。
 * - "same-origin": 各シードと同一ホスト(exact, ポート込み)
 * - "etld":        各シードの登録可能ドメイン配下(`*.example.com`)。同一プログラムの API サブドメインを含む
 * - "unrestricted": ホスト制限なし(`*`)
 * パス接頭辞は常に "/"(ホスト粒度のゲート)。URL の path で絞らないのは従来挙動どおり。
 */
export function deriveScopeFromUrls(rawUrls: string[], mode: ScopeMode = "same-origin"): ScopePolicy {
  const hosts = new Set<string>();
  for (const raw of rawUrls) {
    const u = new URL(raw);
    if (mode === "unrestricted") hosts.add(UNRESTRICTED_HOST);
    else if (mode === "etld") hosts.add(`*.${registrableDomain(u.hostname)}`);
    else hosts.add(u.host);
  }
  return {
    inScopeHosts: [...hosts],
    outOfScopeHosts: [],
    inScopePathPrefixes: ["/"],
    outOfScopePathPrefixes: [],
    approvalPathPrefixes: [],
    approvalMethods: ["DELETE", "PUT", "PATCH"], // 破壊的 → REQUIRES_APPROVAL(DESIGN §4.5)
    rate: { requestsPerMinute: 30, maxConcurrent: 2 }, // WAF 教訓: 保守的(DESIGN §2.2)
  };
}

/**
 * 単一 URL から同一オリジン + 起点配下を既定スコープとして導出(DESIGN §4.2/§5)。
 * 後方互換の薄いラッパ(= deriveScopeFromUrls([url], "same-origin"))。
 */
export function deriveScopeFromSingleUrl(rawUrl: string): ScopePolicy {
  return deriveScopeFromUrls([rawUrl], "same-origin");
}
