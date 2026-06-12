// 初期状態を組み立てる純粋ヘルパ。PolicyEngine/BudgetGuard 本体は後続マイルストン。

import type { BudgetState } from "./types/budget.js";
import type { ScopePolicy } from "./types/scope.js";

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
 * 単一 URL から同一オリジン + 起点配下を既定スコープとして導出(DESIGN §4.2/§5)。
 * M0 は最小シード。精緻な判定は PolicyEngine(後続)が担う。
 */
export function deriveScopeFromSingleUrl(rawUrl: string): ScopePolicy {
  const u = new URL(rawUrl);
  return {
    inScopeHosts: [u.host],
    outOfScopeHosts: [],
    inScopePathPrefixes: ["/"],
    outOfScopePathPrefixes: [],
    approvalPathPrefixes: [],
    approvalMethods: ["DELETE", "PUT", "PATCH"], // 破壊的 → REQUIRES_APPROVAL(DESIGN §4.5)
    rate: { requestsPerMinute: 30, maxConcurrent: 2 }, // WAF 教訓: 保守的(DESIGN §2.2)
  };
}
