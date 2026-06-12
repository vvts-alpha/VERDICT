// DESIGN §4.4 — BudgetGuard(予算・停止条件)。純粋関数で BudgetState を更新し停止判定する。

import type { AssessmentState, BudgetState, StopReason } from "./types/index.js";
import { coverage } from "./coverage.js";

export function recordRequests(budget: BudgetState, host: string, n = 1): BudgetState {
  return {
    ...budget,
    totalRequests: budget.totalRequests + n,
    requestsPerTarget: { ...budget.requestsPerTarget, [host]: (budget.requestsPerTarget[host] ?? 0) + n },
  };
}

export function recordTokens(budget: BudgetState, n: number): BudgetState {
  return { ...budget, tokensUsed: budget.tokensUsed + n };
}

export function elapsedMs(budget: BudgetState, now: number = Date.now()): number {
  const started = Date.parse(budget.startedAt);
  return Number.isNaN(started) ? 0 : now - started;
}

export interface StopDecision {
  stop: boolean;
  reason?: StopReason;
  detail: string;
}

export interface StopOptions {
  /** no-progress: 直近 N ステップで findings も新画面もゼロ(呼び出し側が計測) */
  stepsWithoutProgress?: number;
  noProgressThreshold?: number;
  /** unreachable: 連続到達不能(WAF)カウント */
  consecutiveUnreachable?: number;
  unreachableThreshold?: number;
  now?: number;
}

/** 停止すべきかを評価(DESIGN §4.4 の 5 条件)。優先: halt > budget > unreachable > coverage > no_progress。 */
export function evaluateStop(state: AssessmentState, opts: StopOptions = {}): StopDecision {
  if (state.phase === "halted") return { stop: true, reason: "human_halt", detail: "already halted" };

  const b = state.budget;
  if (b.tokensUsed >= b.limits.maxTokens) {
    return { stop: true, reason: "budget_exceeded", detail: `tokens ${b.tokensUsed}/${b.limits.maxTokens}` };
  }
  if (b.totalRequests >= b.limits.maxTotalRequests) {
    return { stop: true, reason: "budget_exceeded", detail: `requests ${b.totalRequests}/${b.limits.maxTotalRequests}` };
  }
  if (elapsedMs(b, opts.now) >= b.limits.maxWallClockMs) {
    return { stop: true, reason: "budget_exceeded", detail: "wall-clock exceeded" };
  }
  for (const [host, n] of Object.entries(b.requestsPerTarget)) {
    if (n >= b.limits.maxRequestsPerTarget) {
      return { stop: true, reason: "budget_exceeded", detail: `requests to ${host} ${n}/${b.limits.maxRequestsPerTarget}` };
    }
  }

  if (opts.consecutiveUnreachable != null && opts.consecutiveUnreachable >= (opts.unreachableThreshold ?? 10)) {
    return { stop: true, reason: "unreachable", detail: `target unreachable (${opts.consecutiveUnreachable} consecutive)` };
  }

  const cov = coverage(state);
  if (cov.complete) {
    return { stop: true, reason: "coverage_complete", detail: `all ${cov.total} screens terminal` };
  }

  if (opts.stepsWithoutProgress != null && opts.stepsWithoutProgress >= (opts.noProgressThreshold ?? 50)) {
    return { stop: true, reason: "no_progress", detail: `${opts.stepsWithoutProgress} steps without progress` };
  }

  return { stop: false, detail: "continue" };
}
