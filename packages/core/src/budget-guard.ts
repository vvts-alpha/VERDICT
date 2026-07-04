// DESIGN §4.4 — BudgetGuard (budget / stop conditions). Pure functions update BudgetState and decide when to stop.

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
  /** no-progress: zero findings and zero new screens over the last N steps (measured by the caller) */
  stepsWithoutProgress?: number;
  noProgressThreshold?: number;
  /** unreachable: consecutive-unreachable (WAF) count */
  consecutiveUnreachable?: number;
  unreachableThreshold?: number;
  now?: number;
}

/** Evaluate whether to stop (the 5 conditions of DESIGN §4.4). Priority: halt > budget > unreachable > coverage > no_progress. */
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
