// DESIGN §4.4 — BudgetGuard (budget / stop conditions)

export interface BudgetLimits {
  maxTokens: number;
  maxWallClockMs: number;
  maxTotalRequests: number;
  maxRequestsPerTarget: number;
}

export interface BudgetState {
  limits: BudgetLimits;
  /** ISO-8601. Origin of the wall-clock budget */
  startedAt: string;
  tokensUsed: number;
  totalRequests: number;
  /** host -> number of requests sent to this target */
  requestsPerTarget: Record<string, number>;
}

/** Stop conditions (DESIGN §4.4) */
export type StopReason =
  | "coverage_complete"
  | "budget_exceeded"
  | "no_progress"
  | "unreachable"
  | "human_halt";
