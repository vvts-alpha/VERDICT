// DESIGN §4.4 — BudgetGuard(予算・停止条件)

export interface BudgetLimits {
  maxTokens: number;
  maxWallClockMs: number;
  maxTotalRequests: number;
  maxRequestsPerTarget: number;
}

export interface BudgetState {
  limits: BudgetLimits;
  /** ISO-8601。実時間予算の起点 */
  startedAt: string;
  tokensUsed: number;
  totalRequests: number;
  /** host -> このターゲットへ送ったリクエスト数 */
  requestsPerTarget: Record<string, number>;
}

/** 停止条件(DESIGN §4.4) */
export type StopReason =
  | "coverage_complete"
  | "budget_exceeded"
  | "no_progress"
  | "unreachable"
  | "human_halt";
