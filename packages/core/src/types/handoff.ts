// DESIGN §6.3 / §6.4 / §8.3 — human-handoff request (auth / approval). No cookie injection.

export type HandoffReason = "auth" | "approval" | "captcha" | "rate_limit" | "other";

export type HandoffStatus = "pending" | "resolved" | "cancelled";

export interface HumanHandoff {
  id: string;
  reason: HandoffReason;
  /** Target URL for the human to log in at, etc. null if none */
  url: string | null;
  message: string;
  status: HandoffStatus;
  /** ISO-8601 */
  createdAt: string;
  resolvedAt: string | null;
}
