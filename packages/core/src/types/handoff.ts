// DESIGN §6.3 / §6.4 / §8.3 — 人間ハンドオフ要求(認証 / 承認)。Cookie 注入はしない。

export type HandoffReason = "auth" | "approval" | "captcha" | "rate_limit" | "other";

export type HandoffStatus = "pending" | "resolved" | "cancelled";

export interface HumanHandoff {
  id: string;
  reason: HandoffReason;
  /** 人間にログインさせる対象 URL 等。無ければ null */
  url: string | null;
  message: string;
  status: HandoffStatus;
  /** ISO-8601 */
  createdAt: string;
  resolvedAt: string | null;
}
