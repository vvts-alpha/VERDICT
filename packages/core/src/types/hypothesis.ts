// DESIGN §7.4 — 攻撃仮説(=「方針」)。WebUI の HYPOTHESES に表示される単位。

export type HypoStatus = "queued" | "testing" | "confirmed" | "refuted" | "blocked";

export type HypothesisClass =
  | "idor"
  | "privilege_escalation"
  | "price_tampering"
  | "qty_tampering"
  | "state_skip"
  | "mass_assignment"
  | "race"
  | "auth_bypass"
  | "info_disclosure"
  | "other";

export interface Hypothesis {
  id: string;
  screenId: string;
  class: HypothesisClass;
  /** 「他人の order_id を閲覧できる」 */
  statement: string;
  /** 具体手順 */
  testPlan: string;
  status: HypoStatus;
  /** EvidenceStore の証拠 id 群 */
  evidenceIds: string[];
}
