// DESIGN §7.4 — attack hypothesis (= a "line of attack"). The unit displayed in the WebUI's HYPOTHESES.

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
  /** e.g. "can view another user's order_id" */
  statement: string;
  /** Concrete steps */
  testPlan: string;
  status: HypoStatus;
  /** Evidence ids in the EvidenceStore */
  evidenceIds: string[];
}
