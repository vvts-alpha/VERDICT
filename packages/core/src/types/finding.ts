// DESIGN §7.6 — findings aggregation. A confirmed Hypothesis or a positive deterministic check + its evidence set.

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** Evidence confidence. `confirmed` = negative control fails + >=2 stable positives (the invariant).
 *  `suspected` = one concrete observed anomaly + a rationale (a lower bar on a separate path; does not clear the confirmed gate).
 *  When absent, `confirmed` (backward compat: all existing findings are treated as confirmed). */
export type FindingVerdict = "confirmed" | "suspected";

export type FindingSource =
  | { kind: "hypothesis"; hypothesisId: string }
  | { kind: "validator"; validatorName: string };

export interface Finding {
  id: string;
  /** Stable recording key, retained across resume instead of guessing from the title. */
  dedupKey?: string;
  /** Superseded record retained for audit; evidence is linked from the canonical finding. */
  duplicateOf?: string;
  /** Originating screen. null if cross-screen */
  screenId: string | null;
  title: string;
  severity: Severity;
  /** Evidence confidence. Absent ⇒ "confirmed" (backward compat). */
  verdict?: FindingVerdict;
  /** Required when verdict==="suspected": the single observed anomaly and why it's a lead. */
  anomaly?: string;
  source: FindingSource;
  description: string;
  /** Reproduction steps */
  reproSteps: string;
  evidenceIds: string[];
  /** Scope basis (why it is in-scope) */
  scopeBasis: string;
  /** Relative path (under artifacts/) to a browser screenshot captured when the finding was recorded — visual
   *  context beyond the raw request/response. e.g. "findings/f-003.png". Absent when no browser page was available. */
  screenshot?: string;
}
