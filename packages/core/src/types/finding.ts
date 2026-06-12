// DESIGN §7.6 — findings 集約。confirmed Hypothesis or 決定論チェック陽性 + 証拠群。

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type FindingSource =
  | { kind: "hypothesis"; hypothesisId: string }
  | { kind: "validator"; validatorName: string };

export interface Finding {
  id: string;
  /** 由来画面。画面横断なら null */
  screenId: string | null;
  title: string;
  severity: Severity;
  source: FindingSource;
  description: string;
  /** 再現手順 */
  reproSteps: string;
  evidenceIds: string[];
  /** スコープ根拠(なぜ in-scope か) */
  scopeBasis: string;
}
