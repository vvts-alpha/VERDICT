// DESIGN §7.6 — findings 集約。confirmed Hypothesis or 決定論チェック陽性 + 証拠群。

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** 証拠の確度。`confirmed` = negative-control 失敗 + >=2 安定 positive(不変条件)。
 *  `suspected` = 具体的な観測異常が 1 件 + 根拠あり(別経路の低いバー。confirmed のゲートには到達しない)。
 *  欠落時は `confirmed`(後方互換: 既存 finding は全て confirmed 扱い)。 */
export type FindingVerdict = "confirmed" | "suspected";

export type FindingSource =
  | { kind: "hypothesis"; hypothesisId: string }
  | { kind: "validator"; validatorName: string };

export interface Finding {
  id: string;
  /** 由来画面。画面横断なら null */
  screenId: string | null;
  title: string;
  severity: Severity;
  /** 証拠の確度。欠落 ⇒ "confirmed"(後方互換)。 */
  verdict?: FindingVerdict;
  /** verdict==="suspected" のとき必須: 観測した単一の異常と、それがリードである理由。 */
  anomaly?: string;
  source: FindingSource;
  description: string;
  /** 再現手順 */
  reproSteps: string;
  evidenceIds: string[];
  /** スコープ根拠(なぜ in-scope か) */
  scopeBasis: string;
}
