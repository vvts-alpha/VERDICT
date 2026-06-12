// DESIGN §4.1 — アセスメントのライフサイクルフェーズ

export type Phase =
  | "init"
  | "phase1_recon"
  | "phase1_label"
  | "phase2_scan"
  | "report"
  | "done"
  | "halted";
