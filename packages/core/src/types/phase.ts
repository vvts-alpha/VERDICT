// DESIGN §4.1 — assessment lifecycle phases

export type Phase =
  | "init"
  | "phase1_recon"
  | "phase1_label"
  | "phase2_scan"
  | "phase2_burpscan"
  | "report"
  | "done"
  | "halted";
