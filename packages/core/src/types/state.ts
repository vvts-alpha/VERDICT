// DESIGN §4.1 — AssessmentState。エージェントの作業記憶 = WebUI データソースの単一正規状態。

import type { Phase } from "./phase.js";
import type { TargetInput } from "./input.js";
import type { ScopePolicy } from "./scope.js";
import type { BudgetState } from "./budget.js";
import type { Screen } from "./screen.js";
import type { ScreenScan } from "./screen-scan.js";
import type { Hypothesis } from "./hypothesis.js";
import type { Finding } from "./finding.js";
import type { HumanHandoff } from "./handoff.js";
import type { StateEvent } from "./event.js";

export interface AssessmentState {
  id: string;
  target: TargetInput;
  phase: Phase;
  scope: ScopePolicy;
  budget: BudgetState;
  screens: Screen[];
  /** Phase2 のカバレッジ台帳(検出した各画面のスキャン状態) */
  screenScans: ScreenScan[];
  hypotheses: Hypothesis[];
  findings: Finding[];
  handoffs: HumanHandoff[];
  /** append-only(再生可能) */
  events: StateEvent[];
}

/** listAssessments 用の軽量サマリ */
export interface AssessmentSummary {
  id: string;
  phase: Phase;
  target: TargetInput;
  createdAt: string;
  updatedAt: string;
}
