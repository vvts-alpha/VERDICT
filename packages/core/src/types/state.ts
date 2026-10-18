// DESIGN §4.1 — AssessmentState. The agent's working memory = the single canonical state that is the WebUI data source.

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
import type { CheckExecution } from "./check.js";
import type { AuthzComparison, AuthzObject } from "./authz.js";

export interface AssessmentState {
  id: string;
  target: TargetInput;
  phase: Phase;
  scope: ScopePolicy;
  budget: BudgetState;
  screens: Screen[];
  /** The Phase2 coverage ledger (scan state of each discovered screen) */
  screenScans: ScreenScan[];
  hypotheses: Hypothesis[];
  findings: Finding[];
  handoffs: HumanHandoff[];
  /** Per-check execution ledger (one row per bounded check). Persisted in its own table —
   *  never derived from the capped recent-events window. */
  checkExecutions: CheckExecution[];
  /** Observed object references + verified ownership state (discovery vs proven relationship). */
  authzObjects: AuthzObject[];
  /** Bounded A/B authorization comparisons with their evidence ids. */
  authzComparisons: AuthzComparison[];
  /** append-only (replayable) */
  events: StateEvent[];
}

/** Lightweight summary for listAssessments */
export interface AssessmentSummary {
  id: string;
  phase: Phase;
  target: TargetInput;
  createdAt: string;
  updatedAt: string;
}
