// 契約スキーマのバレル。全レイヤー(crawler/scanner/agent/server/webui)が core から型を共有する。

export type { TargetInput } from "./input.js";
export type { Phase } from "./phase.js";
export type { PolicyDecision, RateLimit, ScopePolicy } from "./scope.js";
export type { BudgetLimits, BudgetState, StopReason } from "./budget.js";
export type {
  AuthState,
  ScreenType,
  ParamLoc,
  JsonShape,
  ApiCall,
  GuessedType,
  Param,
  Screen,
} from "./screen.js";
export type { ScreenScanStatus, ScreenScan, Coverage } from "./screen-scan.js";
export type { HypoStatus, HypothesisClass, Hypothesis } from "./hypothesis.js";
export type { Severity, FindingSource, Finding } from "./finding.js";
export type { HandoffReason, HandoffStatus, HumanHandoff } from "./handoff.js";
export type { StateEvent, StateEventType, StateEventInput } from "./event.js";
export type { AssessmentState, AssessmentSummary } from "./state.js";
