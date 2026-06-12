// @veritas/core — 全レイヤーが共有する契約型 + AssessmentState の SQLite ストア。

// 契約スキーマ(DESIGN §4.1, §5, §6.6, §7.4 ...)
export type {
  TargetInput,
  Phase,
  PolicyDecision,
  RateLimit,
  ScopePolicy,
  BudgetLimits,
  BudgetState,
  StopReason,
  AuthState,
  ScreenType,
  ParamLoc,
  JsonShape,
  ApiCall,
  GuessedType,
  Param,
  Screen,
  ScreenScanStatus,
  ScreenScan,
  Coverage,
  HypoStatus,
  HypothesisClass,
  Hypothesis,
  Severity,
  FindingSource,
  Finding,
  HandoffReason,
  HandoffStatus,
  HumanHandoff,
  StateEvent,
  StateEventType,
  StateEventInput,
  AssessmentState,
  AssessmentSummary,
} from "./types/index.js";

// SQLite 状態ストア
export { AssessmentStore } from "./store.js";
export type { CreateAssessmentParams } from "./store.js";

// 初期状態ファクトリ
export { newAssessmentId, defaultBudget, deriveScopeFromSingleUrl } from "./factories.js";

// カバレッジ台帳の派生ビュー / 優先度付け(純粋関数)
export {
  coverage,
  isScannable,
  prioritizeScreens,
  scoreScreen,
  DEFAULT_MAX_ATTEMPTS,
} from "./coverage.js";
export type { PrioritizedScreen } from "./coverage.js";

// スコープ判定(crawler / scanner 共有)
export { hostMatches, isInScope } from "./scope-check.js";

// サイトツリー / 状態投影(M3 WebUI 契約)
export { buildSiteTree } from "./tree.js";
export type { TreeNode } from "./tree.js";
export { buildStateView } from "./view.js";
export type { StateView, WsMessage } from "./view.js";

// 予算・停止条件 / レポート(M7)
export { recordRequests, recordTokens, elapsedMs, evaluateStop } from "./budget-guard.js";
export type { StopDecision, StopOptions } from "./budget-guard.js";
export { buildReport } from "./report.js";
