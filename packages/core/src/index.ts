// @veritas/core — contract types shared by every layer + the SQLite store for AssessmentState.

// Contract schemas (DESIGN §4.1, §5, §6.6, §7.4 ...)
export type {
  TargetInput,
  Phase,
  PolicyDecision,
  RateLimit,
  ScopePolicy,
  ScopeMode,
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
  FindingVerdict,
  FindingSource,
  Finding,
  HandoffReason,
  HandoffStatus,
  HumanHandoff,
  StateEvent,
  StateEventType,
  StateEventInput,
  ControlCommand,
  AssessmentState,
  AssessmentSummary,
  AssetSource,
  AssetBand,
  AssetScore,
  AssetTriage,
  AssetPathHit,
  FindingSeverity,
  AssetFinding,
  AssetTakeover,
  ListingEntry,
  Asset,
  AssetInventory,
  JsAsset,
  JsSecret,
  JsSink,
} from "./types/index.js";

// SQLite state store
export { AssessmentStore } from "./store.js";
export type { CreateAssessmentParams } from "./store.js";

// Initial-state factories
export { newAssessmentId, defaultBudget, deriveScopeFromSingleUrl, deriveScopeFromUrls, DEFAULT_BROWSER_UA } from "./factories.js";

// Registrable-domain (eTLD+1) computation (for scope mode="etld")
export { registrableDomain } from "./etld.js";

// Derived views over the coverage ledger / prioritization (pure functions)
export {
  coverage,
  isScannable,
  prioritizeScreens,
  scoreScreen,
  DEFAULT_MAX_ATTEMPTS,
} from "./coverage.js";
export type { PrioritizedScreen } from "./coverage.js";

// Scope decisions (shared by crawler / scanner)
export { hostMatches, isInScope, parseTargetUrl } from "./scope-check.js";

// Site tree / state projection (M3 WebUI contract)
export { buildSiteTree } from "./tree.js";
export type { TreeNode } from "./tree.js";
export { buildStateView } from "./view.js";
export type { StateView, WsMessage } from "./view.js";

// Budget / stop conditions / report (M7)
export { recordRequests, recordTokens, elapsedMs, evaluateStop } from "./budget-guard.js";
export type { StopDecision, StopOptions } from "./budget-guard.js";
export { buildReport, renderMarkdown } from "./report.js";
export { buildReportModel, SEVERITY_ORDER, findingVerdict } from "./report-model.js";
export type { ReportModel, ReportFindingRow, ReportScreenRow, ReportEvidence, EvidenceLoader, BuildReportOptions } from "./report-model.js";
export { renderReportHtml, renderFindingsCsv, renderScreensCsv, renderInventoryHtml } from "./report-formats.js";
export { buildOpenApi, jsonShapeToSchema, schemaToJsonShape } from "./openapi.js";
export type { BuildOpenApiOptions } from "./openapi.js";
export type { ReadinessCheck } from "./types/readiness.js";
