// レポートの構造化モデル(純粋)。"何を載せるか" を1つの型に集約し、各フォーマットの
// レンダラ(markdown / html / csv / inventory)が "どう出すか" を担う。PDF は html を
// Chromium で印刷する(crawler 側)。screens[] は survey 結果の画面一覧(単体エクスポート用)。

import type { AssessmentState, AuthState, Phase, ScopePolicy, ScreenScanStatus, ScreenType, Severity } from "./types/index.js";
import { coverage } from "./coverage.js";

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export interface ReportFindingRow {
  index: number; // 1-based
  title: string;
  severity: Severity;
  screenId: string | null;
  sourceKind: "validator" | "hypothesis";
  sourceName: string; // validatorName または hypothesisId
  scopeBasis: string;
  description: string;
  reproSteps: string;
  evidencePaths: string[]; // artifacts/<screenId|_>/<evidenceId>/
}

/** survey が検出した1画面(画面一覧の1行)。 */
export interface ReportScreenRow {
  screenId: string;
  url: string; // urlTemplate
  screenType: ScreenType;
  authState: AuthState;
  labels: string[];
  paramCount: number;
  apiCount: number;
  scanStatus: ScreenScanStatus | "unknown";
  screenshot: string; // artifacts ディレクトリ相対(例 "screens/s-0001.png")。未取得なら ""
}

export interface ReportModel {
  id: string;
  brand: string;
  target: string;
  phase: Phase;
  generatedAt: string; // ISO
  scope: ScopePolicy;
  stats: {
    screens: { total: number; scanned: number; remaining: number };
    hypotheses: { total: number; confirmed: number };
    findings: { total: number; bySeverity: Record<Severity, number> };
  };
  findings: ReportFindingRow[]; // severity 昇順(critical→info)
  screens: ReportScreenRow[]; // screenId 昇順
}

/** AssessmentState → ReportModel(純粋)。全レンダラの単一の入力。 */
export function buildReportModel(state: AssessmentState, now: Date = new Date()): ReportModel {
  const cov = coverage(state);
  const sorted = [...state.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const target = state.target.kind === "single_url" ? state.target.url : `scope_manifest ${state.target.path}`;
  const confirmedHypotheses = state.hypotheses.filter((h) => h.status === "confirmed").length;

  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of sorted) bySeverity[f.severity] += 1;

  const scanByScreen = new Map<string, ScreenScanStatus>();
  for (const sc of state.screenScans) scanByScreen.set(sc.screenId, sc.status);

  const findings: ReportFindingRow[] = sorted.map((f, idx) => ({
    index: idx + 1,
    title: f.title,
    severity: f.severity,
    screenId: f.screenId ?? null,
    sourceKind: f.source.kind,
    sourceName: f.source.kind === "validator" ? f.source.validatorName : f.source.hypothesisId,
    scopeBasis: f.scopeBasis,
    description: f.description,
    reproSteps: f.reproSteps,
    evidencePaths: f.evidenceIds.map((e) => `artifacts/${f.screenId ?? "_"}/${e}/`),
  }));

  const screens: ReportScreenRow[] = [...state.screens]
    .sort((a, b) => a.screenId.localeCompare(b.screenId))
    .map((s) => ({
      screenId: s.screenId,
      url: s.urlTemplate,
      screenType: s.screenType,
      authState: s.authState,
      labels: s.labels,
      paramCount: s.params.length,
      apiCount: s.apis.length,
      scanStatus: scanByScreen.get(s.screenId) ?? "unknown",
      screenshot: s.screenshot,
    }));

  return {
    id: state.id,
    brand: "AMRAAM",
    target,
    phase: state.phase,
    generatedAt: now.toISOString(),
    scope: state.scope,
    stats: {
      screens: { total: cov.total, scanned: cov.terminal, remaining: cov.remaining },
      hypotheses: { total: state.hypotheses.length, confirmed: confirmedHypotheses },
      findings: { total: state.findings.length, bySeverity },
    },
    findings,
    screens,
  };
}
