// The structured report model (pure). Concentrates "what to include" into one type, and each format's
// renderer (markdown / html / csv / inventory) handles "how to present it". PDF prints the html with
// Chromium (crawler-side). screens[] is the survey-result screen inventory (for standalone export).

import type { AssessmentState, AuthState, Finding, FindingVerdict, Phase, ScopePolicy, ScreenScanStatus, ScreenType, Severity } from "./types/index.js";
import { coverage } from "./coverage.js";

export const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VERDICT_ORDER: Record<FindingVerdict, number> = { confirmed: 0, suspected: 1 };

/** finding confidence. Absent ⇒ confirmed (backward compat: all existing findings are confirmed). */
export const findingVerdict = (f: Pick<Finding, "verdict">): FindingVerdict => f.verdict ?? "confirmed";

/** One piece of evidence a finding cites. The body (req/resp) is present only when loadEvidence supplies it. */
export interface ReportEvidence {
  evidenceId: string;
  path: string; // artifacts/<screenId|_>/<evidenceId>/
  request: string | null; // raw HTTP request (redacted)
  response: string | null; // raw HTTP response (redacted, possibly truncated)
  truncated: boolean;
}

export interface ReportFindingRow {
  index: number; // 1-based
  title: string;
  severity: Severity;
  verdict: FindingVerdict;
  /** When suspected: the observed anomaly + rationale. */
  anomaly?: string;
  screenId: string | null;
  sourceKind: "validator" | "hypothesis";
  sourceName: string; // validatorName or hypothesisId
  scopeBasis: string;
  description: string;
  reproSteps: string;
  evidence: ReportEvidence[]; // with bodies (when loadEvidence is passed); otherwise path only
}

/** Loader returning raw req/resp for an evidenceId (the impure fs read is injected by the caller = cli/server). core stays pure. */
export type EvidenceLoader = (evidenceId: string) => { request: string | null; response: string | null; truncated?: boolean } | null;

export interface BuildReportOptions {
  loadEvidence?: EvidenceLoader;
}

/** One screen the survey discovered (a row in the screen inventory). */
export interface ReportScreenRow {
  screenId: string;
  url: string; // urlTemplate
  screenType: ScreenType;
  authState: AuthState;
  labels: string[];
  paramCount: number;
  apiCount: number;
  scanStatus: ScreenScanStatus | "unknown";
  screenshot: string; // relative to the artifacts directory (e.g. "screens/s-0001.png"); "" if not captured
}

export interface ReportModel {
  id: string;
  brand: string;
  target: string;
  phase: Phase;
  startedAt: string; // ISO (budget.startedAt = run start)
  generatedAt: string; // ISO
  scope: ScopePolicy;
  stats: {
    screens: { total: number; scanned: number; excluded: number; remaining: number };
    hypotheses: { total: number; confirmed: number };
    findings: { total: number; bySeverity: Record<Severity, number>; suspected: number };
  };
  findings: ReportFindingRow[]; // ascending severity (critical→info)
  screens: ReportScreenRow[]; // ascending screenId
}

/** AssessmentState → ReportModel (pure). The single input to every renderer.
 *  Passing opts.loadEvidence pulls in each evidence's req/resp body (the fs read is injected by the caller). */
export function buildReportModel(state: AssessmentState, now: Date = new Date(), opts: BuildReportOptions = {}): ReportModel {
  const cov = coverage(state);
  // confirmed first, ordered by ascending severity within; suspected go to a separate later section.
  const sorted = [...state.findings].sort(
    (a, b) => VERDICT_ORDER[findingVerdict(a)] - VERDICT_ORDER[findingVerdict(b)] || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
  const target = state.target.kind === "single_url" ? state.target.url : `scope_manifest ${state.target.path}`;
  const confirmedHypotheses = state.hypotheses.filter((h) => h.status === "confirmed").length;

  // The headline (bySeverity / total) is confirmed only; suspected are counted separately.
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let confirmedCount = 0;
  for (const f of sorted) if (findingVerdict(f) === "confirmed") { bySeverity[f.severity] += 1; confirmedCount += 1; }
  const suspectedCount = sorted.length - confirmedCount;

  const scanByScreen = new Map<string, ScreenScanStatus>();
  for (const sc of state.screenScans) scanByScreen.set(sc.screenId, sc.status);

  const findings: ReportFindingRow[] = sorted.map((f, idx) => ({
    index: idx + 1,
    title: f.title,
    severity: f.severity,
    verdict: findingVerdict(f),
    ...(f.anomaly ? { anomaly: f.anomaly } : {}),
    screenId: f.screenId ?? null,
    sourceKind: f.source.kind,
    sourceName: f.source.kind === "validator" ? f.source.validatorName : f.source.hypothesisId,
    scopeBasis: f.scopeBasis,
    description: f.description,
    reproSteps: f.reproSteps,
    evidence: f.evidenceIds.map((e): ReportEvidence => {
      const loaded = opts.loadEvidence?.(e) ?? null;
      // A missing-header ("[headers] ...") finding is proven by the response HEADER block alone — the HTML body is
      // irrelevant to it and was dominating the report (the same page body re-embedded once per header finding, so a
      // 45-header run ballooned to 1.3MB / 23k lines). Keep only the status line + headers for these; real findings
      // keep full bodies. Fixing it here in the shared model covers markdown, html, and pdf at once.
      let response = loaded?.response ?? null;
      let truncated = loaded?.truncated ?? false;
      if (response && f.title.startsWith("[headers]")) {
        const headerBlock = response.split(/\r?\n\r?\n/)[0] ?? response;
        if (headerBlock.length < response.length) {
          response = headerBlock;
          truncated = true;
        }
      }
      return {
        evidenceId: e,
        path: `artifacts/${f.screenId ?? "_"}/${e}/`,
        request: loaded?.request ?? null,
        response,
        truncated,
      };
    }),
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
    brand: "VERDICT",
    target,
    phase: state.phase,
    startedAt: state.budget.startedAt,
    generatedAt: now.toISOString(),
    scope: state.scope,
    stats: {
      screens: { total: cov.total, scanned: cov.byStatus.clean + cov.byStatus.finding + cov.byStatus.suspected, excluded: cov.byStatus.excluded, remaining: cov.remaining },
      hypotheses: { total: state.hypotheses.length, confirmed: confirmedHypotheses },
      findings: { total: confirmedCount, bySeverity, suspected: suspectedCount },
    },
    findings,
    screens,
  };
}
