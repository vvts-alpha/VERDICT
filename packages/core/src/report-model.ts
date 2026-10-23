// The structured report model (pure). Concentrates "what to include" into one type, and each format's
// renderer (markdown / html / csv / inventory) handles "how to present it". PDF prints the html with
// Chromium (crawler-side). screens[] is the survey-result screen inventory (for standalone export).

import type { AssessmentState, AuthState, CheckExecution, CheckStatus, Finding, FindingVerdict, Phase, ScopePolicy, ScreenScanStatus, ScreenType, Severity } from "./types/index.js";
import { coverage } from "./coverage.js";
import { OBSERVATION_CHECK_CLASSES, rollupChecks } from "./checks.js";
import { deriveRoleProgress, type RoleProgress } from "./view.js";
import { mutationLedger, type MutationRow } from "./mutations.js";

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
  /** 1-based indexes of other findings sharing this finding's dedup family+endpoint — distinct vulnerabilities
   *  on one mechanism (e.g. sibling disclosures on /ftp/{file}), shown as related but NOT merged. */
  related?: number[];
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

/** One recorded check execution — the coverage row a finding (or its absence) actually rests on.
 *  Evidence is referenced by id + artifact path only; bodies stay in finding evidence / the evidence
 *  viewer so a long ledger can't balloon the report. */
export interface ReportCheckRow {
  screenId: string;
  /** "GET /orders/{id}" or "POST /graphql#name:Op:hash". */
  target: string;
  /** Parameter / JSON pointer the check targeted, when applicable. */
  param?: string;
  /** Concrete object the check exercised, when object-scoped. */
  resource?: string;
  /** Subject label the check ran as (configured role, "unauth", or "" for plan rows). */
  subject: string;
  /** Established principal for the subject, when known. */
  principal?: string;
  tenant?: string;
  origin?: string;
  checkClass: string;
  status: CheckStatus;
  tool?: string;
  baselineOk?: boolean;
  /** Concrete gap reason — required on unverified/blocked/not-applicable rows by the ledger contract. */
  reason?: string;
  /** Evidence the outcome rests on (id + artifact path). */
  evidence: ReportEvidence[];
  /** Findings this check produced. */
  findingIds: string[];
}

/** A screen whose terminal scan status claims it was tested but that has ZERO structured check rows —
 *  the clean verdict came from a legacy run or a log note, so the actual coverage detail is unknown. */
export interface ReportLegacyScreen {
  screenId: string;
  url: string;
  scanStatus: ScreenScanStatus;
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
    screens: {
      total: number;
      /** Screens that reached a conclusive scan status WITH structured backing (check rows or a
       *  recorded finding) — the "tested" headline. */
      scanned: number;
      /** Screens claiming a conclusive status with ZERO structured records (legacy run or log note).
       *  Reported separately so an unbacked claim can never masquerade as a tested count. */
      claimed: number;
      excluded: number;
      remaining: number;
    };
    hypotheses: { total: number; confirmed: number };
    findings: { total: number; bySeverity: Record<Severity, number>; suspected: number };
    checks: {
      total: number;
      byStatus: Record<CheckStatus, number>;
      /** planned slots still waiting for a satisfying execution. */
      unfulfilledPlans: number;
      /** outcome rows without a conclusive answer (unverified + blocked + still running). */
      gaps: number;
      /** screens claiming a conclusive clean scan with zero ledger rows (legacy/log-derived coverage). */
      legacyCleanScreens: number;
    };
  };
  findings: ReportFindingRow[]; // ascending severity (critical→info)
  screens: ReportScreenRow[]; // ascending screenId
  /** The structured check ledger — every executed check with its real context (ledger order). */
  checks: ReportCheckRow[];
  /** Conclusive-looking screens with no ledger rows — coverage detail unknown, not "verified clean". */
  legacyScreens: ReportLegacyScreen[];
  /** Latest survey outcome per authenticated role (full-log projection — a role blocked before any
   *  check row exists keeps its reason here even when it owns zero ledger rows). */
  roleProgress: RoleProgress[];
  /** Mutation ledger — current effective state per (subject, field) for every state-changing write
   *  the assessment performed (empty when nothing was written). */
  mutations: MutationRow[];
}

/** AssessmentState → ReportModel (pure). The single input to every renderer.
 *  Passing opts.loadEvidence pulls in each evidence's req/resp body (the fs read is injected by the caller). */
export function buildReportModel(state: AssessmentState, now: Date = new Date(), opts: BuildReportOptions = {}): ReportModel {
  const cov = coverage(state);
  // confirmed first, ordered by ascending severity within; suspected go to a separate later section.
  const sorted = state.findings.filter((f) => !f.duplicateOf).sort(
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

  // Cluster findings by dedup family::endpoint (the param tail is dropped — sibling params on one mechanism
  // are related, not identical). Only clusters of ≥2 surface a `related` annotation.
  const clusterOf = new Map<number, number[]>();
  const byCluster = new Map<string, number[]>();
  sorted.forEach((f, i) => {
    const parts = (f.dedupKey ?? "").split("::");
    if (parts.length < 2 || !parts[0] || !parts[1]) return;
    const k = `${parts[0]}::${parts[1]}`;
    const arr = byCluster.get(k) ?? [];
    arr.push(i);
    byCluster.set(k, arr);
  });
  for (const idxs of byCluster.values()) {
    if (idxs.length < 2) continue;
    for (const i of idxs) clusterOf.set(i, idxs.filter((j) => j !== i).map((j) => j + 1));
  }

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
    ...(clusterOf.has(idx) ? { related: clusterOf.get(idx) } : {}),
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

  // ── Check-execution ledger → report coverage. Rows keep the store's deterministic (created_at, id)
  //    order so two model builds over the same state are deep-equal. Evidence is referenced by
  //    id + artifact path (bodies stay in finding evidence / the evidence viewer). ──
  const checks: ReportCheckRow[] = state.checkExecutions.map((c: CheckExecution): ReportCheckRow => ({
    screenId: c.screenId,
    target: c.target,
    ...(c.param !== undefined ? { param: c.param } : {}),
    ...(c.resource !== undefined ? { resource: c.resource } : {}),
    subject: c.subject,
    ...(c.principal !== undefined ? { principal: c.principal } : {}),
    ...(c.tenant !== undefined ? { tenant: c.tenant } : {}),
    ...(c.origin !== undefined ? { origin: c.origin } : {}),
    checkClass: c.checkClass,
    status: c.status,
    ...(c.tool !== undefined ? { tool: c.tool } : {}),
    ...(c.baselineOk !== undefined ? { baselineOk: c.baselineOk } : {}),
    ...(c.reason !== undefined ? { reason: c.reason } : {}),
    evidence: c.evidenceIds.map((e): ReportEvidence => ({
      evidenceId: e,
      path: `artifacts/${c.screenId}/${e}/`,
      request: null,
      response: null,
      truncated: false,
    })),
    findingIds: c.findingIds,
  }));

  const byStatus = Object.fromEntries(
    (["planned", "running", "found", "suspected", "tested-clean", "not-applicable", "unverified", "blocked"] as CheckStatus[])
      .map((s) => [s, 0]),
  ) as Record<CheckStatus, number>;
  for (const c of state.checkExecutions) byStatus[c.status] += 1;
  const checkGaps = state.checkExecutions.filter(
    (c) => (c.status === "unverified" || c.status === "blocked" || c.status === "running") && !OBSERVATION_CHECK_CLASSES.has(c.checkClass),
  ).length;
  const unfulfilledPlans = rollupChecks(state.checkExecutions).reduce((n, cell) => n + cell.unfulfilled.length, 0);

  // A screen is "checked" only by verdict-bearing rows — raw traffic observations neither gap nor back it.
  const checkedScreens = new Set(state.checkExecutions.filter((c) => !OBSERVATION_CHECK_CLASSES.has(c.checkClass)).map((c) => c.screenId));
  const findingScreens = new Set(sorted.map((f) => f.screenId).filter((x): x is string => x != null));
  const legacyScreens: ReportLegacyScreen[] = screens
    // A conclusive scan status asserts a finished diagnosis; with zero ledger rows the claim traces to
    // a legacy run or a log note — coverage detail unknown, not verified. A "finding"/"suspected"
    // screen whose recorded finding carries its own evidence stays backed by it; a "clean" claim
    // (nothing found) has no such carrier, so ledgerless clean is always disclosed.
    .filter((s) => {
      if (checkedScreens.has(s.screenId)) return false;
      if (s.scanStatus === "clean") return true;
      return (s.scanStatus === "finding" || s.scanStatus === "suspected") && !findingScreens.has(s.screenId);
    })
    .map((s) => ({ screenId: s.screenId, url: s.url, scanStatus: s.scanStatus as ScreenScanStatus }));

  // "Scanned" counts every screen whose diagnosis actually EXECUTED — conclusive outcomes AND
  // honest inconclusive ones (unverified is an executed terminal status, never a pass but always
  // real work). A legacy/log-claimed clean or finding with zero check rows (and no recorded
  // finding) is disclosed as `claimed` — an unknown-detail status, never folded into the headline.
  const statusClaims = cov.byStatus.clean + cov.byStatus.finding + cov.byStatus.suspected + cov.byStatus.unverified;
  const backedScanned = statusClaims - legacyScreens.length;
  const roleProgress = deriveRoleProgress(state.events);

  return {
    id: state.id,
    brand: "VERDICT",
    target,
    phase: state.phase,
    startedAt: state.budget.startedAt,
    generatedAt: now.toISOString(),
    scope: state.scope,
    stats: {
      screens: { total: cov.total, scanned: backedScanned, claimed: legacyScreens.length, excluded: cov.byStatus.excluded, remaining: cov.remaining },
      hypotheses: { total: state.hypotheses.length, confirmed: confirmedHypotheses },
      findings: { total: confirmedCount, bySeverity, suspected: suspectedCount },
      checks: {
        total: checks.length,
        byStatus,
        unfulfilledPlans,
        gaps: checkGaps,
        legacyCleanScreens: legacyScreens.length,
      },
    },
    findings,
    screens,
    checks,
    legacyScreens,
    roleProgress,
    mutations: mutationLedger(state.events),
  };
}
