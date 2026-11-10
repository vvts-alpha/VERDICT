// DESIGN §8.1 — the state projection the server pushes to the WebUI + the WS message contract.
// "State for the UI" and "working memory" are the same thing (§4.1), so this is purely derived from AssessmentState.

import type {
  AssessmentState,
  AuthzComparison,
  AuthzObject,
  BudgetState,
  CheckExecution,
  CheckStatus,
  Coverage,
  Finding,
  HumanHandoff,
  Hypothesis,
  JsAsset,
  Phase,
  Screen,
  ScreenScan,
  ScreenScanStatus,
  StateEvent,
  TargetInput,
} from "./types/index.js";
import { screenChecks, type ScreenCheckView } from "./checks.js";
import { coverage } from "./coverage.js";
import { mutationLedger, type MutationRow } from "./mutations.js";
import { buildSiteTree, type TreeNode } from "./tree.js";

/** The server's authoritative display status for one scanned screen. Never infer check coverage
 * from the recent-events window: old runs can have no check rows, and raw HTTP is not a verdict. */
export interface ScreenHonesty {
  status: ScreenScanStatus | "unknown-records";
  raw: ScreenScanStatus;
  legacy: boolean;
  gaps: number;
  unfulfilled: number;
}

/** Compact, audit-friendly class rollup from screenChecks (not a second implementation of plan matching). */
export interface ScreenCheckClassSummary {
  checkClass: string;
  status: CheckStatus;
  /** Outcome multiplicity includes historical attempts; `gaps` counts only current unresolved ones. */
  outcomes: Array<{ status: CheckStatus; count: number }>;
  gaps: number;
  unfulfilled: number;
}

export interface ScreenCheckSummary {
  /** Ledger-only verdict for the Scenarios tab, including screens that have no ScreenScan row. */
  verdict: "finding" | "suspected" | "unverified" | "planned" | "clean";
  classes: ScreenCheckClassSummary[];
  gaps: number;
  unfulfilled: number;
}

export interface StateView {
  id: string;
  phase: Phase;
  target: TargetInput;
  budget: BudgetState;
  coverage: Coverage;
  tree: TreeNode[];
  screens: Screen[];
  screenScans: ScreenScan[];
  hypotheses: Hypothesis[];
  findings: Finding[];
  handoffs: HumanHandoff[];
  /** First-party JS bundles the agent analyzed (endpoints/secrets mined) — the JS tab + agent dedup. */
  jsAssets: JsAsset[];
  /** Per-check execution ledger (table-backed — NOT capped by the events window). */
  checkExecutions: CheckExecution[];
  /** Server-projected display status for every scanned screen, including legacy ledgerless runs. */
  screenHonesty: Record<string, ScreenHonesty>;
  /** Compact class results for screens with ledger rows (raw observations get an unverified verdict). */
  screenCheckSummaries: Record<string, ScreenCheckSummary>;
  /** Observed objects + verified ownership for authorization testing. */
  authzObjects: AuthzObject[];
  /** Bounded A/B authorization comparisons with provenance evidence ids. */
  authzComparisons: AuthzComparison[];
  /** Effective current state per (subject, field) — last-write-wins over mutation_recorded events. */
  mutations: MutationRow[];
  /** Latest survey progress per authenticated role — projected from the FULL log, NOT the capped
   *  window below, so a blocked role's reason survives any amount of later log noise. */
  roleProgress: RoleProgress[];
  /** Recent activity log (for the diagnosis-log tab). Capped to the last 300 since too many is heavy. */
  events: StateEvent[];
  /** Whether paused via a WebUI action (derived from control_changed events) */
  paused: boolean;
  /** Last known event seq (baseline for WS diffs) */
  lastSeq: number;
}

export type WsMessage =
  | { type: "snapshot"; view: StateView }
  | { type: "events"; events: StateEvent[]; view: StateView }
  | { type: "error"; message: string };

function derivePaused(events: AssessmentState["events"]): boolean {
  for (let i = events.length - 1; i >= 0; i -= 1) {
    const e = events[i];
    if (e && e.type === "control_changed") return e.payload.paused;
  }
  return false;
}

/** Fold the append-only log into the analyzed-JS list (last write per url wins = free dedup). */
function deriveJsAssets(events: AssessmentState["events"]): JsAsset[] {
  const byUrl = new Map<string, JsAsset>();
  for (const e of events) if (e.type === "js_analyzed") byUrl.set(e.payload.url, e.payload);
  return [...byUrl.values()];
}

/** Latest survey outcome for one authenticated role (last write wins across the FULL log). */
export interface RoleProgress {
  role: string;
  visited: number;
  /** Pending frontier URLs + referer-gated URLs at the latest snapshot (0 when not reported). */
  pending: number;
  gated: number;
  state: "mapped" | "blocked";
  /** Concrete block reason (session expired / login bounce / …) — kept on blocked rows. */
  reason?: string;
}

/** Latest `survey_role_progress` per role, folded from the FULL append-only log — a role blocked
 *  before any check row exists must not lose its reason to the capped display window (>300
 *  intervening notes or a SQLite reopen would otherwise erase it). First-seen role order is kept
 *  so the projection is deterministic for a fixed log. */
export function deriveRoleProgress(events: AssessmentState["events"]): RoleProgress[] {
  const byRole = new Map<string, RoleProgress>();
  for (const e of events) {
    if (e.type !== "survey_role_progress") continue;
    const p = e.payload;
    byRole.set(p.role, {
      role: p.role,
      visited: p.visited,
      pending: p.pending?.length ?? 0,
      gated: p.gated?.length ?? 0,
      state: p.state,
      ...(p.reason !== undefined ? { reason: p.reason } : {}),
    });
  }
  return [...byRole.values()];
}

/** Derive the Scenarios chips from the same selector as the coverage gate. In particular, only
 * screenChecks decides whether a plan is satisfied or a failed attempt was superseded. */
function summarizeChecks(checks: ScreenCheckView): ScreenCheckSummary {
  const gapsByClass = new Map<string, number>();
  for (const gap of checks.gaps) gapsByClass.set(gap.checkClass, (gapsByClass.get(gap.checkClass) ?? 0) + 1);
  const classes = checks.classes.map((cell): ScreenCheckClassSummary => {
    const counts = new Map<CheckStatus, number>();
    for (const row of cell.checks) counts.set(row.status, (counts.get(row.status) ?? 0) + 1);
    return {
      checkClass: cell.checkClass,
      status: cell.status,
      outcomes: [...counts].map(([status, count]) => ({ status, count })),
      gaps: gapsByClass.get(cell.checkClass) ?? 0,
      unfulfilled: cell.unfulfilled.length,
    };
  });
  const ran = checks.classes.some((cell) => cell.checks.length > 0);
  const verdict: ScreenCheckSummary["verdict"] =
    checks.classes.some((cell) => cell.status === "found") ? "finding"
      : checks.classes.some((cell) => cell.status === "suspected") ? "suspected"
        : checks.gaps.length > 0 ? "unverified"
          : checks.unstarted.length > 0 ? (ran ? "unverified" : "planned")
            : classes.length === 0 ? "unverified" // raw http-request rows do not prove coverage
              : !ran ? "planned"
                : checks.classes.every((cell) => cell.conclusive) ? "clean" : "unverified";
  return { verdict, classes, gaps: checks.gaps.length, unfulfilled: checks.unstarted.length };
}

export function buildStateView(state: AssessmentState): StateView {
  const last = state.events[state.events.length - 1];
  const rowsByScreen = new Map<string, CheckExecution[]>();
  for (const row of state.checkExecutions) {
    const rows = rowsByScreen.get(row.screenId) ?? [];
    rows.push(row);
    rowsByScreen.set(row.screenId, rows);
  }
  const findingsByScreen = new Set(state.findings.map((f) => f.screenId).filter((sid): sid is string => sid !== null));
  const scansByScreen = new Map(state.screenScans.map((scan) => [scan.screenId, scan] as const));
  const screenHonesty: Record<string, ScreenHonesty> = Object.create(null) as Record<string, ScreenHonesty>;
  const screenCheckSummaries: Record<string, ScreenCheckSummary> = Object.create(null) as Record<string, ScreenCheckSummary>;
  for (const sid of new Set([...scansByScreen.keys(), ...rowsByScreen.keys()])) {
    const rows = rowsByScreen.get(sid);
    const checks = screenChecks({ checkExecutions: rows ?? [] }, sid);
    if (rows) screenCheckSummaries[sid] = summarizeChecks(checks);
    const scan = scansByScreen.get(sid);
    if (!scan) continue;
    const conclusive = scan.status === "clean" || scan.status === "finding" || scan.status === "suspected";
    const legacy = conclusive && checks.legacy && (scan.status === "clean" || !findingsByScreen.has(sid));
    const status = legacy ? "unknown-records"
      : scan.status === "clean" && (checks.gaps.length > 0 || checks.unstarted.length > 0) ? "unverified"
        : scan.status;
    screenHonesty[sid] = {
      status, raw: scan.status, legacy, gaps: checks.gaps.length, unfulfilled: checks.unstarted.length,
    };
  }
  return {
    id: state.id,
    phase: state.phase,
    target: state.target,
    budget: state.budget,
    coverage: coverage(state),
    tree: buildSiteTree(state.screens, state.screenScans),
    screens: state.screens,
    screenScans: state.screenScans,
    hypotheses: state.hypotheses,
    findings: state.findings,
    handoffs: state.handoffs,
    jsAssets: deriveJsAssets(state.events),
    // Ledger rows come from their own persisted tables — never from the capped event window,
    // so >300 intervening events (or a reopen) cannot silently drop coverage records.
    checkExecutions: state.checkExecutions,
    screenHonesty,
    screenCheckSummaries,
    authzObjects: state.authzObjects,
    authzComparisons: state.authzComparisons,
    mutations: mutationLedger(state.events),
    roleProgress: deriveRoleProgress(state.events),
    events: state.events.slice(-300),
    paused: derivePaused(state.events),
    lastSeq: last ? last.seq : 0,
  };
}
