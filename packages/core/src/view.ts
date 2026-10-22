// DESIGN §8.1 — the state projection the server pushes to the WebUI + the WS message contract.
// "State for the UI" and "working memory" are the same thing (§4.1), so this is purely derived from AssessmentState.

import type {
  AssessmentState,
  AuthzComparison,
  AuthzObject,
  BudgetState,
  CheckExecution,
  Coverage,
  Finding,
  HumanHandoff,
  Hypothesis,
  JsAsset,
  Phase,
  Screen,
  ScreenScan,
  StateEvent,
  TargetInput,
} from "./types/index.js";
import { coverage } from "./coverage.js";
import { mutationLedger, type MutationRow } from "./mutations.js";
import { buildSiteTree, type TreeNode } from "./tree.js";

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

export function buildStateView(state: AssessmentState): StateView {
  const last = state.events[state.events.length - 1];
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
    authzObjects: state.authzObjects,
    authzComparisons: state.authzComparisons,
    mutations: mutationLedger(state.events),
    roleProgress: deriveRoleProgress(state.events),
    events: state.events.slice(-300),
    paused: derivePaused(state.events),
    lastSeq: last ? last.seq : 0,
  };
}
