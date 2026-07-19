// DESIGN §8.1 — the state projection the server pushes to the WebUI + the WS message contract.
// "State for the UI" and "working memory" are the same thing (§4.1), so this is purely derived from AssessmentState.

import type {
  AssessmentState,
  BudgetState,
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
    events: state.events.slice(-300),
    paused: derivePaused(state.events),
    lastSeq: last ? last.seq : 0,
  };
}
