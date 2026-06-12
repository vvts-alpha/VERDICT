// DESIGN §8.1 — server が WebUI に push する状態投影 + WS メッセージ契約。
// 「UI のための state」と「作業記憶」を同一物にする(§4.1)ので、AssessmentState から純粋に導出する。

import type {
  AssessmentState,
  BudgetState,
  Coverage,
  Finding,
  HumanHandoff,
  Hypothesis,
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
  /** 直近の活動ログ(診断ログタブ用)。多すぎると重いので末尾 300 件に制限。 */
  events: StateEvent[];
  /** WebUI 操作で pause 中か(control_changed イベントから導出) */
  paused: boolean;
  /** 既知の最終イベント seq(WS 差分の基準) */
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
    events: state.events.slice(-300),
    paused: derivePaused(state.events),
    lastSeq: last ? last.seq : 0,
  };
}
