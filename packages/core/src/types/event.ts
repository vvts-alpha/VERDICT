// DESIGN §4.1 — append-only イベントログ。
// すべての状態遷移を StateEvent として追記 → 再生可能・監査可能。

import type { Phase } from "./phase.js";
import type { TargetInput } from "./input.js";
import type { ScopePolicy } from "./scope.js";
import type { BudgetState, StopReason } from "./budget.js";
import type { HypoStatus } from "./hypothesis.js";
import type { HandoffReason } from "./handoff.js";
import type { ScreenScanStatus } from "./screen-scan.js";

interface EventEnvelope<TType extends string, TPayload> {
  /** アセスメント内で 1 始まりの単調増加 */
  seq: number;
  /** ISO-8601 */
  ts: string;
  type: TType;
  payload: TPayload;
}

export type StateEvent =
  | EventEnvelope<"assessment_created", { id: string; target: TargetInput }>
  | EventEnvelope<"phase_changed", { from: Phase; to: Phase }>
  | EventEnvelope<"scope_updated", { scope: ScopePolicy }>
  | EventEnvelope<"budget_updated", { budget: BudgetState }>
  | EventEnvelope<"screen_discovered", { screenId: string }>
  | EventEnvelope<"screen_updated", { screenId: string }>
  | EventEnvelope<
      "screen_scan_status_changed",
      { screenId: string; from: ScreenScanStatus; to: ScreenScanStatus }
    >
  | EventEnvelope<"hypothesis_created", { hypothesisId: string; screenId: string }>
  | EventEnvelope<
      "hypothesis_status_changed",
      { hypothesisId: string; from: HypoStatus; to: HypoStatus }
    >
  | EventEnvelope<"finding_created", { findingId: string }>
  | EventEnvelope<"handoff_requested", { handoffId: string; reason: HandoffReason }>
  | EventEnvelope<"handoff_resolved", { handoffId: string }>
  | EventEnvelope<"halted", { reason: StopReason; detail?: string }>
  | EventEnvelope<"control_changed", { paused: boolean; reason?: string }>
  | EventEnvelope<"note", { message: string }>;

export type StateEventType = StateEvent["type"];

/** union の各メンバから seq/ts を落とす(ストアが採番する) */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** appendEvent に渡す入力(seq/ts はストアが付与) */
export type StateEventInput = DistributiveOmit<StateEvent, "seq" | "ts">;
