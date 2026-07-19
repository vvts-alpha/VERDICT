// DESIGN §4.1 — append-only event log.
// Every state transition is appended as a StateEvent → replayable and auditable.

import type { Phase } from "./phase.js";
import type { TargetInput } from "./input.js";
import type { ScopePolicy } from "./scope.js";
import type { BudgetState, StopReason } from "./budget.js";
import type { HypoStatus } from "./hypothesis.js";
import type { HandoffReason } from "./handoff.js";
import type { ScreenScanStatus } from "./screen-scan.js";
import type { JsAsset } from "./js-asset.js";

interface EventEnvelope<TType extends string, TPayload> {
  /** Monotonically increasing within an assessment, starting at 1 */
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
  | EventEnvelope<"js_analyzed", JsAsset>
  | EventEnvelope<"note", { message: string }>;

export type StateEventType = StateEvent["type"];

/** Drop seq/ts from each union member (the store assigns them) */
type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never;

/** Input passed to appendEvent (seq/ts are added by the store) */
export type StateEventInput = DistributiveOmit<StateEvent, "seq" | "ts">;
