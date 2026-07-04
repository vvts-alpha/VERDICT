// DESIGN §4.4 / §7.1 / §8.2 — the Phase2 coverage ledger.
//
// A Screen (the §6.6 Phase1 contract = screen_inventory.json) is an immutable artifact, so don't taint it.
// Scan state is kept as a separate per-screen record (ScreenScan), structurally guaranteeing that
// "every discovered screen is scanned to completion, none missed".

export type ScreenScanStatus =
  | "queued" // discovered, not yet scanned (right after auto-enrollment)
  | "scanning" // being processed by a sub-agent
  | "clean" // scanned, no findings (terminal)
  | "finding" // scanned, confirmed findings present (terminal)
  | "suspected" // scanned, only suspected leads (no confirmed). Diagnosis is done = terminal, awaiting manual verification
  | "blocked" // can't proceed, waiting on auth/scope/handoff (non-terminal)
  | "excluded" // excluded from scanning by a human (terminal)
  | "error"; // failed; can be retried while retry budget remains

export interface ScreenScan {
  screenId: string;
  status: ScreenScanStatus;
  /** Cumulative attempt count from errors */
  attempts: number;
  hypothesisIds: string[];
  findingIds: string[];
  lastError: string | null;
  /** ISO-8601 */
  updatedAt: string;
}

/** Derived view of coverage(). Read by the WebUI badge (§8.2) and the stop condition (§4.4①). */
export interface Coverage {
  total: number;
  byStatus: Record<ScreenScanStatus, number>;
  /** clean + finding + suspected + excluded */
  terminal: number;
  /** total - terminal (sum of queued / scanning / error / blocked) */
  remaining: number;
  /** Number of screens workable now (queued + error with retry budget left). Excludes blocked / scanning */
  scannable: number;
  /** total > 0 and remaining === 0 → coverage_complete (§4.4①) */
  complete: boolean;
}
