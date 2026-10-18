import type { CheckExecution, ScreenScanStatus, StateView } from "@veritas/core";

// Honest per-screen display status. The scan-status word is a CLAIM — it only headlines as
// tested/clean when the structured check ledger (or an actual finding) backs it. Two corrections
// keep summary/tree/detail consistent with the ledger:
//   - "unknown-records": a conclusive claim (clean/finding/suspected) with ZERO ledger rows and no
//     backing finding — legacy or log-note provenance; truth unknown, shown neutral not green.
//   - "unverified" (demoted): a "clean" claim whose ledger still holds inconclusive outcome rows
//     (unverified/blocked/running) or planned slots no terminal execution satisfied — never clean.

export type EffectiveStatus = ScreenScanStatus | "unknown-records";

export interface ScreenHonesty {
  /** The status the UI should headline. */
  status: EffectiveStatus;
  /** The scan status as recorded. */
  raw: ScreenScanStatus;
  /** Conclusive claim with no ledger rows (and no finding to back it). */
  legacy: boolean;
  /** Terminal-but-inconclusive execution rows (unverified / blocked / running). */
  gaps: number;
  /** Planned rows no matching terminal execution satisfied. */
  unfulfilled: number;
}

// Mirrors core TERMINAL_CHECK_STATUSES / planSatisfiedBy — webui stays types-only on core, so the
// rollup is ported faithfully: a plan slot is satisfied ONLY by a terminal execution matching every
// explicitly bound dimension (target/param/subject/principal/tenant/origin/session/resource).
const TERMINAL: ReadonlySet<string> = new Set(["found", "suspected", "tested-clean", "not-applicable", "unverified", "blocked"]);
export function planSatisfied(plan: CheckExecution, e: CheckExecution): boolean {
  if (e.status === "planned" || !TERMINAL.has(e.status)) return false;
  if (plan.screenId !== e.screenId || plan.checkClass !== e.checkClass) return false;
  if (plan.target !== "*" && plan.target !== e.target) return false;
  if (plan.param && plan.param !== e.param) return false;
  if (plan.subject && plan.subject !== e.subject) return false;
  if (plan.principal && plan.principal !== e.principal) return false;
  if (plan.tenant && plan.tenant !== e.tenant) return false;
  if (plan.origin && plan.origin !== e.origin) return false;
  if (plan.session && plan.session !== e.session) return false;
  if (plan.resource && plan.resource !== e.resource) return false;
  return true;
}

/** screenId → honesty record for every scanned screen. Single pass over the ledger — callers use
 *  this for badges/counts instead of re-deriving per render. Screens absent from `screenScans`
 *  (e.g. rows without a scan-status entry) simply get no map entry — callers keep their raw status. */
export function screenHonestyMap(view: StateView): Map<string, ScreenHonesty> {
  const rowsByScreen = new Map<string, CheckExecution[]>();
  for (const c of view.checkExecutions) {
    const arr = rowsByScreen.get(c.screenId) ?? [];
    arr.push(c);
    rowsByScreen.set(c.screenId, arr);
  }
  const findingScreens = new Set(view.findings.map((f) => f.screenId).filter((x): x is string => Boolean(x)));
  const out = new Map<string, ScreenHonesty>();
  for (const s of view.screenScans) {
    const rows = rowsByScreen.get(s.screenId) ?? [];
    const plans = rows.filter((r) => r.status === "planned");
    const execs = rows.filter((r) => r.status !== "planned");
    const unfulfilled = plans.filter((p) => !execs.some((e) => planSatisfied(p, e))).length;
    const gaps = execs.filter((e) => e.status === "unverified" || e.status === "blocked" || e.status === "running").length;
    const conclusive = s.status === "clean" || s.status === "finding" || s.status === "suspected";
    const legacy = conclusive && rows.length === 0 && (s.status === "clean" || !findingScreens.has(s.screenId));
    let status: EffectiveStatus = s.status;
    if (legacy) status = "unknown-records";
    else if (s.status === "clean" && (gaps > 0 || unfulfilled > 0)) status = "unverified";
    out.set(s.screenId, { status, raw: s.status, legacy, gaps, unfulfilled });
  }
  return out;
}
