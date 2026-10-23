// Pure selectors over the per-check execution ledger (no IO).
// Pilot (gate) / server (view) / report share the same rollup logic.
//
// Two row kinds share the table:
//   * plan rows     — status "planned", subject "", written when the methodology declares bounded
//                     coverage. A plan row is a SLOT scoped to a concrete (target, param) pair —
//                     never a whole-class blanket, so one execution can't satisfy other inputs.
//   * outcome rows  — written by instrumented tool paths at the concrete (target, param, subject,
//                     session, resource) they actually exercised.

import type { AssessmentState, CheckExecution, CheckStatus } from "./types/index.js";

/** Canonical dedup key for a check row — a JSON array (collision-free, unlike delimiter joins).
 *  Identity = screen × target × param × subject-ref × tenant × origin × session × resource × class:
 *  the same principal under two role aliases collapses (principal wins), two principals under one
 *  role name stay distinct, a re-authed session can't impersonate the old one, and a check on
 *  object A never overwrites the record for object B. */
export function checkKey(
  c: Pick<CheckExecution, "screenId" | "target" | "param" | "subject" | "principal" | "tenant" | "origin" | "session" | "resource" | "checkClass">,
): string {
  const subj = c.principal ? `p:${c.principal}` : `r:${c.subject || ""}`;
  return JSON.stringify([
    c.screenId,
    c.target,
    c.param ?? "",
    subj,
    c.tenant ?? "",
    c.origin ?? "",
    c.session ?? "",
    c.resource ?? "",
    c.checkClass,
  ]);
}

/** A check outcome that ends the check's lifecycle for this run (a reason-backed terminal state). */
export const TERMINAL_CHECK_STATUSES: ReadonlySet<CheckStatus> = new Set([
  "found",
  "suspected",
  "tested-clean",
  "not-applicable",
  "unverified",
  "blocked",
]);

/** Statuses that assert the check RAN and reached a security conclusion (need instrumented evidence). */
export const EXECUTION_CHECK_STATUSES: ReadonlySet<CheckStatus> = new Set(["found", "suspected", "tested-clean"]);

/** Whether outcome row `e` satisfies plan slot `p`. The slot binds (screen, class) plus every concrete
 *  dimension it names — target ("*" = unconstrained), param, subject, principal, tenant, origin,
 *  session, resource. An explicitly bound dimension requires an EXACT match; an execution that leaves
 *  a bound dimension absent can never satisfy it (an unparametrized probe is not evidence about a
 *  named param, and one role's run is not evidence about another). Empty plan dimensions are
 *  intentional bounded wildcards — they never constrain. */
export function planSatisfiedBy(plan: CheckExecution, e: CheckExecution): boolean {
  if (plan.status !== "planned" || e.status === "planned") return false;
  if (plan.screenId !== e.screenId || plan.checkClass !== e.checkClass) return false;
  if (!TERMINAL_CHECK_STATUSES.has(e.status)) return false;
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

/** Check classes that record raw traffic/observations rather than a verdict-bearing check: they
 *  stay listed in the ledger but cover nothing and can never hold a screen "unverified" — an
 *  unattributed fetch has no conclusion to leave hanging. */
export const OBSERVATION_CHECK_CLASSES: ReadonlySet<string> = new Set(["http-request"]);

/** Rollup precedence for a (screen, class) cell: a real hole outranks; gaps stay visible via conclusive. */
const ROLLUP_RANK: Record<CheckStatus, number> = {
  found: 7,
  suspected: 6,
  unverified: 5,
  blocked: 4,
  "tested-clean": 3,
  "not-applicable": 2,
  planned: 1,
  running: 0,
};

export interface ClassRollup {
  screenId: string;
  checkClass: string;
  /** Dominant EXECUTION status (plan rows never claim a class). "planned" when nothing ran. */
  status: CheckStatus;
  /** Outcome rows for this cell (excludes plan slots). */
  checks: CheckExecution[];
  /** Plan slots still waiting for a satisfying execution. */
  unfulfilled: CheckExecution[];
  /** true iff every plan slot is satisfied AND every outcome is terminal AND none is unverified/blocked. */
  conclusive: boolean;
}

/** Fold the ledger into per-(screen,class) cells, pairing plan slots with the executions that satisfy them. */
export function rollupChecks(checks: ReadonlyArray<CheckExecution>): ClassRollup[] {
  const byCell = new Map<string, CheckExecution[]>();
  for (const c of checks) {
    if (OBSERVATION_CHECK_CLASSES.has(c.checkClass)) continue; // unattributed raw requests are listed but cover nothing
    const k = `${c.screenId}${c.checkClass}`;
    const arr = byCell.get(k) ?? [];
    arr.push(c);
    byCell.set(k, arr);
  }
  const out: ClassRollup[] = [];
  for (const list of byCell.values()) {
    const plans = list.filter((c) => c.status === "planned");
    const execs = list.filter((c) => c.status !== "planned");
    const unfulfilled = plans.filter((p) => !execs.some((e) => planSatisfiedBy(p, e)));
    const status = execs.length
      ? execs.reduce((a, b) => (ROLLUP_RANK[b.status] > ROLLUP_RANK[a.status] ? b : a)).status
      : "planned";
    out.push({
      screenId: list[0]!.screenId,
      checkClass: list[0]!.checkClass,
      status,
      checks: execs,
      unfulfilled,
      conclusive:
        unfulfilled.length === 0 &&
        execs.length > 0 &&
        execs.every((e) => TERMINAL_CHECK_STATUSES.has(e.status) && e.status !== "unverified" && e.status !== "blocked"),
    });
  }
  return out;
}

export interface ScreenCheckView {
  screenId: string;
  /** Plan slots with no satisfying execution (screen×class×target×param detail — not just a class name). */
  unstarted: CheckExecution[];
  classes: ClassRollup[];
  /** Outcome rows in a non-conclusive state (unverified / blocked / still running). */
  gaps: CheckExecution[];
  /** The screen predates the check ledger: zero rows at all (a legacy clean screen shows here). */
  legacy: boolean;
}

/** Per-screen check view for the coverage gate / WebUI. */
export function screenChecks(state: Pick<AssessmentState, "checkExecutions">, screenId: string): ScreenCheckView {
  const mine = state.checkExecutions.filter((c) => c.screenId === screenId);
  const classes = rollupChecks(mine);
  const unstarted = classes.flatMap((c) => c.unfulfilled);
  const gaps = mine.filter((c) => (c.status === "unverified" || c.status === "blocked" || c.status === "running") && !OBSERVATION_CHECK_CLASSES.has(c.checkClass));
  // "legacy" = no VERDICT-BEARING rows: a conclusive status backed only by raw traffic observations is
  // a claim, not tested evidence — same substance as zero rows.
  return { screenId, unstarted, classes, gaps, legacy: !mine.some((c) => !OBSERVATION_CHECK_CLASSES.has(c.checkClass)) };
}
