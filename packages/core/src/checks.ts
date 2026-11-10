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
 *  intentional bounded wildcards — they never constrain.
 *
 *  A tool-emitted `unverified`/`blocked` row records that the check could NOT conclude — it is an
 *  observation of a failed attempt, not a decision about the slot. It stays visible as a gap but does
 *  NOT satisfy the slot: the diagnosis loop must either remediate (fix the session/baseline/stability
 *  and re-run) or declare the gap with a concrete reason (a `screen_done` coverage row). Only the
 *  declared row closes the slot — "couldn't run" can never silently masquerade as "dealt with". */
export function planSatisfiedBy(plan: CheckExecution, e: CheckExecution): boolean {
  if (plan.status !== "planned" || e.status === "planned") return false;
  if (plan.screenId !== e.screenId || plan.checkClass !== e.checkClass) return false;
  if (!TERMINAL_CHECK_STATUSES.has(e.status)) return false;
  if ((e.status === "unverified" || e.status === "blocked") && e.tool !== "screen_done") return false;
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

/** Raw traffic and parameter discovery are observations, not verdict-bearing checks. They
 * remain in the audit ledger but cannot prove a screen clean or leave a security-check gap. */
export const OBSERVATION_CHECK_CLASSES: ReadonlySet<string> = new Set(["http-request", "recon"]);

/** A failed attempt can be omitted from the *current* verdict only when a later, evidenced
 *  execution actually rechecks the same thing. The ledger rows themselves remain untouched.
 *  Role labels cannot establish identity across sessions; even "unauth" is only safe within
 *  the same session material, since a changed cookie may carry a different account. */
function supersedesGap(gap: CheckExecution, retry: CheckExecution): boolean {
  // A running row is still in flight, not a completed failed attempt; another caller's
  // success cannot establish that this concurrent work has finished.
  if (gap.status !== "unverified" && gap.status !== "blocked") return false;
  if (!EXECUTION_CHECK_STATUSES.has(retry.status)) return false;
  if (!retry.tool || ["screen_done", "http_request", "methodology", "plan-floor"].includes(retry.tool)) return false;
  if (!retry.evidenceIds?.some((id) => typeof id === "string" && id.trim().length > 0)) return false;
  // Instrumented checks such as probe_authz record their execution evidence without a baselineOk
  // field; an explicitly invalid baseline, however, can never support a clean retry.
  if (retry.baselineOk === false) return false;

  // A declared input gap uses the plan's wildcard target. A later concrete probe of that
  // same input can resolve it; never generalize an object or screen-level wildcard.
  const declaredInput = gap.tool === "screen_done" && gap.target === "*" && !!gap.param &&
    !gap.resource && !retry.resource && gap.checkClass !== "idor" && gap.checkClass !== "idor-write" &&
    retry.target !== "*";
  if ((gap.target === "*" && !declaredInput) ||
      gap.screenId !== retry.screenId || gap.checkClass !== retry.checkClass ||
      (!declaredInput && gap.target !== retry.target) || (gap.param ?? "") !== (retry.param ?? "") ||
      (gap.resource ?? "") !== (retry.resource ?? "") ||
      (gap.tenant ?? "") !== (retry.tenant ?? "") ||
      (gap.origin ?? "") !== (retry.origin ?? "")) return false;
  // IDOR checks are object-scoped: two requests for the same endpoint/param can still
  // address different objects. Without an object key we cannot prove supersession.
  if ((gap.checkClass === "idor" || gap.checkClass === "idor-write") && !gap.resource) return false;
  if (gap.principal && retry.principal) {
    if (gap.principal !== retry.principal) return false;
  } else if (!gap.principal && !retry.principal &&
             gap.subject === retry.subject && !!gap.session && gap.session === retry.session) {
    // No verified principal either side, but the SAME claimed actor under BYTE-IDENTICAL session
    // material is the same wire identity — the session ref is the identity, not the role label.
    // Different subject labels can never match here even when material coincides (a claimed actor
    // difference is unprovable relabeling).
  } else {
    return false; // Unknown principal, or only one attempt has established identity.
  }

  // Store reads are ordered by row creation (and upserts can change updatedAt). A
  // later finish is not a later retry: two concurrent calls can finish in either
  // order. Old rows without invocation starts cannot supersede another session's
  // gap; a real retry must start strictly after the failed attempt finished.
  if (!gap.finishedAt || !retry.startedAt || !retry.finishedAt) return false;
  const gapEnd = Date.parse(gap.finishedAt);
  const retryStart = Date.parse(retry.startedAt);
  const retryEnd = Date.parse(retry.finishedAt);
  return Number.isFinite(gapEnd) && Number.isFinite(retryStart) && Number.isFinite(retryEnd) &&
    retryStart > gapEnd && retryStart <= retryEnd;
}

function currentOutcomes(execs: CheckExecution[]): CheckExecution[] {
  const retries = execs.filter((c) => EXECUTION_CHECK_STATUSES.has(c.status));
  return execs.filter((c) =>
    (c.status !== "unverified" && c.status !== "blocked" && c.status !== "running") ||
    !retries.some((later) => supersedesGap(c, later)));
}

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
  /** Dominant current EXECUTION status (plan rows never claim a class). "planned" when nothing ran. */
  status: CheckStatus;
  /** All outcome rows for this cell, including superseded attempts, for audit. */
  checks: CheckExecution[];
  /** Plan slots still waiting for a satisfying execution. */
  unfulfilled: CheckExecution[];
  /** true iff every plan slot is satisfied AND every current outcome is terminal and conclusive. */
  conclusive: boolean;
}

/** Fold the ledger into per-(screen,class) cells, pairing plan slots with the executions that satisfy them. */
export function rollupChecks(checks: ReadonlyArray<CheckExecution>): ClassRollup[] {
  const byCell = new Map<string, CheckExecution[]>();
  for (const c of checks) {
    if (OBSERVATION_CHECK_CLASSES.has(c.checkClass)) continue; // unattributed raw requests are listed but cover nothing
    const k = JSON.stringify([c.screenId, c.checkClass]);
    const arr = byCell.get(k) ?? [];
    arr.push(c);
    byCell.set(k, arr);
  }
  const out: ClassRollup[] = [];
  for (const list of byCell.values()) {
    const plans = list.filter((c) => c.status === "planned");
    const execs = list.filter((c) => c.status !== "planned");
    const unfulfilled = plans.filter((p) => !execs.some((e) => planSatisfiedBy(p, e)));
    const current = currentOutcomes(execs);
    const status = current.length
      ? current.reduce((a, b) => (ROLLUP_RANK[b.status] > ROLLUP_RANK[a.status] ? b : a)).status
      : "planned";
    out.push({
      screenId: list[0]!.screenId,
      checkClass: list[0]!.checkClass,
      status,
      checks: execs,
      unfulfilled,
      conclusive:
        unfulfilled.length === 0 &&
        current.length > 0 &&
        current.every((e) => TERMINAL_CHECK_STATUSES.has(e.status) && e.status !== "unverified" && e.status !== "blocked"),
    });
  }
  return out;
}

export interface ScreenCheckView {
  screenId: string;
  /** Plan slots with no satisfying execution (screen×class×target×param detail — not just a class name). */
  unstarted: CheckExecution[];
  classes: ClassRollup[];
  /** Current outcomes in a non-conclusive state (superseded attempts remain in classes[].checks). */
  gaps: CheckExecution[];
  /** The screen predates the check ledger: zero rows at all (a legacy clean screen shows here). */
  legacy: boolean;
}

/** Per-screen check view for the coverage gate / WebUI. */
export function screenChecks(state: Pick<AssessmentState, "checkExecutions">, screenId: string): ScreenCheckView {
  const mine = state.checkExecutions.filter((c) => c.screenId === screenId);
  const classes = rollupChecks(mine);
  const unstarted = classes.flatMap((c) => c.unfulfilled);
  const gaps = currentOutcomes(mine.filter((c) => !OBSERVATION_CHECK_CLASSES.has(c.checkClass)))
    .filter((c) => c.status === "unverified" || c.status === "blocked" || c.status === "running");
  // "legacy" = no VERDICT-BEARING rows: a conclusive status backed only by raw traffic observations is
  // a claim, not tested evidence — same substance as zero rows.
  return { screenId, unstarted, classes, gaps, legacy: !mine.some((c) => !OBSERVATION_CHECK_CLASSES.has(c.checkClass)) };
}
