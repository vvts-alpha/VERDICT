// Per-check execution ledger (the coverage record).
//
// Every row is ONE bounded check execution, keyed by
// (assessment, screen, target, param, subject-ref, checkClass) — where the
// subject-ref resolves principal > tenant > origin > role label, so same-role
// different-principal or cross-tenant checks never collapse into each other.
// "target" is the
// method+endpoint ("GET /orders/{id}") or a GraphQL operation identity
// ("POST /graphql#name:Op:hash"); "param" is the parameter/JSON pointer when
// the check addresses a specific input. Rows are written by instrumented tool
// paths (probes, record_finding, methodology planning) — never by raw model
// self-report alone — so "tested-clean" always traces to a real execution.
//
// A "planned" row marks bounded intended coverage (from the per-screen plan);
// it is satisfied by a terminal row for the same (screen, checkClass) — this is
// planned coverage of the screen's real surface, NOT a brute-force sweep over
// every param×role×class combination.

export type CheckStatus =
  | "planned" // declared by the methodology plan; nothing ran yet
  | "running" // an instrumented tool picked it up (in-flight)
  | "found" // a confirmed finding / proven exploit exists for this check
  | "suspected" // a suspected finding / real observed anomaly recorded
  | "tested-clean" // the check ran to a conclusive negative result
  | "not-applicable" // the class genuinely does not apply (NOT "couldn't run")
  | "unverified" // it ran but reached no conclusion (bad baseline, partial read, unknown ownership…)
  | "blocked"; // cannot run this session: missing auth/CSRF/OOB/scope — concrete reason required

export interface CheckExecution {
  /** Deterministic dedup key — see checkKey() in core/checks.ts. */
  id: string;
  screenId: string;
  /** The surface under test: "GET /orders/{id}", "POST /graphql#name:GetOrder:abc", or "*" (screen-level claim). */
  target: string;
  /** Parameter / JSON pointer / variable path the check targeted, when applicable. */
  param?: string;
  /** The concrete resource this check exercised when it is object-scoped (an object id or AuthzObject.key) —
   *  part of the row key so a test against object A never overwrites/clears a test against object B. */
  resource?: string;
  /** Subject LABEL the check ran as — a configured role name, or "unauth"/"" (unspecified, plan rows).
   *  A role name alone does NOT identify a principal (two role aliases may share one principal; a role's
   *  session may rotate to a different account). */
  subject: string;
  /** Established principal for the subject when known (operator-declared or session-verified identity).
   *  Included in the row key so two principals sharing a role name do not collapse, and a re-authed role
   *  does not masquerade as its predecessor. */
  principal?: string;
  /** Subject's tenant context when established (operator-declared). Part of the row key. */
  tenant?: string;
  /** Web origin (https://host:port) the request was sent to. Part of the row key — the same path on
   *  another origin is a different check. */
  origin?: string;
  /** Opaque reference to the session material actually used (e.g. a digest of the resolved auth headers).
   *  Part of the row key — a re-login under different material is a different check context, and the same
   *  cookie file carrying a switched account cannot pass as the previous subject. */
  session?: string;
  /** Coarse check class (idor, sqli, xss-reflected, …) or "http-request" for an unattributed raw request. */
  checkClass: string;
  status: CheckStatus;
  /** Concrete reason — REQUIRED for unverified/blocked/not-applicable so the gap is auditable. */
  reason?: string;
  /** Tool that produced this outcome (probe_xss, probe_authz, record_finding, screen_done, …). */
  tool?: string;
  /** Whether a valid baseline was established for the attempt (baseline is necessary but NOT sufficient for clean). */
  baselineOk?: boolean;
  /** Evidence ids (ev-…) this outcome rests on — real ids from the evidence store, never caller-invented. */
  evidenceIds: string[];
  /** Finding ids this check produced. */
  findingIds: string[];
  /** Opaque back-reference for audit (e.g. an AuthzComparison id) — machine detail beyond `reason`. */
  detail?: string;
  /** ISO-8601 */
  startedAt?: string;
  finishedAt?: string;
  updatedAt: string;
}
