import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { checkKey, planSatisfiedBy, rollupChecks, screenChecks } from "./checks.js";
import { deriveScopeFromSingleUrl } from "./factories.js";
import { AssessmentStore } from "./store.js";
import type { CheckExecution } from "./types/index.js";

const at = (second: number) => new Date(Date.UTC(2025, 0, 1, 0, 0, second)).toISOString();

function check(overrides: Partial<CheckExecution> = {}): CheckExecution {
  const row: CheckExecution = {
    id: "",
    screenId: "s-1",
    target: "GET /orders/{id}",
    param: "id",
    resource: "order-1",
    subject: "reader",
    principal: "principal-1",
    tenant: "tenant-1",
    origin: "https://example.test",
    session: "session-1",
    checkClass: "idor",
    status: "unverified",
    tool: "probe_authz",
    evidenceIds: [],
    findingIds: [],
    finishedAt: at(1),
    updatedAt: at(1),
    ...overrides,
  };
  row.id = checkKey(row);
  return row;
}

const view = (...rows: CheckExecution[]) => screenChecks({ checkExecutions: rows }, "s-1");
const retry = (overrides: Partial<CheckExecution> = {}) =>
  check({ session: "session-2", subject: "reader-alias", status: "tested-clean", evidenceIds: ["ev-retry"], startedAt: at(2), finishedAt: at(3), updatedAt: at(3), ...overrides });

test("a later evidenced retry under the established principal resolves the current gap but retains the failed attempt", () => {
  const failure = check({ status: "blocked", reason: "expired session" });
  const success = retry(); // Different role alias and session, same established principal and resource.
  const plan = check({ status: "planned", subject: "", principal: undefined, session: undefined, resource: undefined });
  const before = view(plan, failure);
  assert.deepEqual(before.gaps, [failure]);
  assert.deepEqual(before.unstarted, [plan], "a failed tool attempt cannot satisfy the plan");

  for (const rows of [[plan, failure, success], [success, plan, failure]]) {
    const result = view(...rows);
    assert.deepEqual(result.gaps, []);
    assert.deepEqual(result.unstarted, [], "the real execution satisfies the wildcard subject/session plan");
    assert.equal(result.classes[0]!.status, "tested-clean");
    assert.equal(result.classes[0]!.conclusive, true);
    assert.equal(result.classes[0]!.checks.length, 2, "the old failed attempt stays in the audit ledger");
  }
  assert.equal(failure.status, "blocked");
  assert.deepEqual(failure.evidenceIds, []);
  assert.equal(planSatisfiedBy(plan, failure), false, "raw failed attempts remain unable to satisfy slots");
  assert.equal(planSatisfiedBy(plan, success), true);
});

test("same-session upserts dedup, while rotated sessions and the append-only events remain auditable after reload", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-checks-"));
  const path = join(dir, "state.sqlite");
  try {
    const store = AssessmentStore.open(path);
    const { id } = store.createAssessment({
      target: { kind: "single_url", url: "https://example.test/", followLinks: true, maxDepth: 1 },
      scope: deriveScopeFromSingleUrl("https://example.test/"),
    });
    const failed = check();
    const sameSession = retry({ session: "session-1", subject: "reader" });
    const rotatedFailure = check({ session: "session-2", finishedAt: at(4) });
    const laterSuccess = retry({ session: "session-3", startedAt: at(5), finishedAt: at(6) });
    store.upsertCheck(id, failed);
    store.upsertCheck(id, sameSession);
    assert.equal(store.checks(id).length, 1);
    store.upsertCheck(id, rotatedFailure);
    store.upsertCheck(id, laterSuccess);
    store.close();

    const reopened = AssessmentStore.open(path);
    try {
      const state = reopened.loadAssessment(id)!;
      assert.deepEqual(state.events.filter((e) => e.type === "check_recorded").map((e) => e.payload.check.status),
        ["unverified", "tested-clean", "unverified", "tested-clean"]);
      assert.equal(state.checkExecutions.length, 3, "both rotated-session rows remain stored");
      assert.ok(state.checkExecutions.some((c) => c.id === rotatedFailure.id && c.status === "unverified"));
      assert.deepEqual(screenChecks(state, "s-1").gaps, []);
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a different principal, object, tenant, origin, target, input, class or screen cannot supersede a failure", () => {
  const failure = check();
  const cases: Array<[string, Partial<CheckExecution>]> = [
    ["principal", { principal: "principal-2" }],
    ["resource", { resource: "order-2" }],
    ["missing resource", { resource: undefined }],
    ["tenant", { tenant: "tenant-2" }],
    ["missing tenant", { tenant: undefined }],
    ["origin", { origin: "https://other.test" }],
    ["target", { target: "GET /other/{id}" }],
    ["param", { param: "other" }],
    ["class", { checkClass: "idor-write" }],
    ["screen", { screenId: "s-2" }],
  ];
  for (const [dimension, change] of cases) {
    const result = view(failure, retry(change));
    assert.deepEqual(result.gaps, [failure], dimension);
    assert.equal(result.classes.find((c) => c.checkClass === "idor")!.status, "unverified", dimension);
  }
});

test("role labels alone do not identify a rotated session; unauth is safe only with the identical session", () => {
  const unknown = check({ principal: undefined });
  assert.deepEqual(view(unknown, retry({ principal: undefined, subject: "reader" })).gaps, [unknown]);
  assert.deepEqual(view(unknown, retry()).gaps, [unknown], "one-sided verified identity is not a match");
  const publicFailure = check({ principal: undefined, subject: "unauth" });
  assert.deepEqual(view(publicFailure, retry({ principal: undefined, subject: "unauth" })).gaps, [publicFailure]);
  assert.deepEqual(view(publicFailure, retry({ principal: undefined, subject: "unauth", session: "session-1" })).gaps, []);
  assert.deepEqual(view(check({ principal: undefined, subject: "" }), retry({ principal: undefined, subject: "" })).gaps.length, 1);
  // The same claimed actor under byte-identical session material IS the same wire identity even for a
  // named role — a retry on that session supersedes; a DIFFERENT subject label on the same material never does.
  assert.deepEqual(view(unknown, retry({ principal: undefined, subject: "reader", session: "session-1" })).gaps, []);
  assert.deepEqual(view(unknown, retry({ principal: undefined, subject: "admin", session: "session-1" })).gaps, [unknown]);
});

test("an earlier clean does not hide a later failure, even when plan coverage was satisfied", () => {
  const clean = retry({ finishedAt: at(1), updatedAt: at(9) });
  const failedLater = check({ session: "session-3", finishedAt: at(5), updatedAt: at(2) });
  const plan = check({ status: "planned", subject: "", principal: undefined, session: undefined, resource: undefined });
  const result = view(failedLater, plan, clean); // Neither array nor updatedAt order determines recency.
  assert.deepEqual(result.gaps, [failedLater]);
  assert.equal(result.classes[0]!.status, "unverified");
  assert.equal(result.classes[0]!.conclusive, false);
  assert.deepEqual(result.unstarted, [], "plan coverage does not erase a newer gap");
});

test("only a post-gap invocation supersedes across sessions; old retries and overlapping work leave the gap", () => {
  const failure = check();
  const cases: Array<[CheckExecution, CheckExecution]> = [
    [check({ finishedAt: undefined }), retry()],
    [failure, retry({ startedAt: undefined, finishedAt: at(9) })],
    [failure, retry({ startedAt: "not a timestamp", finishedAt: at(9) })],
    [failure, retry({ finishedAt: undefined })],
    [failure, retry({ finishedAt: "not a timestamp" })],
    [failure, retry({ finishedAt: at(1) })],
    [failure, retry({ finishedAt: at(0), updatedAt: at(9) })],
    [failure, retry({ startedAt: at(0), finishedAt: at(3) })], // overlaps failure, finishes later
    [failure, retry({ startedAt: at(1), finishedAt: at(3) })], // a tie is not strictly later
    [failure, retry({ startedAt: at(4), finishedAt: at(3) })],
  ];
  for (const [failed, success] of cases) {
    assert.deepEqual(view(success, failed).gaps, [failed]);
  }
  assert.deepEqual(view(failure, retry({ startedAt: at(2) })).gaps, []);
  // Even a pre-instrumentation failed row can be retried if its finish is known.
  assert.deepEqual(view(check({ startedAt: undefined }), retry()).gaps, []);
  const inFlight = check({ status: "running" });
  assert.deepEqual(view(inFlight, retry()).gaps, [inFlight], "another caller's clean cannot complete running work");
});

test("a declared, unproven or unrelated outcome cannot erase a failed attempt", () => {
  const failure = check();
  const inconclusive: Partial<CheckExecution>[] = [
    { evidenceIds: [] },
    { evidenceIds: [""], baselineOk: true },
    { baselineOk: false },
    { tool: "screen_done" },
    { tool: "http_request" },
    { status: "not-applicable" },
    { status: "running" },
    { target: "*" },
  ];
  for (const outcome of inconclusive) {
    const result = view(failure, retry(outcome));
    assert.ok(result.gaps.includes(failure), JSON.stringify(outcome));
    assert.equal(result.classes[0]!.status, "unverified");
  }
  // Two IDOR attempts without object identity cannot prove that the same object was exercised.
  const noObject = check({ resource: undefined });
  assert.deepEqual(view(noObject, retry({ resource: undefined })).gaps, [noObject]);
  const inputScoped = check({ resource: undefined, checkClass: "sqli" });
  assert.deepEqual(view(inputScoped, retry({ resource: undefined, checkClass: "sqli" })).gaps, []);
  const wildcardFailure = check({ target: "*" });
  assert.deepEqual(view(wildcardFailure, retry({ target: "*" })).gaps, [wildcardFailure]);
});

test("evidenced found/suspected retries resolve a failed attempt without claiming tested-clean", () => {
  for (const status of ["found", "suspected"] as const) {
    const failure = check();
    const result = view(failure, retry({ status }));
    assert.deepEqual(result.gaps, []);
    assert.equal(result.classes[0]!.status, status);
    assert.equal(result.classes[0]!.conclusive, true);
  }
});

test("only a matching conclusive execution closes a plan slot; session-bound plans remain strict", () => {
  const plan = check({ status: "planned", subject: "", principal: undefined, resource: undefined, session: "session-1" });
  const failure = check();
  const success = retry();
  assert.equal(planSatisfiedBy(plan, failure), false);
  assert.equal(planSatisfiedBy(plan, success), false, "a different session cannot satisfy a session-bound plan");
  const result = view(plan, failure, success);
  assert.deepEqual(result.gaps, [], "the logical retry resolved the failed attempt");
  assert.deepEqual(result.unstarted, [plan], "supersession must not weaken planSatisfiedBy");
  assert.equal(result.classes[0]!.conclusive, false);

  const wildcard = check({ status: "planned", target: "*", subject: "", principal: undefined, resource: undefined, session: undefined });
  assert.equal(planSatisfiedBy(wildcard, success), true);
  const otherInput = check({ ...wildcard, param: "other" });
  assert.equal(planSatisfiedBy(otherInput, success), false);
  const otherResource = check({ ...wildcard, resource: "order-2" });
  assert.equal(planSatisfiedBy(otherResource, success), false);
  assert.deepEqual(view(otherResource, success).unstarted, [otherResource]);
  assert.equal(planSatisfiedBy(wildcard, retry({ status: "unverified", tool: "probe_authz" })), false);
  assert.equal(planSatisfiedBy(wildcard, retry({ status: "unverified", tool: "screen_done" })), true, "declared gaps still satisfy coverage, without becoming a clean check");
});

test("same-session dedup stays keyed to the current outcome; raw HTTP observations stay out of rollups and gaps", () => {
  const failure = check();
  const sameSession = retry({ session: "session-1", subject: "reader" });
  assert.equal(failure.id, sameSession.id, "status is not part of the store's dedup key");
  assert.deepEqual(view(sameSession).gaps, [], "a same-key upsert projects the current row");
  const raw = check({ checkClass: "http-request", status: "blocked", tool: "http_request" });
  const result = view(failure, raw);
  assert.deepEqual(result.gaps, [failure]);
  assert.deepEqual(result.classes[0]!.checks, [failure]);
  assert.equal(rollupChecks([raw]).length, 0);
  assert.equal(view(raw).legacy, true);
});

test("parameter discovery is an observation, not an inconclusive security check", () => {
  const recon = check({ checkClass: "recon", status: "unverified", tool: "probe_params" });
  const result = view(recon);
  assert.equal(result.legacy, true);
  assert.deepEqual(result.gaps, []);
  assert.deepEqual(result.unstarted, []);
  assert.deepEqual(result.classes, []);
});

test("a later probe resolves only the matching declared input gap, not another slot", () => {
  const gap = check({
    target: "*", param: "q", resource: undefined, checkClass: "sqli",
    status: "unverified", tool: "screen_done", evidenceIds: [],
  });
  const plan = check({
    target: "*", param: "q", resource: undefined, checkClass: "sqli",
    subject: "", principal: undefined, status: "planned", tool: "methodology",
  });
  const success = retry({
    target: "GET /search", param: "q", resource: undefined, checkClass: "sqli",
    startedAt: at(2),
  });
  assert.deepEqual(view(plan, gap, success).gaps, []);
  assert.equal(view(plan, gap, success).classes[0]!.status, "tested-clean");
  assert.deepEqual(view(gap, retry({ ...success, param: "id" })).gaps, [gap]);
  assert.deepEqual(view(gap, retry({ ...success, principal: "other" })).gaps, [gap]);
  assert.deepEqual(view(gap, retry({ ...success, startedAt: at(0) })).gaps, [gap]);
  const unscoped = check({ ...gap, param: undefined });
  assert.deepEqual(view(unscoped, success).gaps, [unscoped]);
});

test("rollup cell keys cannot collide across distinct screen and class pairs", () => {
  const a = check({ screenId: "ab", checkClass: "c" });
  const b = check({ screenId: "a", checkClass: "bc", status: "tested-clean", evidenceIds: ["ev-b"] });
  assert.equal(rollupChecks([a, b]).length, 2);
});
