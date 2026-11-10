import { test } from "node:test";
import assert from "node:assert/strict";

import { buildReportModel } from "./report-model.js";
import { defaultBudget, deriveScopeFromSingleUrl } from "./factories.js";
import type { AssessmentState, CheckExecution, CheckStatus } from "./types/index.js";

const at = (second: number) => new Date(Date.UTC(2025, 0, 1, 0, 0, second)).toISOString();

function check(id: string, status: CheckStatus, overrides: Partial<CheckExecution> = {}): CheckExecution {
  return {
    id, screenId: "s-1", target: "GET /orders/{id}", param: "id", resource: "order-1",
    subject: "reader", principal: "account-a", tenant: "tenant-1", origin: "https://shop.test",
    session: "session-old", checkClass: "idor", status, tool: "probe_authz",
    evidenceIds: [], findingIds: [], updatedAt: at(1),
    ...overrides,
  };
}

function state(checkExecutions: CheckExecution[]): AssessmentState {
  return {
    id: "a-1",
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 1 },
    phase: "report",
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
    budget: defaultBudget(new Date(at(0))),
    screens: [{
      screenId: "s-1", urlTemplate: "/orders/{id}", observedUrls: ["https://shop.test/orders/1"],
      authState: "post-login", screenType: "detail", description: "", params: [], apis: [],
      screenshot: "", domSkeletonHash: "orders", labels: [],
    }],
    screenScans: [{
      screenId: "s-1", status: "unverified", attempts: 0, hypothesisIds: [], findingIds: [],
      lastError: null, updatedAt: at(0),
    }],
    hypotheses: [], findings: [], handoffs: [], checkExecutions,
    authzObjects: [], authzComparisons: [], events: [],
  };
}

const plan = () => check("plan", "planned", {
  subject: "", session: "session-old", tool: "methodology",
});
const failed = () => check("failed", "unverified", {
  reason: "baseline unstable", finishedAt: at(1),
});
const retried = () => check("retry", "tested-clean", {
  subject: "reader-alias", session: "session-new", tool: "probe_authz",
  evidenceIds: ["ev-retry"], baselineOk: true, startedAt: at(2), finishedAt: at(3),
});
const rawBlocked = () => check("raw-blocked", "blocked", {
  checkClass: "http-request", tool: "http_request", reason: "raw request could not complete",
});
const rawRunning = () => check("raw-running", "running", {
  checkClass: "http-request", tool: "http_request",
});

test("report current gaps exclude a resolved attempt across sessions but preserve historical audit rows", () => {
  const rows = [plan(), failed(), rawBlocked(), rawRunning()];
  const before = buildReportModel(state(rows), new Date(at(4)));
  assert.equal(before.stats.checks.gaps, 1, "raw HTTP observations are never check gaps");
  assert.equal(before.stats.checks.unfulfilledPlans, 1, "a failed probe does not satisfy its plan");

  const after = buildReportModel(state([rows[0]!, rows[1]!, retried(), ...rows.slice(2)]), new Date(at(4)));
  assert.equal(after.stats.checks.gaps, 0, "same verified principal/resource retry resolves the old gap");
  assert.equal(after.stats.checks.unfulfilledPlans, 1, "the original session-bound plan stays unfulfilled");
  assert.equal(after.stats.checks.total, 5);
  assert.deepEqual(after.stats.checks.byStatus, {
    planned: 1, running: 1, found: 0, suspected: 0, "tested-clean": 1,
    "not-applicable": 0, unverified: 1, blocked: 1,
  });
  assert.deepEqual(after.checks.map((c) => c.status), [
    "planned", "unverified", "tested-clean", "blocked", "running",
  ], "report checks[] keeps the superseded failure and raw observations");
  assert.equal(after.checks[1]!.reason, "baseline unstable");
  assert.equal(after.checks[2]!.evidence[0]!.path, "artifacts/s-1/ev-retry/");
});

test("a retry never hides the gap of another resource or principal", () => {
  const base = [plan(), failed(), retried(), rawBlocked()];
  for (const [dimension, overrides] of [
    ["resource", { resource: "order-2" }],
    ["principal", { principal: "account-b" }],
  ] as const) {
    const other = check(`other-${dimension}`, "blocked", {
      ...overrides, reason: `not authorized for other ${dimension}`, finishedAt: at(1),
    });
    const report = buildReportModel(state([...base, other]), new Date(at(4)));
    assert.equal(report.stats.checks.gaps, 1, `${dimension} gap is still unresolved`);
    assert.equal(report.stats.checks.unfulfilledPlans, 1, "plan fulfillment remains independent of gaps");
    assert.equal(report.stats.checks.byStatus.unverified, 1, "the resolved attempt stays in history");
    assert.equal(report.stats.checks.byStatus.blocked, 2, "the raw HTTP attempt also stays in history");
    assert.deepEqual(report.checks.filter((c) => c.status === "blocked").map((c) => c.checkClass),
      ["http-request", "idor"]);
  }
});

test("blocked attempts can resolve, but an in-flight check remains a gap", () => {
  const blocked = check("old-blocked", "blocked", {
    reason: "session expired", finishedAt: at(1),
  });
  const resolved = buildReportModel(state([blocked, retried()]), new Date(at(4)));
  assert.equal(resolved.stats.checks.gaps, 0);
  assert.equal(resolved.stats.checks.byStatus.blocked, 1);
  assert.deepEqual(resolved.checks.map((c) => c.status), ["blocked", "tested-clean"]);

  const inFlight = check("still-running", "running", { session: "session-third" });
  const concurrent = buildReportModel(state([blocked, retried(), inFlight]), new Date(at(4)));
  assert.equal(concurrent.stats.checks.gaps, 1, "success never finishes a separate running attempt");
  assert.equal(concurrent.stats.checks.byStatus.running, 1);
});

test("an unbound plan is satisfied by the conclusive retry independently of historical gaps", () => {
  const wildcardPlan = plan();
  wildcardPlan.session = undefined;
  const before = buildReportModel(state([wildcardPlan, failed()]), new Date(at(4)));
  const after = buildReportModel(state([wildcardPlan, failed(), retried()]), new Date(at(4)));
  assert.equal(before.stats.checks.unfulfilledPlans, 1);
  assert.equal(after.stats.checks.unfulfilledPlans, 0);
  assert.equal(after.stats.checks.gaps, 0);
  assert.equal(after.stats.checks.byStatus.unverified, 1);
});
