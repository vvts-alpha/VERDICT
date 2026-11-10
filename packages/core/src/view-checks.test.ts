import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { screenChecks } from "./checks.js";
import { deriveScopeFromSingleUrl } from "./factories.js";
import { AssessmentStore } from "./store.js";
import type { CheckExecution, CheckStatus } from "./types/index.js";
import { buildStateView } from "./view.js";

let nextId = 0;
function check(status: CheckStatus, opts: Partial<CheckExecution> = {}): CheckExecution {
  return {
    id: `check-${++nextId}`,
    screenId: "s-0001",
    target: "GET /api/orders/{id}",
    param: "id",
    resource: "order-1",
    subject: "member",
    principal: "account-a",
    session: "session-a",
    checkClass: "idor",
    status,
    tool: status === "planned" ? "methodology" : "probe_idor",
    evidenceIds: [],
    findingIds: [],
    updatedAt: "2026-02-01T00:00:00Z",
    ...opts,
  };
}

function assessment(store: AssessmentStore): string {
  const { id } = store.createAssessment({
    target: { kind: "single_url", url: "https://example.test/", followLinks: false, maxDepth: 0 },
    scope: deriveScopeFromSingleUrl("https://example.test/"),
  });
  store.setScreenScanStatus(id, "s-0001", "clean");
  return id;
}

test("failed tool unverified/blocked attempts do not satisfy a plan or verify a clean claim", () => {
  for (const failure of ["unverified", "blocked"] as const) {
    const store = AssessmentStore.open(":memory:");
    try {
      const id = assessment(store);
      store.upsertCheck(id, check("planned"));
      store.upsertCheck(id, check(failure, { reason: "session could not establish a baseline" }));
      const state = store.loadAssessment(id)!;
      const source = screenChecks(state, "s-0001");
      const view = buildStateView(state);
      assert.equal(source.unstarted.length, 1);
      assert.equal(source.gaps.length, 1);
      assert.deepEqual(view.screenHonesty["s-0001"], {
        raw: "clean", status: "unverified", legacy: false, gaps: 1, unfulfilled: 1,
      });
      assert.equal(view.screenCheckSummaries["s-0001"]?.verdict, "unverified");
      assert.deepEqual(view.screenCheckSummaries["s-0001"]?.classes.map((c) => [c.status, c.gaps, c.unfulfilled]), [[failure, 1, 1]]);
    } finally {
      store.close();
    }
  }
});

test("a raw HTTP observation (even a 'tested-clean' claim) cannot establish coverage or erase legacy", () => {
  const store = AssessmentStore.open(":memory:");
  try {
    const id = assessment(store);
    const blank = buildStateView(store.loadAssessment(id)!);
    assert.deepEqual(blank.screenHonesty["s-0001"], {
      raw: "clean", status: "unknown-records", legacy: true, gaps: 0, unfulfilled: 0,
    });
    assert.equal(blank.screenCheckSummaries["s-0001"], undefined);

    store.upsertCheck(id, check("tested-clean", {
      checkClass: "http-request", tool: "http_request", evidenceIds: ["ev-http"],
    }));
    const view = buildStateView(store.loadAssessment(id)!);
    assert.deepEqual(view.screenHonesty["s-0001"], blank.screenHonesty["s-0001"]);
    assert.deepEqual(view.screenCheckSummaries["s-0001"], {
      verdict: "unverified", classes: [], gaps: 0, unfulfilled: 0,
    });
  } finally {
    store.close();
  }
});

test("a clean execution at another target cannot cover a bound plan slot", () => {
  const store = AssessmentStore.open(":memory:");
  try {
    const id = assessment(store);
    store.upsertCheck(id, check("planned"));
    store.upsertCheck(id, check("tested-clean", {
      target: "GET /api/other", baselineOk: true, evidenceIds: ["ev-other"],
    }));
    const view = buildStateView(store.loadAssessment(id)!);
    assert.equal(view.screenHonesty["s-0001"]?.status, "unverified");
    assert.equal(view.screenHonesty["s-0001"]?.gaps, 0);
    assert.equal(view.screenHonesty["s-0001"]?.unfulfilled, 1);
    assert.equal(view.screenCheckSummaries["s-0001"]?.verdict, "unverified");
    assert.equal(view.screenCheckSummaries["s-0001"]?.classes[0]?.status, "tested-clean");
    assert.equal(view.screenCheckSummaries["s-0001"]?.classes[0]?.unfulfilled, 1);
  } finally {
    store.close();
  }
});

test("an older finding-backed screen can retain its finding headline without check rows", () => {
  const store = AssessmentStore.open(":memory:");
  try {
    const id = assessment(store);
    store.upsertFinding(id, {
      id: "finding-1", screenId: "s-0001", title: "Confirmed issue", severity: "high",
      source: { kind: "validator", validatorName: "existing" }, description: "Recorded finding",
      reproSteps: "", evidenceIds: ["ev-existing"], scopeBasis: "in scope",
    });
    store.setScreenScanStatus(id, "s-0001", "finding");
    const view = buildStateView(store.loadAssessment(id)!);
    assert.deepEqual(view.screenHonesty["s-0001"], {
      raw: "finding", status: "finding", legacy: false, gaps: 0, unfulfilled: 0,
    });
  } finally {
    store.close();
  }
});

test("a later evidenced retry clears only the same verified principal's gap; a different principal stays visible", () => {
  const store = AssessmentStore.open(":memory:");
  try {
    const id = assessment(store);
    store.upsertCheck(id, check("planned", { session: undefined }));
    store.upsertCheck(id, check("unverified", {
      reason: "baseline unstable", finishedAt: "2026-02-01T00:00:01Z",
    }));
    const retry = check("tested-clean", {
      session: "session-b", startedAt: "2026-02-01T00:00:02Z", finishedAt: "2026-02-01T00:00:03Z",
      baselineOk: true, evidenceIds: ["ev-retry"],
    });
    store.upsertCheck(id, retry);
    const good = buildStateView(store.loadAssessment(id)!);
    assert.deepEqual(good.screenHonesty["s-0001"], {
      raw: "clean", status: "clean", legacy: false, gaps: 0, unfulfilled: 0,
    });
    assert.equal(good.screenCheckSummaries["s-0001"]?.classes[0]?.status, "tested-clean");
    assert.equal(good.screenCheckSummaries["s-0001"]?.classes[0]?.gaps, 0);
    assert.equal(good.screenCheckSummaries["s-0001"]?.classes[0]?.outcomes.find((o) => o.status === "unverified")?.count, 1);

    store.upsertCheck(id, check("blocked", {
      principal: "account-b", session: "session-b", reason: "other account not authorized",
      finishedAt: "2026-02-01T00:00:01Z",
    }));
    const mixed = buildStateView(store.loadAssessment(id)!);
    const source = screenChecks(store.loadAssessment(id)!, "s-0001");
    assert.equal(source.gaps.length, 1);
    assert.equal(source.unstarted.length, 0);
    assert.equal(mixed.screenHonesty["s-0001"]?.status, "unverified");
    assert.equal(mixed.screenHonesty["s-0001"]?.gaps, 1);
    assert.equal(mixed.screenCheckSummaries["s-0001"]?.classes[0]?.gaps, 1);
    assert.equal(mixed.screenCheckSummaries["s-0001"]?.verdict, "unverified");
  } finally {
    store.close();
  }
});

test("recent-event truncation and SQLite reopen cannot erase projected gaps or class rollups", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-view-checks-"));
  const db = join(dir, "state.sqlite");
  try {
    const store = AssessmentStore.open(db);
    const id = assessment(store);
    store.upsertCheck(id, check("planned"));
    store.upsertCheck(id, check("unverified", { reason: "missing authorization" }));
    for (let i = 0; i < 310; i++) store.appendEvent(id, { type: "note", payload: { message: `later event ${i}` } });
    const before = buildStateView(store.loadAssessment(id)!);
    assert.equal(before.events.length, 300);
    assert.equal(before.events.some((e) => e.type === "check_recorded"), false);
    store.close();

    const reopened = AssessmentStore.open(db);
    try {
      const after = buildStateView(reopened.loadAssessment(id)!);
      assert.deepEqual(after.screenHonesty, before.screenHonesty);
      assert.deepEqual(after.screenCheckSummaries, before.screenCheckSummaries);
      assert.equal(after.screenHonesty["s-0001"]?.unfulfilled, 1);
      assert.equal(after.screenHonesty["s-0001"]?.gaps, 1);
    } finally {
      reopened.close();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
