// カバレッジ台帳の不変条件: 全画面の自動エンロール / coverage 集計 / 優先度付け / 再試行 / 完了判定。

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AssessmentStore,
  coverage,
  prioritizeScreens,
  deriveScopeFromSingleUrl,
  type Screen,
} from "./index.js";

function withStore<T>(fn: (store: AssessmentStore) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "veritas-cov-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  try {
    return fn(store);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  }
}

function screen(id: string, o: Partial<Screen> = {}): Screen {
  return {
    screenId: id,
    urlTemplate: o.urlTemplate ?? `/${id}`,
    observedUrls: o.observedUrls ?? [],
    authState: o.authState ?? "unauth",
    screenType: o.screenType ?? "other",
    description: o.description ?? "",
    params: o.params ?? [],
    apis: o.apis ?? [],
    screenshot: o.screenshot ?? "",
    domSkeletonHash: o.domSkeletonHash ?? id,
    labels: o.labels ?? [],
  };
}

function seed(store: AssessmentStore): string {
  const { id } = store.createAssessment({
    target: { kind: "single_url", url: "https://example.com/", followLinks: true, maxDepth: 3 },
    scope: deriveScopeFromSingleUrl("https://example.com/"),
  });
  store.upsertScreen(
    id,
    screen("s-0001", {
      screenType: "payment",
      labels: ["payment"],
      params: [{ name: "amount", in: "body", example: "10", guessedType: "price" }],
    }),
  );
  store.upsertScreen(
    id,
    screen("s-0002", {
      screenType: "detail",
      authState: "post-login",
      labels: ["idor-candidate", "pii"],
      params: [{ name: "id", in: "path", example: "1", guessedType: "object_ref" }],
    }),
  );
  store.upsertScreen(id, screen("s-0003", { screenType: "listing" }));
  store.upsertScreen(id, screen("s-0004", { screenType: "auth", labels: ["auth"] }));
  return id;
}

test("every discovered screen is auto-enrolled as queued (no screen missed)", () => {
  withStore((store) => {
    const id = seed(store);
    const state = store.loadAssessment(id);
    assert.ok(state);
    assert.equal(state.screenScans.length, 4);
    const cov = coverage(state);
    assert.equal(cov.total, 4);
    assert.equal(cov.byStatus.queued, 4);
    assert.equal(cov.terminal, 0);
    assert.equal(cov.remaining, 4);
    assert.equal(cov.scannable, 4);
    assert.equal(cov.complete, false);
  });
});

test("prioritizeScreens orders by attack value (§7.1)", () => {
  withStore((store) => {
    const id = seed(store);
    const state = store.loadAssessment(id);
    assert.ok(state);
    const order = prioritizeScreens(state).map((p) => p.screenId);
    assert.deepEqual(order, ["s-0001", "s-0002", "s-0004", "s-0003"]);
  });
});

test("coverage reaches complete only when every screen is terminal", () => {
  withStore((store) => {
    const id = seed(store);
    store.setScreenScanStatus(id, "s-0001", "scanning");
    store.setScreenScanStatus(id, "s-0001", "finding", { findingIds: ["f-1"] });
    store.setScreenScanStatus(id, "s-0002", "clean");
    store.setScreenScanStatus(id, "s-0003", "excluded");

    let state = store.loadAssessment(id);
    assert.ok(state);
    let cov = coverage(state);
    assert.equal(cov.terminal, 3);
    assert.equal(cov.remaining, 1);
    assert.equal(cov.complete, false);
    assert.deepEqual(
      prioritizeScreens(state).map((p) => p.screenId),
      ["s-0004"],
      "only the still-queued screen is scannable",
    );

    // s-0004 が一過性失敗 → 再試行枠の間は scannable、使い切ると外れる
    store.setScreenScanStatus(id, "s-0004", "error", { incrementAttempt: true, error: "timeout" });
    state = store.loadAssessment(id);
    assert.ok(state);
    assert.equal(coverage(state).scannable, 1, "error with attempts<max stays scannable");

    store.setScreenScanStatus(id, "s-0004", "error", { incrementAttempt: true });
    store.setScreenScanStatus(id, "s-0004", "error", { incrementAttempt: true });
    state = store.loadAssessment(id);
    assert.ok(state);
    assert.equal(state.screenScans.find((s) => s.screenId === "s-0004")?.attempts, 3);
    assert.equal(coverage(state).scannable, 0, "retry budget exhausted -> not scannable");
    assert.equal(coverage(state).complete, false, "exhausted error is not coverage-complete");

    // 最終的に clean に落ち着けば complete
    store.setScreenScanStatus(id, "s-0004", "clean");
    state = store.loadAssessment(id);
    assert.ok(state);
    cov = coverage(state);
    assert.equal(cov.terminal, 4);
    assert.equal(cov.remaining, 0);
    assert.equal(cov.complete, true);
  });
});

test("a 'suspected' screen is terminal — coverage stays reachable (no hang on a lead-only screen)", () => {
  withStore((store) => {
    const id = seed(store);
    store.setScreenScanStatus(id, "s-0001", "finding", { findingIds: ["f-1"] });
    store.setScreenScanStatus(id, "s-0002", "suspected"); // 異常リードのみ。診断は完了 = terminal
    store.setScreenScanStatus(id, "s-0003", "clean");
    store.setScreenScanStatus(id, "s-0004", "suspected");
    const state = store.loadAssessment(id);
    assert.ok(state);
    const cov = coverage(state);
    assert.equal(cov.byStatus.suspected, 2);
    assert.equal(cov.terminal, 4, "suspected counts toward terminal");
    assert.equal(cov.remaining, 0);
    assert.equal(cov.complete, true, "a suspected-only screen does not hang the stop condition");
  });
});

test("scan-status transitions are recorded as events and survive reopen", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-cov-"));
  const dbPath = join(dir, "state.sqlite");
  try {
    let store = AssessmentStore.open(dbPath);
    const id = seed(store);
    store.setScreenScanStatus(id, "s-0001", "scanning");
    store.setScreenScanStatus(id, "s-0001", "finding", { findingIds: ["f-1"] });
    store.close();

    store = AssessmentStore.open(dbPath);
    const state = store.loadAssessment(id);
    assert.ok(state);
    const scan = state.screenScans.find((s) => s.screenId === "s-0001");
    assert.equal(scan?.status, "finding");
    assert.deepEqual(scan?.findingIds, ["f-1"]);
    const transitions = state.events.filter((e) => e.type === "screen_scan_status_changed");
    assert.equal(transitions.length, 2, "queued->scanning, scanning->finding");
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
