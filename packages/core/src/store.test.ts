// Verifies AssessmentStore's round-trip / event-log invariants.
// Run: pnpm --filter @veritas/core test  (node:test + tsx, no native dependency)

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AssessmentStore,
  buildStateView,
  defaultBudget,
  deriveScopeFromSingleUrl,
  type Hypothesis,
  type Screen,
} from "./index.js";

function withTempDb<T>(fn: (dbPath: string) => T): T {
  const dir = mkdtempSync(join(tmpdir(), "veritas-core-"));
  try {
    return fn(join(dir, "state.sqlite"));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("createAssessment writes an empty assessment to state.sqlite (M0 completion criterion)", () => {
  withTempDb((dbPath) => {
    const store = AssessmentStore.open(dbPath);
    const state = store.createAssessment({
      target: { kind: "single_url", url: "https://example.com/app", followLinks: true, maxDepth: 3 },
      scope: deriveScopeFromSingleUrl("https://example.com/app"),
      budget: defaultBudget(),
    });

    assert.equal(state.phase, "init");
    assert.equal(state.screens.length, 0);
    assert.equal(state.hypotheses.length, 0);
    assert.equal(state.findings.length, 0);
    assert.equal(state.handoffs.length, 0);
    assert.equal(state.events.length, 1);
    assert.equal(state.events[0]?.type, "assessment_created");
    store.close();

    // The file is actually written to disk
    assert.ok(existsSync(dbPath), "state.sqlite should exist on disk");
  });
});

// analyzed-JS assets: js_analyzed events dedup the agent's bundle analysis (analyzedJsUrls) and project into the WebUI
// state view (jsAssets, last-write-per-url). No new table — the append-only log carries it.
test("js_analyzed events: analyzedJsUrls dedups + buildStateView projects jsAssets", () => {
  withTempDb((dbPath) => {
    const store = AssessmentStore.open(dbPath);
    const { id } = store.createAssessment({
      target: { kind: "single_url", url: "https://app.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://app.test/"),
      budget: defaultBudget(),
    });
    store.appendEvent(id, {
      type: "js_analyzed",
      payload: { url: "https://app.test/main.js", bytes: 1024, endpointsFound: ["GET /api/x"], secretsFound: [{ kind: "secret", detail: "Google API key: AIza…QXh4" }], sourceMap: true, analyzedAt: "2026-01-01T00:00:00Z" },
    });
    store.appendEvent(id, {
      type: "js_analyzed",
      payload: { url: "https://app.test/vendor.js", bytes: 2048, endpointsFound: [], secretsFound: [], sourceMap: false, analyzedAt: "2026-01-01T00:00:01Z" },
    });

    const urls = store.analyzedJsUrls(id); // dedup source the analyze_js tool reads
    assert.ok(urls.has("https://app.test/main.js") && urls.has("https://app.test/vendor.js"));
    assert.equal(urls.size, 2);

    const view = buildStateView(store.loadAssessment(id)!); // WebUI projection
    assert.equal(view.jsAssets.length, 2);
    const main = view.jsAssets.find((a) => a.url.endsWith("main.js"));
    assert.ok(main && main.endpointsFound.length === 1 && main.sourceMap === true && main.secretsFound.length === 1);
    store.close();
  });
});

test("two writable connections on the same file both write (server + spawned pilot share state.sqlite)", () => {
  withTempDb((dbPath) => {
    const a = AssessmentStore.open(dbPath);
    const { id } = a.createAssessment({
      target: { kind: "single_url", url: "https://example.com/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://example.com/"),
      budget: defaultBudget(),
    });
    const b = AssessmentStore.open(dbPath); // a second connection (= the spawned pilot)
    // Write alternately. With BEGIN IMMEDIATE + busy_timeout, both succeed without failing on "database is locked".
    assert.doesNotThrow(() => {
      a.setPaused(id, true, "A");
      b.setPaused(id, false, "B");
      a.setPaused(id, true, "A again");
    });
    const loaded = b.loadAssessment(id);
    assert.ok(loaded, "state reloads from the second connection");
    assert.ok(loaded.events.length >= 2, "pause events from both connections are persisted");
    a.close();
    b.close();
  });
});

test("state is durable across reopen", () => {
  withTempDb((dbPath) => {
    const store = AssessmentStore.open(dbPath);
    const { id } = store.createAssessment({
      target: { kind: "scope_manifest", path: "/tmp/scope.yaml" },
      scope: deriveScopeFromSingleUrl("https://shop.example.com/"),
    });
    store.close();

    const reopened = AssessmentStore.open(dbPath);
    const loaded = reopened.loadAssessment(id);
    assert.ok(loaded, "assessment should reload after reopen");
    assert.equal(loaded.id, id);
    assert.equal(loaded.target.kind, "scope_manifest");
    assert.equal(loaded.events.length, 1);
    reopened.close();
  });
});

test("every state transition appends a sequenced event", () => {
  withTempDb((dbPath) => {
    const store = AssessmentStore.open(dbPath);
    const { id } = store.createAssessment({
      target: { kind: "single_url", url: "https://example.com/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://example.com/"),
    });

    store.setPhase(id, "phase1_recon");

    const screen: Screen = {
      screenId: "s-0001",
      urlTemplate: "/orders/{id}",
      observedUrls: ["/orders/1", "/orders/2"],
      authState: "post-login",
      screenType: "detail",
      description: "Order detail",
      params: [{ name: "id", in: "path", example: "1", guessedType: "object_ref" }],
      apis: [{ method: "GET", urlTemplate: "/api/orders/{id}", auth: "cookie", reqSchema: null, resSchema: null }],
      screenshot: "artifacts/s-0001.png",
      domSkeletonHash: "deadbeef",
      labels: ["idor-candidate", "pii"],
    };
    store.upsertScreen(id, screen);
    store.upsertScreen(id, { ...screen, description: "Order detail (refined)" }); // second time → updated

    const hypo: Hypothesis = {
      id: "h-0001",
      screenId: "s-0001",
      class: "idor",
      statement: "can view another user's order_id",
      testPlan: "GET with another account's order_id in id",
      status: "queued",
      evidenceIds: [],
    };
    store.upsertHypothesis(id, hypo);
    store.upsertHypothesis(id, { ...hypo, status: "testing" }); // status transition

    const loaded = store.loadAssessment(id);
    assert.ok(loaded);
    assert.equal(loaded.phase, "phase1_recon");
    assert.equal(loaded.screens.length, 1, "same screenId dedups to one row");
    assert.equal(loaded.screens[0]?.description, "Order detail (refined)");
    assert.equal(loaded.hypotheses.length, 1);
    assert.equal(loaded.hypotheses[0]?.status, "testing");

    const types = loaded.events.map((e) => e.type);
    assert.deepEqual(types, [
      "assessment_created",
      "phase_changed",
      "screen_discovered",
      "screen_updated",
      "hypothesis_created",
      "hypothesis_status_changed",
    ]);

    // seq is monotonically increasing, starting at 1
    assert.deepEqual(
      loaded.events.map((e) => e.seq),
      [1, 2, 3, 4, 5, 6],
    );
    store.close();
  });
});

test("halt records the stop reason and flips phase", () => {
  withTempDb((dbPath) => {
    const store = AssessmentStore.open(dbPath);
    const { id } = store.createAssessment({
      target: { kind: "single_url", url: "https://example.com/", followLinks: false, maxDepth: 1 },
      scope: deriveScopeFromSingleUrl("https://example.com/"),
    });
    store.halt(id, "unreachable", "WAF 403 from this host");

    const loaded = store.loadAssessment(id);
    assert.ok(loaded);
    assert.equal(loaded.phase, "halted");
    const halted = loaded.events.find((e) => e.type === "halted");
    assert.ok(halted);
    assert.equal(halted.type === "halted" && halted.payload.reason, "unreachable");
    store.close();
  });
});
