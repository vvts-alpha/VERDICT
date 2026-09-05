import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { seedSpecInventory } from "./spec-inventory.js";

test("specification starts an in-scope, queued inventory at methodology and preserves schemas", () => {
  const root = mkdtempSync(join(tmpdir(), "verdict-spec-"));
  mkdirSync(join(root, "run"));
  const store = AssessmentStore.open(join(root, "run", "state.sqlite"));
  try {
    const scope = { ...deriveScopeFromSingleUrl("https://app.test"), outOfScopePathPrefixes: ["/admin"] };
    store.createAssessment({ id: "run", target: { kind: "single_url", url: "https://app.test", followLinks: false, maxDepth: 0 }, scope });
    const doc = { openapi: "3.0.3", servers: [{ url: "https://outside.test" }], paths: {
      "/orders": { post: { requestBody: { content: { "application/json": { schema: { type: "object", properties: { quantity: { type: "integer" } } } } } } } },
      "/admin": { get: {} },
    } };
    assert.equal(seedSpecInventory(store, "run", root, doc, "https://app.test", scope), 1);
    const state = store.loadAssessment("run")!;
    assert.equal(state.phase, "phase1_label");
    assert.equal(state.screenScans[0]?.status, "queued");
    assert.deepEqual(state.scope, scope);
    assert.ok(state.screens[0]?.observedUrls[0]?.startsWith("https://app.test/"));
    assert.equal(state.screens[0]?.apis[0]?.method, "POST");
    assert.ok(state.screens[0]?.apis[0]?.reqSchema);
    assert.ok(existsSync(join(root, "run", "screen_inventory.json")));
  } finally { store.close(); rmSync(root, { recursive: true, force: true }); }
});
