// LLM labeling tests: prompt generation / structured-output type validation / merge / fallback on failure /
// bulk inventory labeling (store update + phase transition). The LLM is made deterministic via FakeLlmClient.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FakeLlmClient } from "@veritas/llm";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { Screen } from "@veritas/core";
import {
  applyLabel,
  buildLabelPrompt,
  labelInventory,
  labelScreen,
  parseScreenLabel,
} from "./index.js";

function screen(over: Partial<Screen> = {}): Screen {
  return {
    screenId: over.screenId ?? "s-0001",
    urlTemplate: over.urlTemplate ?? "/orders/{id}",
    observedUrls: over.observedUrls ?? ["https://shop.test/orders/1"],
    authState: over.authState ?? "unauth",
    screenType: over.screenType ?? "other",
    description: over.description ?? "[rule] other /orders/{id}.",
    params: over.params ?? [{ name: "id", in: "path", example: "1", guessedType: "object_ref" }],
    apis: over.apis ?? [],
    screenshot: "",
    domSkeletonHash: over.domSkeletonHash ?? "deadbeef",
    labels: over.labels ?? ["idor-candidate"],
  };
}

test("buildLabelPrompt includes the structured surface", () => {
  const p = buildLabelPrompt(screen());
  assert.match(p, /\/orders\/\{id\}/);
  assert.match(p, /screenType/);
  assert.match(p, /object_ref/);
});

test("parseScreenLabel accepts valid structured output (with fences)", () => {
  const r = parseScreenLabel('```json\n{"screenType":"detail","description":"order detail; IDOR risk","labels":["idor-candidate","pii"]}\n```');
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.label.screenType, "detail");
    assert.deepEqual(r.label.labels, ["idor-candidate", "pii"]);
  }
});

test("parseScreenLabel rejects invalid screenType / missing fields", () => {
  assert.equal(parseScreenLabel('{"screenType":"bogus","description":"x","labels":[]}').ok, false);
  assert.equal(parseScreenLabel('{"description":"no type","labels":[]}').ok, false);
  assert.equal(parseScreenLabel("not json at all").ok, false);
});

test("applyLabel unions labels and refines param types", () => {
  const merged = applyLabel(screen(), {
    screenType: "detail",
    description: "order detail; IDOR via id",
    labels: ["pii"],
    params: [{ name: "id", guessedType: "id" }],
  });
  assert.equal(merged.screenType, "detail");
  assert.equal(merged.description, "order detail; IDOR via id");
  assert.deepEqual(merged.labels, ["idor-candidate", "pii"], "rule + LLM labels unioned");
  assert.equal(merged.params[0]?.guessedType, "id", "param type refined by LLM");
});

test("labelScreen applies a valid LLM label", async () => {
  const client = new FakeLlmClient('{"screenType":"detail","description":"order detail; IDOR risk","labels":["idor-candidate"]}');
  const r = await labelScreen(screen(), client);
  assert.equal(r.usedFallback, false);
  assert.equal(r.screen.screenType, "detail");
  assert.match(r.screen.description, /IDOR/);
  // the system prompt was passed
  assert.match(client.calls[0]?.system ?? "", /security recon/i);
});

test("labelScreen falls back to rule label on garbage output", async () => {
  const client = new FakeLlmClient("the model rambled without any json");
  const original = screen();
  const r = await labelScreen(original, client);
  assert.equal(r.usedFallback, true);
  assert.equal(r.screen.description, original.description, "rule description preserved");
  assert.equal(r.screen.screenType, "other");
  assert.ok(r.error);
});

test("labelInventory updates the store and advances to phase1_label", async () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-label-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-1",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    const s1 = screen({ screenId: "s-0001", urlTemplate: "/orders/{id}" });
    const s2 = screen({ screenId: "s-0002", urlTemplate: "/login", screenType: "auth", labels: ["auth"], params: [] });
    store.upsertScreen("a-1", s1);
    store.upsertScreen("a-1", s2);

    const client = new FakeLlmClient([
      '{"screenType":"detail","description":"order detail; IDOR via id","labels":["idor-candidate","pii"]}',
      "garbage with no json", // s2 → fallback
    ]);
    const result = await labelInventory(store.loadAssessment("a-1")!.screens, client, { store, assessmentId: "a-1" });

    assert.equal(result.labeled, 1);
    assert.equal(result.fallback, 1);

    const state = store.loadAssessment("a-1");
    assert.ok(state);
    assert.equal(state.phase, "phase1_label");
    const detail = state.screens.find((s) => s.screenId === "s-0001");
    assert.equal(detail?.screenType, "detail");
    assert.ok(detail?.labels.includes("pii"));
    const login = state.screens.find((s) => s.screenId === "s-0002");
    assert.equal(login?.screenType, "auth", "fallback kept the rule label");
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
