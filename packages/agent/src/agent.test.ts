// M5 completion criterion: on one screen, IDOR hypothesis generation → verification runs (evidence discipline + store integration). LLM/HTTP are Fakes.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { Screen } from "@veritas/core";
import { FakeLlmClient } from "@veritas/llm";
import { EvidenceStore, FakeHttpClient } from "@veritas/scanner";
import type { FakeResponder } from "@veritas/scanner";
import { assessScreenLogic, generateHypotheses, ruleHypotheses, verifyHypothesis } from "./index.js";

function idorScreen(): Screen {
  return {
    screenId: "s-0001",
    urlTemplate: "/orders/{id}",
    observedUrls: ["https://shop.test/orders/5"],
    authState: "unauth",
    screenType: "detail",
    description: "order detail",
    params: [{ name: "id", in: "path", example: "5", guessedType: "object_ref" }],
    apis: [{ method: "GET", urlTemplate: "/api/orders/{id}", auth: "cookie", reqSchema: null, resSchema: null }],
    screenshot: "",
    domSkeletonHash: "x",
    labels: ["idor-candidate"],
  };
}

// A neighbouring id (/api/orders/6) returns an entity, an invalid id (/api/orders/10000024) 404s → IDOR
const idorResponder: FakeResponder = (req) => {
  const p = new URL(req.url).pathname;
  if (p === "/api/orders/6") return { status: 200, body: '{"order":6,"total":42,"owner":"victim"}' };
  return { status: 404, body: "not found" };
};

function withEvidence<T>(fn: (ev: EvidenceStore, dir: string) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-agent-"));
  return fn(new EvidenceStore(join(dir, "artifacts")), dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("ruleHypotheses emits an IDOR hypothesis from an object_ref param", () => {
  const hs = ruleHypotheses(idorScreen());
  assert.equal(hs.length, 1);
  assert.equal(hs[0]?.class, "idor");
  assert.equal(hs[0]?.status, "queued");
});

test("generateHypotheses parses LLM structured output", async () => {
  const llm = new FakeLlmClient('{"hypotheses":[{"class":"idor","statement":"other orders viewable","testPlan":"swap id"}]}');
  const { hypotheses, usedFallback } = await generateHypotheses(idorScreen(), llm);
  assert.equal(usedFallback, false);
  assert.equal(hypotheses.length, 1);
  assert.equal(hypotheses[0]?.class, "idor");
});

test("verifyHypothesis confirms IDOR via neighbour-id + invalid-id discipline", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(idorResponder);
    const hs = ruleHypotheses(idorScreen());
    const outcome = await verifyHypothesis(hs[0]!, idorScreen(), http, ev, new Set());
    assert.equal(outcome.status, "confirmed");
    assert.equal(outcome.evidenceIds.length, 3, "negative control + 2 positive replays");
  });
});

test("catch-all (every id returns data) refutes IDOR", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(() => ({ status: 200, body: '{"anything":true,"x":1234}' }));
    const outcome = await verifyHypothesis(ruleHypotheses(idorScreen())[0]!, idorScreen(), http, ev, new Set());
    assert.equal(outcome.status, "refuted");
  });
});

// A neighbour id that returns 200 but carries NO cross-user data proves only enumerability (or a public endpoint), not a
// missing object-level auth. Before the cross-user requirement this confirmed a HIGH IDOR on ANY 200 — the deterministic
// over-confirm the audit flagged (false HIGH on public catalogs / self-owned objects).
test("IDOR refutes a 200 that carries no cross-user data (enumerable ≠ proven object-level-auth failure)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) => (req.url.includes("/api/orders/6") ? { status: 200, body: '{"status":"ok","results":[]}' } : { status: 404, body: "not found" }));
    const outcome = await verifyHypothesis(ruleHypotheses(idorScreen())[0]!, idorScreen(), http, ev, new Set());
    assert.equal(outcome.status, "refuted", "no cross-user data → must not confirm HIGH IDOR");
  });
});

test("non-idor class is blocked (no automated verifier yet)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(() => ({ status: 200, body: "x" }));
    const hypothesis = { ...ruleHypotheses(idorScreen())[0]!, class: "price_tampering" as const };
    const outcome = await verifyHypothesis(hypothesis, idorScreen(), http, ev, new Set());
    assert.equal(outcome.status, "blocked");
  });
});

const pageIdorScreen = (): Screen => ({
  screenId: "s-0002",
  urlTemplate: "/orders/{id}",
  observedUrls: ["https://shop.test/orders/12"],
  authState: "post-login",
  screenType: "detail",
  description: "order detail (page)",
  params: [{ name: "id", in: "path", example: "12", guessedType: "object_ref" }],
  apis: [], // server-rendered: no XHR API
  screenshot: "",
  domSkeletonHash: "x",
  labels: ["idor-candidate"],
});

test("page-level IDOR confirms on a post-login screen with no API (P2)", async () => {
  await withEvidence(async (ev) => {
    const screen = pageIdorScreen();
    const http = new FakeHttpClient((req) =>
      new URL(req.url).pathname === "/orders/13"
        ? { status: 200, body: "<h1>Order 13 belonging to another user</h1>" }
        : { status: 404, body: "not found" },
    );
    const h = ruleHypotheses(screen)[0];
    assert.ok(h, "post-login id page yields an idor hypothesis");
    const outcome = await verifyHypothesis(h, screen, http, ev, new Set());
    assert.equal(outcome.status, "confirmed");
  });
});

test("public (unauth) object pages are not IDOR candidates", () => {
  const publicScreen: Screen = { ...pageIdorScreen(), authState: "unauth" };
  assert.equal(ruleHypotheses(publicScreen).length, 0);
});

test("assessScreenLogic runs generate→verify→persist for one screen (M5)", async () => {
  await withEvidence(async (ev, dir) => {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-1",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    store.upsertScreen("a-1", idorScreen());

    const llm = new FakeLlmClient('{"hypotheses":[{"class":"idor","statement":"IDOR on order id","testPlan":"swap id"}]}');
    const http = new FakeHttpClient(idorResponder);
    const result = await assessScreenLogic(idorScreen(), llm, http, ev, { store, assessmentId: "a-1" });

    assert.equal(result.hypotheses.length, 1);
    assert.equal(result.findings.length, 1);

    const state = store.loadAssessment("a-1");
    assert.ok(state);
    assert.equal(state.hypotheses.length, 1);
    assert.equal(state.hypotheses[0]?.status, "confirmed");
    assert.equal(state.findings.length, 1);
    assert.equal(state.findings[0]?.source.kind, "hypothesis");
    assert.equal(state.screenScans.find((s) => s.screenId === "s-0001")?.status, "finding");
    const types = state.events.map((e) => e.type);
    assert.ok(types.includes("hypothesis_created"));
    assert.ok(types.includes("hypothesis_status_changed"));
    assert.ok(types.includes("finding_created"));
    store.close();
  });
});
