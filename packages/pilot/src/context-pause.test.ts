import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, PlaywrightDriver } from "@veritas/crawler";
import { runPilot } from "./run.js";

test("context failure leaves a diagnosis queued and pauses the saved run instead of reporting it clean", async (t) => {
  const env = { VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1", VERDICT_LLM_MODEL: "deep",
    VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_CONTEXT_TOKENS: "8192", VERDICT_LLM_FAST_CONTEXT_TOKENS: "8192" };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-context-pause-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const url = "https://app.test/account";
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  const network = t.mock.method(globalThis, "fetch", async () => { throw new Error("No real model or target calls are allowed in this test"); });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    store.upsertScreen("a-1", { screenId: "s-0001", urlTemplate: url, observedUrls: [url], authState: "post-login", screenType: "detail", description: "Account", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] });
    store.setPhase("a-1", "phase2_scan");
    store.appendEvent("a-1", { type: "note", payload: { message: "📋 PLAN s-0001: [idor] verify account access" } });
    store.appendEvent("a-1", { type: "note", payload: { message: "📋 METHODOLOGY done: ready" } });
    const result = await runPilot({ store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"), roleCreds: new Map(), resume: true,
      operatorContext: "x".repeat(40_000), maxScreens: 1, scenarioPass: false, fingerprintPass: false, keepAliveMinutes: 0 });
    const state = store.loadAssessment("a-1")!;
    assert.equal(store.isPaused("a-1"), true);
    assert.equal(state.phase, "phase2_scan");
    assert.equal(state.screenScans.find((s) => s.screenId === "s-0001")?.status, "queued");
    assert.equal(state.findings.length, 0);
    assert.match(result.summary, /paused.*context/i);
    assert.equal(network.mock.callCount(), 0);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
});
