import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, PlaywrightDriver } from "@veritas/crawler";
import { runPilot } from "./run.js";

const tool = (name: string, args: object) => ({ id: "call-1", type: "function", function: { name, arguments: JSON.stringify(args) } });
for (const mode of ["401", "429", "network", "no-tools", "max-turns", "done", "resume-existing-finding", "survey-incomplete", "target-auth-wall"] as const) {
  test(`diagnosis completion: ${mode}`, async (t) => {
    const env = { VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1", VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native" };
    const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
    Object.assign(process.env, env);
    const dir = mkdtempSync(join(tmpdir(), "verdict-incomplete-"));
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    const url = "https://app.test/account";
    const scope = deriveScopeFromSingleUrl(url);
    const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
    t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
    let modelCalls = 0;
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
      if (mode === "target-auth-wall" && String(input).startsWith("https://app.test/")) return new Response("Login required", { status: 401 });
      modelCalls += 1;
      assert.match(String(input), /^http:\/\/model\.test\//, "only the mock model can be contacted");
      if (mode === "401" || mode === "429") return new Response('{"error":{"message":"provider unavailable"}}', { status: Number(mode) });
      if (mode === "network") throw new Error("mock transport failure");
      const done = mode === "done" || mode === "resume-existing-finding" || (mode === "target-auth-wall" && modelCalls > 1);
      const calls = mode === "target-auth-wall" && modelCalls === 1 ? Array.from({ length: 12 }, (_, i) => ({ ...tool("http_request", { url: `https://app.test/account?probe=${i}`, method: "GET" }), id: `call-${i}` })) : mode === "max-turns" ? [tool("get_screen", {})] : done ? [tool("screen_done", { summary: "Static screen reviewed", verdict: "clean", coverage: [] })] : undefined;
      return Response.json({ choices: [{ message: { role: "assistant", content: calls ? null : "Finished without tools", ...(calls ? { tool_calls: calls } : {}) } }] });
    });
    try {
      store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
      store.upsertScreen("a-1", { screenId: "s-0001", urlTemplate: url, observedUrls: [url], authState: "unauth", screenType: "detail", description: "Static", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] });
      store.setPhase("a-1", "phase2_scan");
      if (mode !== "survey-incomplete") store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: "s-0001", vulnClasses: [], plan: "Static leaf" } });
      if (mode !== "survey-incomplete") store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: ["s-0001"], summary: "ready" } });
      if (mode === "resume-existing-finding") store.upsertFinding("a-1", { id: "f-001", screenId: "s-0001", title: "[other] Previously confirmed issue", severity: "low", source: { kind: "validator", validatorName: "test" }, description: "Recorded before interruption", reproSteps: "test", evidenceIds: [], scopeBasis: "same host" });
      if (mode === "survey-incomplete") store.setPhase("a-1", "phase1_recon");
      const result = await runPilot({ store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"), roleCreds: new Map(), resume: true,
        maxTurns: mode === "target-auth-wall" ? 2 : 1, maxScreens: 1, scenarioPass: false, fingerprintPass: false, keepAliveMinutes: 0 });
      const state = store.loadAssessment("a-1")!;
      const completed = mode === "done" || mode === "resume-existing-finding";
      assert.equal(store.isPaused("a-1"), !completed);
      assert.equal(state.phase, completed ? "report" : mode === "survey-incomplete" ? "phase1_recon" : "phase2_scan");
      assert.equal(state.screenScans[0]?.status, mode === "resume-existing-finding" ? "finding" : completed ? "clean" : "queued");
      assert.equal(state.findings.length, mode === "resume-existing-finding" ? 1 : 0);
      if (!completed) assert.match(result.summary, /paused/i);
      if (mode === "target-auth-wall") assert.ok(state.handoffs.some((h) => h.id === "ho-authwall"));
    } finally {
      store.close(); rmSync(dir, { recursive: true, force: true });
      for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    }
  });
}
