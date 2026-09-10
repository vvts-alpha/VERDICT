import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, PlaywrightDriver } from "@veritas/crawler";
import { FetchHttpClient } from "@veritas/scanner";
import { runPilot } from "./run.js";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

test("survey completion refuses unvisited URLs, with an explicit survey cap preserved", async () => {
  const events: unknown[] = [];
  const session = { assessmentId: "review", store: { appendEvent: (_id: string, event: unknown) => events.push(event) },
    roleCreds: new Map(), roleCookieFiles: new Map(), roleDescriptions: new Map(), currentCookie: "", currentBearer: "",
    frontier: new Set(["https://app.test/private"]), inv: { screens: () => [] }, surveyDone: false, surveyCapped: false } as unknown as PilotSession;
  const tool = buildTools(session).find((t) => t.name === "survey_done")!;
  await tool.handler({ summary: "premature" } as never, {} as never);
  assert.equal(session.surveyDone, false);
  assert.equal(events.length, 0);
  session.frontier.clear();
  await tool.handler({ summary: "mapped" } as never, {} as never);
  assert.equal(session.surveyDone, true);
  session.surveyDone = false;
  session.frontier.add("https://app.test/private");
  session.surveyCapped = true;
  await tool.handler({ summary: "operator cap reached" } as never, {} as never);
  assert.equal(session.surveyDone, true);
});

test("resume continues unfinished recon after survey and does not repeat a completed recon pass", async (t) => {
  const env = { VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1", VERDICT_LLM_MODEL: "deep",
    VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native" };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-recon-resume-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const url = "https://app.test/account";
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("No target traffic in this test"); });
  let calls = 0;
  t.mock.method(globalThis, "fetch", async (_input: unknown, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    assert.match(body.messages[1]!.content, /probe_guesses/);
    calls++;
    return Response.json({ choices: [{ message: { role: "assistant", content: null,
      tool_calls: [{ id: "done", type: "function", function: { name: "guess_done", arguments: "{}" } }] } }] });
  });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    store.upsertScreen("a-1", { screenId: "s-0001", urlTemplate: url, observedUrls: [url], authState: "unauth", screenType: "detail", description: "Static", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] });
    store.setPhase("a-1", "phase1_recon");
    store.appendEvent("a-1", { type: "note", payload: { message: "🗺  SURVEY done: mapped" } });
    store.setPaused("a-1", true, "recon interrupted");
    const options = { store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"),
      roleCreds: new Map(), resume: true, surveyOnly: true, maxTurns: 1, keepAliveMinutes: 0 };
    await runPilot(options);
    assert.equal(calls, 1);
    assert.equal(store.isPaused("a-1"), false);
    assert.equal(store.loadAssessment("a-1")!.events.filter((event) => event.type === "recon_completed").length, 1);
    await runPilot(options);
    assert.equal(calls, 1, "completed recon is not repeated");
  } finally {
    store.close(); rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  }
});
