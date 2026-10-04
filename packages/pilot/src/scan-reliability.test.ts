import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createServer, type RequestListener } from "node:http";
import { AssessmentStore, defaultBudget, deriveScopeFromSingleUrl, type Screen } from "@veritas/core";
import { FakeDriver, InventoryBuilder, PlaywrightDriver } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient, type HttpRequest } from "@veritas/scanner";
import { analyzePageJs, buildTools, type PilotSession } from "./tools.js";
import { judgeConfirmedFinding } from "./findings-qa.js";
import { runPilot } from "./run.js";
import { runOpenAiAgentLoop, type PilotToolDef } from "./agent-loop.js";

const BASE = "https://app.test/";
const screen = (i: number): Screen => ({ screenId: `s-${String(i).padStart(4, "0")}`, urlTemplate: `/page-${i}`, observedUrls: [`${BASE}page-${i}`], authState: "unauth", screenType: "detail", description: "Static fixture", params: [], apis: [], screenshot: "", domSkeletonHash: `h-${i}`, labels: [] });
function fixture(t: TestContext, base = BASE) {
  const dir = mkdtempSync(join(tmpdir(), "verdict-scan-regression-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const scope = deriveScopeFromSingleUrl(base);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope });
  t.after(() => { store.close(); rmSync(dir, { recursive: true, force: true }); });
  const s = { store, assessmentId: "a-1", scope, targetUrl: base, evidence: new EvidenceStore(join(dir, "artifacts")), inv: new InventoryBuilder(),
    roleCreds: new Map(), roleCookieFiles: new Map(), roleDescriptions: new Map(), currentCookie: "", currentBearer: "", currentRole: "", currentScreenId: "s-0001",
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0, findings: [], findingsByKey: new Map(), accessVerdicts: new Map(), recordCalls: 0, findCounter: 0, plans: new Map() } as unknown as PilotSession;
  const options = { store, assessmentId: "a-1", targetUrl: base, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"), roleCreds: new Map(), resume: true, rateMs: 0, maxTurns: 300, scenarioPass: false, fingerprintPass: false, keepAliveMinutes: 0 };
  return { s, store, options };
}
async function call(s: PilotSession, name: string, args: object): Promise<string> {
  const tool = buildTools(s).find((x) => x.name === name)!;
  const result = (await tool.handler(args as never, {} as never)).content[0]!;
  assert.ok(result.type === "text");
  return result.text;
}
function modelEnv(t: TestContext, mode = "native") {
  const env = { VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1", VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: mode };
  const old = Object.fromEntries(Object.keys(env).map((k) => [k, process.env[k]]));
  Object.assign(process.env, env);
  t.after(() => { for (const [k, v] of Object.entries(old)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
}
const actionResponse = (mode: string, name: string, args: object) => Response.json({ choices: [{ message: mode === "text" ? { content: JSON.stringify({ tool: name, args }) } : { content: null, tool_calls: [{ id: "call-1", type: "function", function: { name, arguments: JSON.stringify(args) } }] } }] });

for (const tool of ["probe_sqli", "probe_cmdi"] as const) {
  for (const mode of ["stable", "slow-control", "flaky", "blocked", "truncated"] as const) {
    test(`${tool}: ${mode} timing must be judged from raw cited replays`, async (t) => {
      const { s, store } = fixture(t);
      store.upsertScreen("a-1", screen(1));
      let sleeps = 0;
      let slowStarted = false;
      s.http = { effectiveHeaders: (h = {}) => h, send: async (req: HttpRequest) => {
        const payload = new URL(req.url).searchParams.get("q") ?? "";
        const sleep = /sleep\(5\)|WAITFOR|sleep 5|ping -[nc] 5/i.test(payload);
        if (sleep) { sleeps++; slowStarted = true; }
        const durationMs = mode === "slow-control" ? (slowStarted ? 5010 : 10) : sleep && (mode !== "flaky" || sleeps % 2 === 1) ? 5010 : 10;
        return { status: mode === "blocked" && sleep ? 429 : 200, headers: {}, body: '{"ok":true}', finalUrl: req.url, durationMs, truncated: mode === "truncated" };
      } } as unknown as FetchHttpClient;
      const result = JSON.parse(await call(s, tool, { url: `${BASE}search`, param: "q" }));
      if (mode !== "stable") { assert.notEqual(result.technique, "time-based"); return; }
      assert.equal(result.technique, "time-based");
      assert.equal(sleeps, 2, "no extra proof-only sleep requests");
      const category = tool === "probe_sqli" ? "sqli" : "rce";
      const args = { title: "Timing fixture", severity: "high", category, endpoint: "/search", param: "q", description: "Measured timing experiment", reproSteps: "Fake transport only", negativeControl: result.negativeControl, positiveReplays: result.positiveReplays };
      assert.match(await call(s, "record_finding", args), /recorded/);
      const finding = store.loadAssessment("a-1")!.findings[0]!;
      assert.equal(finding.verdict, "confirmed");
      assert.equal(finding.evidenceIds.length, 5);
      for (const id of finding.evidenceIds) assert.equal(s.evidence.records.find((r) => r.id === id)!.response.body, '{"ok":true}');
      assert.equal(judgeConfirmedFinding(finding, s.evidence).demote, false);
      // Even a previously valid proof must fail if its actual cited measurement is no longer delayed.
      s.evidence.records.find((r) => r.id === result.positiveReplays[1])!.response.durationMs = 10;
      assert.equal(judgeConfirmedFinding(finding, s.evidence).demote, true);
      s.findingsByKey.clear();
      assert.match(await call(s, "record_finding", args), /REJECTED/);
    });
  }
}

for (const mode of ["text", "native"]) for (const count of [30, 60, 120]) {
  test(`planning ${count} screens completes with one ${mode} tool per turn`, async (t) => {
    modelEnv(t, mode);
    const { store, options } = fixture(t);
    for (let i = 1; i <= count; i++) store.upsertScreen("a-1", screen(i));
    store.setPhase("a-1", "phase1_label");
    let calls = 0;
    t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("No target requests in planning fixture"); });
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
      assert.match(String(input), /^http:\/\/model\.test\//);
      calls++;
      if (calls === 1) return actionResponse(mode, "get_inventory", {});
      if (calls <= count + 1) return actionResponse(mode, "record_methodology", { screenId: screen(calls - 1).screenId, vulnClasses: [], plan: "Static fixture" });
      if (calls === count + 2) return actionResponse(mode, "methodology_done", { summary: "Every screen planned" });
      return actionResponse(mode, "screen_done", { verdict: "clean", coverage: [] });
    });
    await runPilot({ ...options, maxScreens: count });
    const state = store.loadAssessment("a-1")!;
    assert.equal(state.events.filter((e) => e.type === "methodology_recorded").length, count);
    assert.equal(store.isPaused("a-1"), false);
    assert.equal(state.screenScans.filter((sc) => sc.status === "clean").length, count);
  });
}

test("batch methodology is atomic, survives resume and exposes planned status", async (t) => {
  const { s, store } = fixture(t);
  for (let i = 1; i <= 120; i++) { const sc = screen(i); s.inv.seed([sc]); store.upsertScreen("a-1", sc); }
  const plan = (i: number) => ({ screenId: screen(i).screenId, vulnClasses: ["sqli"], plan: "Compare matched controls and positive replays" });
  assert.match(await call(s, "record_methodologies", { plans: [plan(1), plan(121)] }), /REJECTED/);
  assert.equal(s.plans.size, 0);
  for (let offset = 0; offset < 120; offset += 20) await call(s, "record_methodologies", { plans: Array.from({ length: 20 }, (_, i) => plan(offset + i + 1)) });
  await call(s, "methodology_done", { summary: "All planned" });
  assert.equal(s.methodologyDone, true);
  assert.equal(store.loadAssessment("a-1")!.events.filter((e) => e.type === "methodology_recorded").length, 120);
  assert.ok(JSON.parse(await call(s, "get_inventory", {})).screens.every((sc: { planned: boolean }) => sc.planned));
});

for (const mode of ["requests", "per-host", "tokens", "wall-clock", "network-failure"] as const) {
  test(`pilot ${mode} limit pauses queued work and accounts actual attempts`, async (t) => {
    modelEnv(t);
    const { store, options } = fixture(t);
    store.upsertScreen("a-1", screen(1)); store.setPhase("a-1", "phase2_scan");
    store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: "s-0001", vulnClasses: [], plan: "Fixture" } });
    store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: ["s-0001"], summary: "Ready" } });
    const budget = defaultBudget();
    if (mode === "tokens") budget.limits.maxTokens = 1;
    else if (mode === "wall-clock") { budget.limits.maxWallClockMs = 1; budget.startedAt = new Date(Date.now() - 1000).toISOString(); }
    else if (mode === "per-host") budget.limits.maxRequestsPerTarget = 1;
    else budget.limits.maxTotalRequests = 1;
    store.updateBudget("a-1", budget);
    let targets = 0;
    let models = 0;
    let resuming = false;
    t.mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
      if (resuming) return actionResponse("native", "screen_done", { verdict: "clean", coverage: [] });
      if (String(input).startsWith(BASE)) {
        targets++;
        if (mode === "network-failure") throw new Error("Fixture connection reset");
        return new Response("ok");
      }
      assert.match(String(input), /^http:\/\/model\.test\//); models++;
      return Response.json({ usage: { total_tokens: 100 }, choices: [{ message: { content: null, tool_calls: Array.from({ length: 3 }, (_, i) => ({ id: `call-${i}`, type: "function", function: { name: "http_request", arguments: JSON.stringify({ method: "GET", url: `${BASE}page-1` }) } })) } }] });
    });
    await runPilot(options);
    const state = store.loadAssessment("a-1")!;
    assert.equal(targets, mode === "tokens" || mode === "wall-clock" ? 0 : 1);
    assert.equal(models, mode === "wall-clock" ? 0 : 1);
    assert.equal(state.budget.totalRequests, targets);
    assert.equal(state.budget.requestsPerTarget["app.test"] ?? 0, targets);
    assert.equal(state.budget.tokensUsed, mode === "wall-clock" ? 0 : 100);
    assert.equal(store.isPaused("a-1"), true);
    assert.equal(state.phase, "phase2_scan");
    assert.equal(state.screenScans[0]!.status, "queued");
    // Raising the persisted limits allows resume without losing usage or redoing the plan.
    store.updateBudget("a-1", { ...state.budget, limits: defaultBudget().limits });
    resuming = true;
    await runPilot(options);
    assert.equal(store.isPaused("a-1"), false);
    assert.equal(store.loadAssessment("a-1")!.budget.totalRequests, targets);
  });
}

test("inventory transport delivers valid bounded pages with every screen exactly once", async (t) => {
  const { s } = fixture(t);
  for (let i = 1; i <= 60; i++) {
    const sc = screen(i);
    sc.apis = Array.from({ length: 8 }, (_, j) => ({ method: "GET", urlTemplate: `/api/検索/${i}/operations/action-${j}`, auth: "none", reqSchema: null, resSchema: null }));
    if (i === 30) sc.params = [{ name: "x".repeat(20000), in: "query", example: "1", guessedType: "unknown" }];
    s.inv.seed([sc]);
  }
  let nextOffset: number | null = 0;
  const seen: string[] = [];
  await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "fake", system: "Plan fixtures", goal: "Read every page", tools: buildTools(s) as unknown as PilotToolDef[], allowed: ["get_inventory"], mode: "native", maxTurns: 20, shouldStop: () => nextOffset === null,
    fetchImpl: async (_input, init) => {
      const body = JSON.parse(String(init.body));
      const last = body.messages.filter((m: { role: string }) => m.role === "tool").at(-1);
      if (last) {
        assert.ok(last.content.length <= 16000);
        const page = JSON.parse(last.content);
        assert.equal(page.returned, page.screens.length);
        assert.ok(page.returned > 0);
        seen.push(...page.screens.map((sc: { screenId: string }) => sc.screenId));
        nextOffset = page.nextOffset;
        if (nextOffset === null) return Response.json({ choices: [{ message: { content: "Finished" } }] });
      }
      return actionResponse("native", "get_inventory", { offset: nextOffset });
    } });
  assert.deepEqual(seen, Array.from({ length: 60 }, (_, i) => screen(i + 1).screenId));
});

async function localServer(t: TestContext, handler: RequestListener) {
  const server = createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const address = server.address(); assert.ok(address && typeof address !== "string");
  return `http://127.0.0.1:${address.port}/`;
}

for (const encoding of ["ASCII", "multibyte"]) test(`JS recon revisits legacy ${encoding} prefixes and finds endpoints after 64 KiB`, async (t) => {
  const script = `/*${encoding === "ASCII" ? "x".repeat(96 * 1024) : "あ".repeat(32 * 1024)}*/fetch("/api/tail-only");`;
  const base = await localServer(t, (req, res) => {
    if (req.url === "/") res.end('<script src="/bundle.js"></script>');
    else if (req.url === "/bundle.js") res.end(script);
    else { res.statusCode = 404; res.end("nf"); }
  });
  const { s, store } = fixture(t, base);
  s.http = new FetchHttpClient({ allow: (u) => u.startsWith(base) });
  store.appendEvent("a-1", { type: "js_analyzed", payload: { url: `${base}bundle.js`, bytes: encoding === "ASCII" ? 65536 : 22000, endpointsFound: [], secretsFound: [], sourceMap: false, analyzedAt: new Date().toISOString() } });
  const analysis = await analyzePageJs(s, base);
  assert.equal(analysis.endpointsEnrolled, 1, JSON.stringify(analysis));
  assert.equal((await analyzePageJs(s, base)).analyzed, 0);
  assert.ok(s.inv.screens()[0]!.observedUrls[0]!.startsWith(base));
  const event = store.loadAssessment("a-1")!.events.filter((e) => e.type === "js_analyzed").at(-1)!;
  assert.equal(event.payload.complete, true); assert.equal(event.payload.bytes, Buffer.byteLength(script));
});

test("partial JS stays retryable until a complete analysis is persisted", async (t) => {
  const { s, store } = fixture(t);
  let partial = true;
  s.http = { send: async (req: HttpRequest) => ({ status: 200, finalUrl: req.url, durationMs: 1, headers: {}, body: req.url === BASE ? '<script src="/bundle.js"></script>' : 'fetch("/api/lead");', truncated: partial }) } as unknown as FetchHttpClient;
  await analyzePageJs(s, BASE);
  assert.equal(store.analyzedJsUrls("a-1").size, 0);
  partial = false;
  await analyzePageJs(s, BASE);
  assert.equal(store.analyzedJsUrls("a-1").size, 1);
});

test("an explicit planning turn limit pauses and resume writes only missing plans", async (t) => {
  modelEnv(t, "text");
  const { store, options } = fixture(t);
  for (let i = 1; i <= 8; i++) store.upsertScreen("a-1", screen(i));
  store.setPhase("a-1", "phase1_label");
  let phaseCalls = 0;
  let resumed = false;
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("No target calls in fixture"); });
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request) => {
    assert.match(String(input), /^http:\/\/model\.test\//);
    phaseCalls++;
    if (phaseCalls === 1) return actionResponse("text", "get_inventory", {});
    const state = store.loadAssessment("a-1")!;
    const planned = new Set(state.events.filter((e) => e.type === "methodology_recorded").map((e) => e.payload.screenId));
    const missing = state.screens.find((sc) => !planned.has(sc.screenId));
    if (missing) return actionResponse("text", "record_methodology", { screenId: missing.screenId, vulnClasses: [], plan: resumed ? "Resumed missing plan" : "Original plan" });
    if (!state.events.some((e) => e.type === "methodology_completed")) return actionResponse("text", "methodology_done", { summary: "All planned" });
    return actionResponse("text", "screen_done", { verdict: "clean", coverage: [] });
  });
  await runPilot({ ...options, maxTurns: 4, maxScreens: 8 });
  assert.equal(store.isPaused("a-1"), true);
  const before = store.loadAssessment("a-1")!;
  assert.equal(before.events.filter((e) => e.type === "methodology_recorded").length, 3);
  assert.ok(before.screenScans.every((sc) => sc.status === "queued"));
  phaseCalls = 0; resumed = true;
  await runPilot({ ...options, maxTurns: 30, maxScreens: 8 });
  const after = store.loadAssessment("a-1")!;
  assert.equal(store.isPaused("a-1"), false);
  const plans = after.events.filter((e) => e.type === "methodology_recorded");
  assert.equal(plans.length, 8);
  assert.equal(plans.filter((e) => e.payload.plan === "Original plan").length, 3);
});
