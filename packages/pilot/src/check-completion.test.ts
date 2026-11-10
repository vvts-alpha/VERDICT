import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, checkKey, deriveScopeFromSingleUrl } from "@veritas/core";
import type { CheckExecution, CheckStatus, Screen } from "@veritas/core";
import { FakeDriver, PlaywrightDriver } from "@veritas/crawler";
import { FetchHttpClient } from "@veritas/scanner";
import { completionProgress, completionWork, runPilot } from "./run.js";

const url = "https://app.test/account";
const screen = {
  screenId: "s-0001", urlTemplate: url, observedUrls: [url], authState: "unauth",
  screenType: "detail", description: "Static", params: [], apis: [], screenshot: "",
  domSkeletonHash: "h", labels: [],
} as Screen;

function row(n: number, status: CheckStatus = "planned"): CheckExecution {
  const data: CheckExecution = {
    id: "", screenId: screen.screenId, target: "GET /account", param: `p${String(n).padStart(2, "0")}`,
    subject: "", checkClass: "sqli", status, tool: status === "planned" ? "record_methodology" : "probe_sqli",
    ...(status === "blocked" || status === "unverified" ? { reason: "failed baseline" } : {}),
    evidenceIds: [], findingIds: [], updatedAt: new Date(0).toISOString(),
  };
  data.id = checkKey(data);
  return data;
}

test("completion startup snapshots all >20 planned/gap identities, chunked once each", () => {
  const slots = Array.from({ length: 45 }, (_, i) => row(i));
  const gap = row(45, "blocked");
  const rawTraffic = { ...row(46, "unverified"), checkClass: "http-request" };
  rawTraffic.id = checkKey(rawTraffic);
  const work = completionWork([screen], [...slots, gap, rawTraffic]);
  assert.deepEqual(work.batches.map((b) => b.checks.length), [20, 20, 6]);
  assert.equal(work.unresolved.size, 46, "traffic observations never create retries");
  assert.deepEqual(new Set(work.batches.flatMap((b) => b.checks.map((c) => c.id))), work.unresolved);
});

test("completion projects an indexed ledger once per screen, even with 200 screens / 8000 rows", () => {
  const screens = Array.from({ length: 200 }, (_, i) => ({ ...screen, screenId: `s-${String(i).padStart(4, "0")}` }));
  let screenIdReads = 0;
  const rows = screens.flatMap((sc) => Array.from({ length: 40 }, (_, i) => {
    const check = { ...row(i, i === 39 ? "blocked" : "planned"), screenId: sc.screenId };
    check.id = checkKey(check);
    Object.defineProperty(check, "screenId", {
      get: () => { screenIdReads++; return sc.screenId; },
    });
    return check;
  }));
  const work = completionWork(screens, rows);
  assert.equal(rows.length, 8000);
  assert.equal(work.unresolved.size, 8000);
  assert.equal(work.batches.length, 400);
  assert.deepEqual(work.batches.map((b) => b.checks.length), Array(400).fill(20));
  assert.deepEqual(new Set(work.batches.flatMap((b) => b.checks.map((c) => c.id))), work.unresolved);
  assert.ok(screenIdReads < rows.length * 8, `per-screen aggregation must not scan all rows: ${screenIdReads} reads`);

  const updated = { ...rows[40]!, status: "tested-clean" as const };
  const added = { ...row(40), screenId: screens[1]!.screenId };
  added.id = checkKey(added);
  const next = completionWork(screens, [...rows.slice(0, 40), updated, ...rows.slice(41), added]);
  const progress = completionProgress(work.unresolved, next.unresolved);
  assert.equal(progress.resolved, 1);
  assert.deepEqual([...progress.added], [added.id]);
  assert.equal(next.unresolved.size, 8000, "equal total can still include a resolved and newly enrolled identity");
  assert.equal(next.batches.flatMap((b) => b.checks).some((c) => c.id === updated.id), false);
  assert.equal(next.batches.flatMap((b) => b.checks).filter((c) => c.id === added.id).length, 1);
  assert.equal(completionProgress(next.unresolved, next.unresolved).continue, false);
});

test("completion concurrent additions with equal aggregate count still count as progress; no-progress stops", () => {
  const start = completionWork([screen], [row(1), row(2), row(3)]);
  const swapped = completionWork([screen], [row(1, "tested-clean"), row(2), row(3), row(4)]);
  assert.equal(start.unresolved.size, swapped.unresolved.size);
  const progress = completionProgress(start.unresolved, swapped.unresolved);
  assert.equal(progress.resolved, 1);
  assert.deepEqual([...progress.added], [row(4).id]);
  assert.equal(progress.continue, true);
  assert.equal(progress.retry, undefined, "real progress allows a second bounded attempt at remaining gaps");
  assert.equal(completionProgress(swapped.unresolved, swapped.unresolved).continue, false, "no endless repeats");
});

test("completion teardown/restart re-reads ledger; additions alone do not retry unchanged tasks", () => {
  const first = completionWork([screen], [row(1, "unverified"), row(2)]);
  const restarted = completionWork([screen], [row(1, "unverified"), row(2), row(3)]);
  const progress = completionProgress(first.unresolved, restarted.unresolved);
  assert.equal(progress.resolved, 0);
  assert.deepEqual([...progress.added], [row(3).id]);
  assert.deepEqual(completionWork([screen], [row(1, "unverified"), row(2), row(3)], progress.retry).batches
    .flatMap((batch) => batch.checks.map((check) => check.id)), [row(3).id]);
  assert.equal(completionProgress(restarted.unresolved, restarted.unresolved).continue, false);
});

test("completion-only report resume visits all 45 slots, never fabricates a verdict or target request", async (t) => {
  const env = {
    VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1",
    VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native",
  };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-check-completion-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("Target traffic not allowed"); });
  const prompts: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.match(String(input), /^http:\/\/model\.test\//, "only the mocked model is contacted");
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    prompts.push(body.messages[1]!.content);
    return Response.json({ choices: [{ message: { role: "assistant", content: "No safe action available" } }] });
  });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    store.upsertScreen("a-1", screen);
    store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: screen.screenId, vulnClasses: ["sqli"], plan: "check every parameter" } });
    store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: [screen.screenId], summary: "ready" } });
    for (let i = 0; i < 45; i++) store.upsertCheck("a-1", row(i));
    // A historical terminal scan status must not hide the still-planned ledger on report resume.
    store.setScreenScanStatus("a-1", screen.screenId, "clean");
    store.setPhase("a-1", "report");
    await runPilot({
      store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"),
      roleCreds: new Map(), resume: true, // report-only recovery must not re-buy scenario, fingerprint or asset-review
      completionPasses: 2, maxTurns: 1, maxScreens: 1, keepAliveMinutes: 0,
    });
    assert.equal(prompts.length, 3, "two passes do not repeat unchanged slots");
    for (let i = 0; i < 45; i++) {
      assert.equal(prompts.filter((p) => p.includes(`param:p${String(i).padStart(2, "0")}`)).length, 1);
    }
    assert.ok(prompts.every((p) => p.includes("Do NOT issue unsafe state-changing requests")));
    assert.equal(store.checks("a-1").filter((c) => c.status === "planned").length, 45);
    assert.equal(store.loadAssessment("a-1")!.screenScans[0]!.status, "queued", "turn cap never launders the ledger clean");
    assert.equal(store.isPaused("a-1"), false);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test("completion concurrent addition mid-pass gets next pass, not a drain retry of the unchanged slot", async (t) => {
  const env = {
    VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1",
    VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native",
  };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-check-addition-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("Target traffic not allowed"); });
  const prompts: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.match(String(input), /^http:\/\/model\.test\//);
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    prompts.push(body.messages[1]!.content);
    if (prompts.length === 1) store.upsertCheck("a-1", row(99)); // another worker discovers a slot during this pass
    return Response.json({ choices: [{ message: { role: "assistant", content: "No safe action available" } }] });
  });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    store.upsertScreen("a-1", screen);
    store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: screen.screenId, vulnClasses: ["sqli"], plan: "review params" } });
    store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: [screen.screenId], summary: "ready" } });
    store.upsertCheck("a-1", row(1));
    store.setScreenScanStatus("a-1", screen.screenId, "clean");
    store.setPhase("a-1", "report");
    await runPilot({
      store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"),
      roleCreds: new Map(), resume: true, scenarioPass: false, fingerprintPass: false, assetReview: false,
      completionPasses: 8, maxTurns: 1, maxScreens: 1, keepAliveMinutes: 0,
    });
    assert.equal(prompts.length, 2, "new row warrants a pass, but the unchanged one is not re-driven");
    assert.match(prompts[0]!, /param:p01/);
    assert.doesNotMatch(prompts[1]!, /param:p01/);
    assert.match(prompts[1]!, /param:p99/);
    assert.equal(store.loadAssessment("a-1")!.screenScans[0]!.status, "queued");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test("completion skips a later batch whose check another worker resolved after the pass snapshot", async (t) => {
  const env = {
    VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1",
    VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native",
  };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-check-stale-batch-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("Target traffic not allowed"); });
  const second = { ...screen, screenId: "s-0002" };
  const later = { ...row(2), screenId: second.screenId };
  later.id = checkKey(later);
  const prompts: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.match(String(input), /^http:\/\/model\.test\//);
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    prompts.push(body.messages[1]!.content);
    if (prompts.length === 1) store.upsertCheck("a-1", { ...later, status: "tested-clean", tool: "probe_sqli" });
    return Response.json({ choices: [{ message: { role: "assistant", content: "No safe action available" } }] });
  });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    for (const sc of [screen, second]) {
      store.upsertScreen("a-1", sc);
      store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: sc.screenId, vulnClasses: ["sqli"], plan: "review params" } });
      store.setScreenScanStatus("a-1", sc.screenId, "clean");
    }
    store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: [screen.screenId, second.screenId], summary: "ready" } });
    store.upsertCheck("a-1", row(1));
    store.upsertCheck("a-1", later);
    store.setPhase("a-1", "report");
    await runPilot({
      store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"),
      roleCreds: new Map(), resume: true, scenarioPass: false, fingerprintPass: false, assetReview: false,
      completionPasses: 1, maxTurns: 1, maxScreens: 1, keepAliveMinutes: 0,
    });
    assert.equal(prompts.length, 1, "a resolved screen must not consume a diagnosis stage");
    assert.match(prompts[0]!, /on screen s-0001/);
    assert.equal(store.checks("a-1").find((c) => c.id === later.id)!.status, "tested-clean");
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});

test("completion visits every screen and batch, sees updated rows, and defers new slots to one bounded next pass", async (t) => {
  const env = {
    VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1",
    VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native",
  };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const dir = mkdtempSync(join(tmpdir(), "verdict-check-many-screens-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  const scope = deriveScopeFromSingleUrl(url);
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("Target traffic not allowed"); });
  const prompts: string[] = [];
  const texts: string[] = [];
  const screens = Array.from({ length: 25 }, (_, i) => ({ ...screen, screenId: `s-${String(i).padStart(4, "0")}` }));
  const slot = (sc: Screen, n: number) => {
    const check = { ...row(n), screenId: sc.screenId };
    check.id = checkKey(check);
    return check;
  };
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.match(String(input), /^http:\/\/model\.test\//);
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    prompts.push(body.messages[1]!.content);
    if (prompts.length === 1) {
      store.upsertCheck("a-1", { ...slot(screens[1]!, 0), detail: "UPDATED BY ANOTHER WORKER" });
      store.upsertCheck("a-1", slot(screens[24]!, 99));
    }
    return Response.json({ choices: [{ message: { role: "assistant", content: "No safe action available" } }] });
  });
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url, followLinks: true, maxDepth: 2 }, scope });
    for (const sc of screens) {
      store.upsertScreen("a-1", sc);
      store.upsertCheck("a-1", slot(sc, 0));
      store.setScreenScanStatus("a-1", sc.screenId, "clean");
      store.appendEvent("a-1", { type: "methodology_recorded", payload: { screenId: sc.screenId, vulnClasses: ["sqli"], plan: "review params" } });
    }
    store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: screens.map((sc) => sc.screenId), summary: "ready" } });
    for (let i = 1; i <= 20; i++) store.upsertCheck("a-1", slot(screens[0]!, i));
    store.setPhase("a-1", "report");
    let fullLoads = 0;
    const load = store.loadAssessment.bind(store);
    t.mock.method(store, "loadAssessment", (...args: Parameters<AssessmentStore["loadAssessment"]>) => {
      fullLoads++;
      return load(...args);
    });
    const result = await runPilot({
      store, assessmentId: "a-1", targetUrl: url, scope, profileDir: join(dir, "profile"), artifactsDir: join(dir, "artifacts"),
      roleCreds: new Map(), resume: true, scenarioPass: false, fingerprintPass: false, assetReview: false,
      completionPasses: 8, maxTurns: 1, maxScreens: 1, keepAliveMinutes: 0,
      onText: (text) => texts.push(text),
    });
    assert.equal(prompts.length, 27, `26 frozen first-pass batches and only the new slot on pass two; ${result.summary}; ${texts.join(" | ")}`);
    assert.equal(prompts.filter((p) => p.includes("param:p99")).length, 1);
    assert.equal(prompts.filter((p) => p.includes("param:p00")).length, 25);
    for (const sc of screens) assert.ok(prompts.some((p) => p.includes(`on screen ${sc.screenId}`)), sc.screenId);
    assert.match(prompts.find((p) => p.includes(`on screen ${screens[1]!.screenId}`))!, /UPDATED BY ANOTHER WORKER/);
    assert.ok(fullLoads < 20, `completion must not reload all assessment events per batch (${fullLoads} loads)`);
    assert.equal(store.checks("a-1").filter((c) => c.status === "planned").length, 46);
  } finally {
    store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
