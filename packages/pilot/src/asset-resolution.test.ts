import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { Finding, Screen } from "@veritas/core";
import { FakeDriver, InventoryBuilder, PlaywrightDriver } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { FakeLlmClient } from "@veritas/llm";
import { enrollObservations, reviewAssets } from "./asset-review.js";
import { runPilot } from "./run.js";
import { buildTools, STAGE_TOOLS, type PilotSession } from "./tools.js";

const BASE = "http://app.test/";
const ASSET = `${BASE}main.js`;
const SCREEN: Screen = {
  screenId: "s-0001", urlTemplate: "/", observedUrls: [BASE], authState: "unauth",
  screenType: "dashboard", description: "", params: [], apis: [], screenshot: "",
  domSkeletonHash: "h", labels: [],
};

function fixture(): { s: PilotSession; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "verdict-asset-resolution-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl(BASE) });
  store.upsertScreen("a-1", SCREEN);
  const inv = new InventoryBuilder();
  inv.seed([SCREEN]);
  const s = {
    http: new FetchHttpClient({ allow: () => false }),
    store, assessmentId: "a-1", artifactsDir: join(dir, "art"),
    evidence: new EvidenceStore(join(dir, "art")), inv,
    scope: deriveScopeFromSingleUrl(BASE), targetUrl: BASE,
    currentScreenId: null, currentCookie: "", currentBearer: "", currentRole: "",
    roleCreds: new Map(), roleCookieFiles: new Map(), roleDescriptions: new Map(),
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
  return { s, dir };
}

async function call(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const def = buildTools(s).find((t) => t.name === name)!;
  const result = await def.handler(args as never, {} as never);
  const first = result.content[0];
  return first?.type === "text" ? first.text : "";
}

async function enroll(s: PilotSession): Promise<[string, string]> {
  const out = await reviewAssets({
    session: s, llm: new FakeLlmClient(JSON.stringify({ observations: [
      { type: "credential", detail: "candidate A" },
      { type: "credential", detail: "candidate B" },
    ] })),
    assets: [{ url: ASSET, kind: "js", body: "const demo = true;", bytes: 18, truncated: false }],
  });
  enrollObservations(s, out.observations);
  return [s.pendingAssetObs![0]!.checkId, s.pendingAssetObs![1]!.checkId];
}

function fakeHttp(s: PilotSession, mock: { method: (obj: object, name: string, fn: (...args: never[]) => unknown) => unknown }): void {
  mock.method(s.http, "send", async () => ({
    status: 200, body: "not a live credential", headers: { "content-type": "text/plain" },
    finalUrl: ASSET, durationMs: 1,
  }));
}

async function fetchAsset(s: PilotSession): Promise<string> {
  const result = JSON.parse(await call(s, "http_request", { method: "GET", url: ASSET })) as { evidenceId: string };
  return result.evidenceId;
}

async function testedClean(s: PilotSession): Promise<string[]> {
  const result = JSON.parse(await call(s, "compose_check", {
    checkClass: "secret-exposure", target: "GET /verify",
    legs: [
      { kind: "control", url: `${BASE}verify`, method: "GET" },
      { kind: "attack", url: `${BASE}verify`, method: "GET" },
    ],
    expect: { controlMustDeny: true },
  })) as { checkStatus: string; evidenceIds: { control: string[]; attack: string[] } };
  assert.equal(result.checkStatus, "tested-clean");
  return [...result.evidenceIds.control, ...result.evidenceIds.attack];
}

test("an unrelated clean probe cannot refute either of two JS leads", async (t) => {
  const { s, dir } = fixture();
  fakeHttp(s, t.mock);
  try {
    assert.ok(STAGE_TOOLS.diagnose.includes("resolve_asset_review" as never), "completion diagnosis exposes resolution");
    const [first, second] = await enroll(s);
    const original = s.store.checks("a-1").find((c) => c.id === first)!;
    const fetchId = await fetchAsset(s);
    const probeIds = await testedClean(s);
    const response = await call(s, "resolve_asset_review", {
      n: 1, verdict: "refuted", reason: "untrusted text", evidenceIds: [fetchId, ...probeIds],
    });
    assert.match(response, /unverified/);
    const checks = s.store.checks("a-1").filter((c) => c.checkClass === "asset-review");
    assert.equal(checks.length, 2);
    const resolved = checks.find((c) => c.id === first)!;
    assert.equal(resolved.status, "unverified");
    assert.deepEqual(resolved.evidenceIds, [fetchId, ...probeIds]);
    for (const dimension of ["id", "screenId", "target", "resource", "subject", "principal", "tenant", "origin", "session", "param", "detail"] as const)
      assert.deepEqual(resolved[dimension], original[dimension], dimension);
    assert.equal(checks.find((c) => c.id === second)!.status, "planned");
    const events = s.store.loadAssessment("a-1")!.events.filter((e) =>
      e.type === "check_recorded" && e.payload.check.id === first);
    assert.equal(events.length, 2, "planned + exact-row outcome; both append-only");
    assert.match(await call(s, "resolve_asset_review", {
      n: 1, verdict: "refuted", evidenceIds: [fetchId, ...probeIds],
    }), /no new evidence/);
    assert.equal(s.store.loadAssessment("a-1")!.events.filter((e) =>
      e.type === "check_recorded" && e.payload.check.id === first).length, 2, "no repeated event without new evidence");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("checkId resolves after fresh session/reopen even with a different login; no in-memory pending list", async (t) => {
  const { s, dir } = fixture();
  fakeHttp(s, t.mock);
  let reopened: AssessmentStore | undefined;
  try {
    const [first, second] = await enroll(s);
    const assetId = await fetchAsset(s);
    const tested = await testedClean(s);
    s.store.close();
    reopened = AssessmentStore.open(join(dir, "state.sqlite"));
    const resumed = {
      ...s, store: reopened, evidence: new EvidenceStore(join(dir, "art")),
      pendingAssetObs: undefined, currentScreenId: SCREEN.screenId,
      currentRole: "admin", currentBearer: "synthetic-rotated-session",
    } as PilotSession;
    const response = await call(resumed, "resolve_asset_review", {
      checkId: first, verdict: "refuted", evidenceIds: [assetId, ...tested],
    });
    assert.match(response, /unverified/);
    assert.equal(reopened.checks("a-1").find((c) => c.id === first)!.status, "unverified");
    assert.equal(reopened.checks("a-1").find((c) => c.id === second)!.status, "planned");
    assert.equal(reopened.checks("a-1").filter((c) => c.checkClass === "asset-review").length, 2);
  } finally {
    reopened?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("no evidence or a duplicate never silently becomes clean; model reason/summary never persist", async (t) => {
  const { s, dir } = fixture();
  fakeHttp(s, t.mock);
  try {
    const [first, second] = await enroll(s);
    const marker = ["private", "credential", Date.now().toString(36)].join("-");
    const noEvidence = await call(s, "resolve_asset_review", { checkId: first, verdict: "refuted", reason: marker });
    assert.match(noEvidence, /unverified/);
    const assetId = await fetchAsset(s);
    assert.match(await call(s, "resolve_asset_review", {
      checkId: first, verdict: "refuted", evidenceIds: [assetId],
    }), /unverified/, "an HTTP asset fetch alone does not prove the observation false");
    assert.match(await call(s, "resolve_asset_review", {
      checkId: first, verdict: "refuted", evidenceIds: [assetId, "ev-fabricated-1"],
    }), /unverified/, "a fabricated evidence ID cannot clear a lead");
    assert.deepEqual(s.store.checks("a-1").find((c) => c.id === first)!.evidenceIds, [assetId]);
    const duplicate = await call(s, "resolve_asset_review", {
      checkId: second, verdict: "not-applicable", reason: marker, evidenceIds: [assetId],
    });
    assert.match(duplicate, /unverified/);
    assert.equal(s.store.checks("a-1").find((c) => c.id === second)!.status, "unverified");
    assert.equal(s.store.checks("a-1").filter((c) => c.checkClass === "asset-review" && c.status === "tested-clean").length, 0);
    s.currentScreenId = SCREEN.screenId;
    assert.match(await call(s, "screen_done", { verdict: "clean",
      coverage: [{ class: "asset-review", result: "not-applicable", note: marker }], note: marker }),
    /NOT DONE/, "generic screen completion cannot declare an asset lead clean or persist prose");
    s.currentScreenId = null;
    await call(s, "asset_review_done", { summary: marker });
    for (const persisted of [s.store.loadAssessment("a-1")!.events, s.store.checks("a-1")])
      assert.equal(JSON.stringify(persisted).includes(marker), false, "no secret in events/notes/checks");
    assert.equal(noEvidence.includes(marker) || duplicate.includes(marker), false, "no secret echoed into tool response");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("foreign/out-of-scope/wrong-class/wrong-screen checkIds are refused without ledger changes", async () => {
  const { s, dir } = fixture();
  try {
    const [first] = await enroll(s);
    enrollObservations(s, [{ url: "http://foreign.test/secret.js", type: "credential", detail: "lead" }]);
    const outOfScope = s.pendingAssetObs![0]!.checkId;
    s.store.createAssessment({ id: "a-2", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl(BASE) });
    const other = { ...s, assessmentId: "a-2" } as PilotSession;
    enrollObservations(other, [{ url: `${BASE}other.js`, type: "credential", detail: "lead" }]);
    const foreign = other.pendingAssetObs![0]!.checkId;
    const wrongClass = { ...s.store.checks("a-1").find((c) => c.id === first)!, checkClass: "other" };
    wrongClass.id = JSON.stringify(["wrong-class"]); // not an enrolled row, even if it exists in the store
    s.store.upsertCheck("a-1", wrongClass);
    const count = s.store.loadAssessment("a-1")!.events.length;
    for (const id of [outOfScope, foreign, wrongClass.id, "random-check-id"]) {
      assert.match(await call(s, "resolve_asset_review", { checkId: id, verdict: "unverified" }), /Rejected/);
    }
    s.currentScreenId = "s-9999";
    assert.match(await call(s, "resolve_asset_review", { checkId: first, verdict: "unverified" }), /Rejected/);
    s.currentScreenId = null;
    assert.match(await call(s, "resolve_asset_review", { n: 1, checkId: first, verdict: "unverified" }), /Rejected/,
      "a conflicting n + checkId cannot select another lead");
    assert.equal(s.store.loadAssessment("a-1")!.events.length, count);
    assert.equal(s.store.checks("a-1").find((c) => c.id === first)!.status, "planned");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("verified requires a confirmed persisted finding about this asset, not a supplied ID or suspected lead", async (t) => {
  const { s, dir } = fixture();
  fakeHttp(s, t.mock);
  try {
    const [first, second] = await enroll(s);
    const assetId = await fetchAsset(s);
    const evidence = [0, 1, 2].map((i) => s.evidence.record({
      screenId: "pilot", validator: "claude-pilot", kind: i ? "positive_replay" : "negative_control",
      request: { method: "GET", url: `${BASE}verify`, headers: {}, body: null },
      response: { status: i ? 200 : 404, headers: {}, body: i ? "proof" : "absent", finalUrl: `${BASE}verify`, durationMs: 1 },
      note: "synthetic test evidence",
    }).id);
    const f: Finding = { id: "f-001", screenId: null, verdict: "suspected", title: "test", severity: "medium",
      description: `Recorded lead for ${ASSET}`, reproSteps: "synthetic",
      source: { kind: "validator", validatorName: "claude-pilot" }, evidenceIds: evidence,
      scopeBasis: "authorized test" };
    s.store.upsertFinding("a-1", f);
    assert.match(await call(s, "resolve_asset_review", {
      checkId: first, verdict: "verified", findingId: f.id, evidenceIds: [assetId],
    }), /unverified/);
    s.store.upsertFinding("a-1", { ...f, verdict: "confirmed", description: `A finding about ${BASE}other.js` });
    assert.match(await call(s, "resolve_asset_review", {
      checkId: first, verdict: "verified", findingId: f.id, evidenceIds: [assetId],
    }), /unverified/, "an unrelated confirmed finding is not evidence for this asset");
    s.store.upsertFinding("a-1", { ...f, verdict: "confirmed" });
    assert.match(await call(s, "resolve_asset_review", {
      checkId: first, verdict: "verified", findingId: f.id, evidenceIds: [assetId],
    }), /found/);
    const resolved = s.store.checks("a-1").find((c) => c.id === first)!;
    assert.deepEqual(resolved.findingIds, [f.id]);
    assert.deepEqual(resolved.evidenceIds, [assetId, ...evidence]);
    assert.match(await call(s, "resolve_asset_review", {
      checkId: second, verdict: "verified", findingId: f.id, evidenceIds: [assetId],
    }), /unverified/, "one recorded finding cannot clear another asset-review lead");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("completion-only resume asks for the persisted checkId and scoped refetch, not old model prose", async (t) => {
  const env = {
    VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://model.test/v1",
    VERDICT_LLM_MODEL: "deep", VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_TOOL_MODE: "native",
  };
  const previous = Object.fromEntries(Object.keys(env).map((key) => [key, process.env[key]]));
  Object.assign(process.env, env);
  const { s, dir } = fixture();
  const driver = Object.assign(new FakeDriver({}), { sessionCookieHeader: async () => "", bearerToken: async () => null });
  t.mock.method(PlaywrightDriver, "launch", async () => driver as unknown as PlaywrightDriver);
  t.mock.method(FetchHttpClient.prototype, "send", async () => { throw new Error("Target traffic not allowed"); });
  const prompts: string[] = [];
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    assert.match(String(input), /^http:\/\/model\.test\//, "no real LLM or target contacted");
    const body = JSON.parse(String(init?.body)) as { messages: Array<{ content: string }> };
    prompts.push(body.messages[1]!.content);
    return Response.json({ choices: [{ message: { role: "assistant", content: "No safe action available" } }] });
  });
  try {
    const [checkId] = await enroll(s);
    const secret = ["synthetic", "secret", Date.now().toString(36)].join("-");
    const row = s.store.checks("a-1").find((c) => c.id === checkId)!;
    s.store.upsertCheck("a-1", { ...row, reason: secret, detail: secret });
    s.store.appendEvent("a-1", { type: "methodology_recorded",
      payload: { screenId: SCREEN.screenId, vulnClasses: [], plan: "no extra plan" } });
    s.store.appendEvent("a-1", { type: "methodology_completed", payload: { screenIds: [SCREEN.screenId], summary: "ready" } });
    s.store.setScreenScanStatus("a-1", SCREEN.screenId, "clean");
    s.store.setPhase("a-1", "report");
    await runPilot({
      store: s.store, assessmentId: "a-1", targetUrl: BASE, scope: s.scope,
      profileDir: join(dir, "profile"), artifactsDir: s.artifactsDir, roleCreds: new Map(),
      resume: true, assetReview: false, scenarioPass: false, fingerprintPass: false,
      completionPasses: 1, maxTurns: 1, maxScreens: 1, keepAliveMinutes: 0,
    });
    assert.ok(prompts.some((p) => p.includes(`checkId=${checkId}`)));
    assert.ok(prompts.some((p) => p.includes("scoped http_request(GET)") && p.includes("resolve_asset_review(checkId")));
    assert.ok(prompts.every((p) => !p.includes(secret)));
    assert.equal(s.store.checks("a-1").find((c) => c.id === checkId)!.status, "planned");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
    for (const [key, value] of Object.entries(previous)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
  }
});
