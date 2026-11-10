import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { FakeLlmClient } from "@veritas/llm";
import { FakeHttpClient } from "@veritas/scanner";
import { assetObservationResource, collectAssets, enrollObservations, reviewAssets, safeAssetUrl, type FetchedAsset } from "./asset-review.js";
import type { PilotSession } from "./tools.js";

const BASE = "http://app.test/";

function session(extra: Partial<PilotSession> = {}): { s: PilotSession; store: AssessmentStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "verdict-assetrev-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  const s = {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(BASE.replace(/\/$/, "")) }),
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "art")),
    inv: new InventoryBuilder(),
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    currentScreenId: null,
    currentCookie: "",
    currentBearer: "",
    currentRole: "",
    roleCreds: new Map(),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    ...extra,
  } as unknown as PilotSession;
  return { s, store, dir };
}

const asset = (body: string, kind: "html" | "js" = "js", url = `${BASE}main.js`): FetchedAsset => ({ url, kind, body, bytes: Buffer.byteLength(body), truncated: false });

test("reviewAssets sends EVERY chunk of the body to the model and marks full coverage", async () => {
  const { s, store, dir } = session();
  try {
    const body = `// ${"x".repeat(30_000)} creds here ` + "y".repeat(30_000); // >1 chunk
    const llm = new FakeLlmClient('{"observations":[{"type":"credential","detail":"candidate login","evidence":"synthetic candidate"}]}');
    const out = await reviewAssets({ session: s, llm, assets: [asset(body)] });
    assert.ok(llm.calls.length >= 2, `every chunk sent (got ${llm.calls.length})`);
    const sent = llm.calls.map((c) => c.prompt.length).reduce((a, b) => a + b, 0);
    assert.ok(sent >= body.length, "the whole body was covered by chunks");
    const review = out.reviews[0]!;
    assert.equal(review.chunksAnalyzed, review.chunksTotal);
    assert.equal(review.complete, true);
    assert.equal(out.observations.length, llm.calls.length, "each chunk's observation collected");
    const events = store.loadAssessment("a-1")!.events.filter((e) => e.type === "asset_reviewed");
    assert.equal(events.length, 1);
  } finally {
    try { s.store.close(); } catch { /* */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a chunk the model never answered keeps the asset INCOMPLETE — not laundered into clean", async () => {
  const { s, dir } = session();
  try {
    const body = "a".repeat(60_000); // 3 chunks at 24k
    let n = 0;
    const llm = new FakeLlmClient(() => {
      n += 1;
      if (n === 2) throw new Error("model down");
      return '{"observations":[]}';
    });
    const out = await reviewAssets({ session: s, llm, assets: [asset(body)] });
    const review = out.reviews[0]!;
    assert.equal(review.chunksTotal, 3);
    assert.equal(review.chunksAnalyzed, 2);
    assert.equal(review.complete, false, "unreviewed coverage stays visible");
  } finally {
    try { s.store.close(); } catch { /* */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a truncated fetch is never complete even when all chunks were analyzed", async () => {
  const { s, dir } = session();
  try {
    const a = { ...asset("short body"), truncated: true };
    const out = await reviewAssets({ session: s, llm: new FakeLlmClient('{"observations":[]}'), assets: [a] });
    assert.equal(out.reviews[0]!.fetchedComplete, false);
    assert.equal(out.reviews[0]!.complete, false);
  } finally {
    try { s.store.close(); } catch { /* */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("an empty asset has no analyzed chunks and cannot claim a clean review", async () => {
  const { s, dir } = session();
  try {
    const out = await reviewAssets({ session: s, llm: new FakeLlmClient('{"observations":[]}'), assets: [asset("")] });
    assert.equal(out.reviews[0]!.chunksTotal, 0);
    assert.equal(out.reviews[0]!.complete, false);
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("enrollObservations writes safe planned asset-review checks consumable by the completion pass", () => {
  const { s, store, dir } = session();
  try {
    s.inv.seed([{ screenId: "s-0001", urlTemplate: "/", observedUrls: [BASE], authState: "unauth", screenType: "dashboard", description: "", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] }]);
    enrollObservations(s, [{ url: `${BASE}main.js`, type: "credential", detail: "candidate credentials", status: "pending" }]);
    assert.equal(s.pendingAssetObs?.length, 1);
    const checks = store.checks("a-1").filter((c) => c.checkClass === "asset-review" && c.status === "planned");
    assert.equal(checks.length, 1);
    assert.equal(checks[0]!.screenId, "s-0001", "relative screen template owns same-origin JS");
    assert.match(checks[0]!.detail ?? "", /inspect the authorized asset/);
  } finally {
    try { s.store.close(); } catch { /* */ }
    rmSync(dir, { recursive: true, force: true });
  }
});

test("two leads in one JS asset get distinct stable check IDs; resolving one leaves the other planned", async () => {
  const { s, store, dir } = session();
  try {
    s.inv.seed([{ screenId: "s-0001", urlTemplate: "/", observedUrls: [BASE], authState: "unauth", screenType: "dashboard", description: "", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] }]);
    const llm = new FakeLlmClient(JSON.stringify({ observations: [
      { type: "credential", detail: "first candidate" },
      { type: "credential", detail: "second candidate" },
    ] }));
    const out = await reviewAssets({ session: s, llm, assets: [asset("const x = 1;")] });
    enrollObservations(s, out.observations);
    const checks = store.checks("a-1").filter((c) => c.checkClass === "asset-review");
    assert.equal(checks.length, 2);
    assert.notEqual(checks[0]!.id, checks[1]!.id);
    assert.notEqual(s.pendingAssetObs![0]!.checkId, s.pendingAssetObs![1]!.checkId);
    assert.equal(checks[0]!.screenId, "s-0001");
    assert.equal(checks[1]!.screenId, "s-0001");
    for (const [i, entry] of s.pendingAssetObs!.entries()) {
      assert.equal(store.checks("a-1").find((c) => c.id === entry.checkId)!.resource, assetObservationResource(entry.obs, i));
    }

    // Simulate the resolver updating just one exact row (tools.ts must use the same resource key).
    const first = checks[0]!;
    store.upsertCheck("a-1", { ...first, status: "tested-clean", reason: "verified negative", updatedAt: new Date().toISOString() });
    const remaining = store.checks("a-1").filter((c) => c.checkClass === "asset-review" && c.status === "planned");
    assert.equal(remaining.length, 1);
    assert.equal(remaining[0]!.id, checks[1]!.id);
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("relative templates map first-party JS to an in-scope observed screen, never a foreign origin", () => {
  const { s, store, dir } = session();
  try {
    const screen = (screenId: string, urlTemplate: string, observedUrls: string[]) =>
      ({ screenId, urlTemplate, observedUrls, authState: "unauth" as const, screenType: "dashboard" as const,
        description: "", params: [], apis: [], screenshot: "", domSkeletonHash: screenId, labels: [] });
    s.inv.seed([
      screen("s-0001", "https://foreign.test/", ["https://foreign.test/"]),
      screen("s-0002", "/", [BASE]),
    ]);
    enrollObservations(s, [
      { url: `${BASE}main.js`, type: "endpoint", detail: "candidate route" },
      { url: "https://foreign.test/main.js", type: "endpoint", detail: "out of scope" },
    ]);
    assert.equal(s.pendingAssetObs![0]!.screenId, "s-0002");
    assert.equal(s.pendingAssetObs![1]!.screenId, "pilot");
    assert.equal(store.checks("a-1").find((c) => c.id === s.pendingAssetObs![0]!.checkId)!.screenId, "s-0002");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a same-origin asset outside the authorized path prefix is never assigned to an in-scope screen", () => {
  const { s, dir } = session({ targetUrl: `${BASE}allowed/`,
    scope: { ...deriveScopeFromSingleUrl(BASE), inScopePathPrefixes: ["/allowed/"] } });
  try {
    s.inv.seed([{ screenId: "s-0001", urlTemplate: "/allowed/", observedUrls: [`${BASE}allowed/`],
      authState: "unauth", screenType: "dashboard", description: "", params: [], apis: [],
      screenshot: "", domSkeletonHash: "h", labels: [] }]);
    enrollObservations(s, [{ url: `${BASE}private/main.js`, type: "endpoint", detail: "candidate" }]);
    assert.equal(s.pendingAssetObs![0]!.screenId, "pilot");
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("collectAssets discovers JS from an observed absolute page even with a relative template; no network", async () => {
  const http = new FakeHttpClient((req) => ({
    status: 200,
    body: req.url === BASE ? '<html><script src="/main.js"></script></html>' : "const candidate = true;",
  }));
  const { s, dir } = session({ http: http as unknown as PilotSession["http"] });
  try {
    s.inv.seed([{ screenId: "s-0001", urlTemplate: "/", observedUrls: [BASE], authState: "unauth", screenType: "dashboard", description: "", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] }]);
    const { assets } = await collectAssets(s);
    assert.deepEqual(assets.map((a) => [a.url, a.kind]), [[BASE, "html"], [`${BASE}main.js`, "js"]]);
    assert.equal(http.sent.length, 2);
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("model text, asset URL secrets and skipped URL parameters never enter events, check details or follow-up input", async () => {
  const { s, store, dir } = session();
  try {
    // Synthetic runtime canary, not a real credential; construct rather than copying a secret fixture.
    const marker = ["asset", "review", "canary", Date.now().toString(36)].join("-");
    const url = `http://user:${marker}@app.test/main.js?opaque=${marker}#${marker}`;
    const llm = new FakeLlmClient(JSON.stringify({ observations: [{
      type: "secret", detail: `key ${marker}`, evidence: marker,
      location: `near ${marker}`, investigation: `send ${marker} to endpoint`,
    }] }));
    const lines: string[] = [];
    const out = await reviewAssets({
      session: s, llm, assets: [asset(`const key = "${marker}";`, "js", url)],
      skipped: [`${BASE}second.js?opaque=${marker}`], onText: (line) => lines.push(line),
    });
    enrollObservations(s, out.observations);
    assert.equal(out.reviews[0]!.url, `${BASE}main.js`);
    assert.equal(out.observations[0]!.evidence, undefined);
    assert.equal(out.observations[0]!.location, "chunk 1, observation 1, char 13");
    assert.equal(llm.calls[0]!.prompt.includes("user:"), false, "asset URL credentials are not in the LLM prompt header");
    assert.equal(s.pendingAssetObs![0]!.obs.url, `${BASE}main.js`);
    assert.equal(safeAssetUrl(url), `${BASE}main.js`);
    const followup = s.pendingAssetObs!.map(({ obs }) =>
      `${obs.url} ${obs.type} ${obs.detail} ${obs.evidence ?? ""} ${obs.investigation ?? ""}`).join("\n");
    for (const persisted of [JSON.stringify(store.loadAssessment("a-1")!.events), JSON.stringify(store.checks("a-1")),
      JSON.stringify(out), followup, lines.join("\n")]) {
      assert.equal(persisted.includes(marker), false);
      assert.equal(persisted.includes("user:"), false);
    }
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("malformed JSON, missing observations and malformed entries leave chunks unanalyzed (atomic per chunk)", async () => {
  const { s, store, dir } = session();
  try {
    const responses = [
      "no JSON",
      '{"ok":true}',
      '{"observations":null}',
      '{"observations":[{"type":"secret","detail":"valid"},false]}',
      '{"observations":[{"type":"endpoint","detail":"last chunk"}]}',
    ];
    let n = 0;
    const llm = new FakeLlmClient(() => responses[n++]!);
    const out = await reviewAssets({ session: s, llm, assets: [asset("x".repeat(24_000 * responses.length))] });
    assert.equal(llm.calls.length, responses.length);
    assert.equal(out.reviews[0]!.chunksTotal, responses.length);
    assert.equal(out.reviews[0]!.chunksAnalyzed, 1);
    assert.equal(out.reviews[0]!.complete, false);
    assert.equal(out.observations.length, 1);
    assert.equal(out.observations[0]!.location, "chunk 5, observation 1");
    const persisted = store.loadAssessment("a-1")!.events.find((e) => e.type === "asset_reviewed");
    assert.equal(persisted?.payload.complete, false);
    assert.equal(persisted?.payload.chunksAnalyzed, 1);
  } finally {
    s.store.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("resume/re-enrollment reproduces identities instead of creating or overwriting sibling leads", async () => {
  const { s, dir } = session();
  let reopened: AssessmentStore | undefined;
  try {
    const screens = [{ screenId: "s-0001", urlTemplate: "/", observedUrls: [BASE], authState: "unauth" as const,
      screenType: "dashboard" as const, description: "", params: [], apis: [], screenshot: "", domSkeletonHash: "h", labels: [] }];
    s.inv.seed(screens);
    const leads = (await reviewAssets({ session: s,
      llm: new FakeLlmClient('{"observations":[{"type":"endpoint","detail":"first"},{"type":"endpoint","detail":"second"}]}'),
      assets: [asset("const a = 1;")] })).observations;
    enrollObservations(s, leads);
    const ids = s.pendingAssetObs!.map((entry) => entry.checkId);
    assert.equal(new Set(ids).size, 2);
    const first = s.store.checks("a-1").find((c) => c.id === ids[0])!;
    s.store.upsertCheck("a-1", { ...first, status: "tested-clean", reason: "verified negative", updatedAt: new Date().toISOString() });
    s.store.close();

    reopened = AssessmentStore.open(join(dir, "state.sqlite"));
    s.store = reopened;
    s.inv = new InventoryBuilder();
    s.inv.seed(screens);
    s.currentRole = "different-role";
    s.currentBearer = "synthetic-session-change";
    enrollObservations(s, leads);
    assert.deepEqual(s.pendingAssetObs!.map((entry) => entry.checkId), ids);
    assert.equal(reopened.checks("a-1").filter((c) => c.checkClass === "asset-review").length, 2);
    assert.equal(reopened.checks("a-1").find((c) => c.id === ids[0])!.status, "tested-clean", "replay must not reset a resolved lead");
    assert.equal(reopened.checks("a-1").find((c) => c.id === ids[1])!.status, "planned");
  } finally {
    reopened?.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
