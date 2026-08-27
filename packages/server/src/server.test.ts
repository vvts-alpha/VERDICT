// Verify the server's HTTP API and WebSocket push without a browser (uses Node 24 global fetch/WebSocket).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { Screen, StateView, WsMessage } from "@veritas/core";
import { startServer } from "./index.js";

function screen(id: string, urlTemplate: string): Screen {
  return {
    screenId: id,
    urlTemplate,
    observedUrls: [],
    authState: "unauth",
    screenType: "other",
    description: "",
    params: [],
    apis: [],
    screenshot: "",
    domSkeletonHash: id,
    labels: [],
  };
}

function seed(runsDir: string, id: string): AssessmentStore {
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(join(runsDir, id, "state.sqlite"));
  store.createAssessment({
    id,
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
  });
  store.upsertScreen(id, screen("s-0001", "/products/{id}"));
  return store;
}

test("HTTP API lists assessments and projects a StateView", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-1");
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50 });
  try {
    const list = (await (await fetch(`${srv.url}/api/assessments`)).json()) as Array<{ id: string }>;
    assert.equal(list.length, 1);
    assert.equal(list[0]?.id, "a-1");

    const view = (await (await fetch(`${srv.url}/api/assessments/a-1`)).json()) as StateView;
    assert.equal(view.phase, "init");
    assert.equal(view.tree.length, 1);
    assert.equal(view.tree[0]?.segment, "products");
    assert.equal(view.coverage.total, 1);

    const missing = await fetch(`${srv.url}/api/assessments/nope`);
    assert.equal(missing.status, 404);
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("reconfigure endpoint appends a control_command the running pilot will apply", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-rc");
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50 });
  try {
    // valid reconfigure → 200 (+ a StateView back)
    const ok = await fetch(`${srv.url}/api/assessments/a-rc/reconfigure`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ addHosts: ["api.shop.test"], rateMs: 400, maxScreens: 25, note: "widen", bogus: "ignored" }),
    });
    assert.equal(ok.status, 200);

    // the command landed on the append-only log as a control_command with only the valid fields
    const check = AssessmentStore.open(join(runsDir, "a-rc", "state.sqlite"));
    const pending = check.controlCommandsSince("a-rc", 0);
    check.close();
    assert.equal(pending.length, 1);
    assert.deepEqual(pending[0]?.cmd, { addHosts: ["api.shop.test"], rateMs: 400, maxScreens: 25, note: "widen" });

    // empty / no-applicable-fields body → 400
    const empty = await fetch(`${srv.url}/api/assessments/a-rc/reconfigure`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ bogus: 1 }),
    });
    assert.equal(empty.status, 400);
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("add-target endpoint: injects an in-scope URL, refuses silent scope-widen, widens with extendScope", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-at"); // scope = shop.test
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50 });
  const post = (bodyObj: unknown) =>
    fetch(`${srv.url}/api/assessments/a-at/add-target`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(bodyObj),
    });
  try {
    // in-scope URL → 200, appended as a target_injected
    assert.equal((await post({ url: "https://shop.test/admin" })).status, 200);

    // schemeless / invalid URL → 400
    assert.equal((await post({ url: "shop.test/x" })).status, 400);

    // out-of-scope host WITHOUT extendScope → 400 (never widen silently)
    assert.equal((await post({ url: "https://evil.test/x" })).status, 400);

    // out-of-scope host WITH extendScope → 200, and the scope is now widened to include it
    assert.equal((await post({ url: "https://api.shop.test/v1/orders/1", extendScope: true })).status, 200);

    const check = AssessmentStore.open(join(runsDir, "a-at", "state.sqlite"));
    const injected = check.targetInjectionsSince("a-at", 0).map((x) => x.url);
    const scope = check.loadAssessment("a-at")!.scope;
    check.close();

    // evil.test was refused (not appended); the two allowed ones landed
    assert.deepEqual(injected, ["https://shop.test/admin", "https://api.shop.test/v1/orders/1"]);
    assert.ok(scope.inScopeHosts.includes("api.shop.test"), "extendScope widened the persisted scope");
    assert.ok(!scope.inScopeHosts.includes("evil.test"), "refused host was never added to scope");
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("auth gate: password-protects WebUI/API with login form + signed cookie", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-auth");
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50, authPasswords: { operator: "s3cret", viewer: "look" } });
  const form = { "content-type": "application/x-www-form-urlencoded" };
  try {
    // unauthenticated API → 401, unauthenticated HTML → 302 /login, /login form → 200
    assert.equal((await fetch(`${srv.url}/api/assessments`, { redirect: "manual" })).status, 401);
    const root = await fetch(`${srv.url}/`, { redirect: "manual" });
    assert.equal(root.status, 302);
    assert.equal(root.headers.get("location"), "/login");
    assert.equal((await fetch(`${srv.url}/login`)).status, 200);

    // wrong PW → 302 /login?e=1, no Cookie
    const bad = await fetch(`${srv.url}/auth`, { method: "POST", headers: form, body: "password=nope", redirect: "manual" });
    assert.equal(bad.headers.get("location"), "/login?e=1");
    assert.equal(bad.headers.getSetCookie().length, 0);

    // correct PW (operator) → 302 /, Set-Cookie
    const ok = await fetch(`${srv.url}/auth`, { method: "POST", headers: form, body: "password=s3cret", redirect: "manual" });
    assert.equal(ok.headers.get("location"), "/");
    const setc = ok.headers.getSetCookie();
    assert.equal(setc.length, 1);
    const cookie = setc[0]?.split(";")[0] ?? "";
    assert.match(cookie, /^verdict_session=operator\./);

    // API with Cookie → 200, tampered Cookie → 401, /api/me → operator (full rights)
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { cookie } })).status, 200);
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { cookie: "verdict_session=1.deadbeef" }, redirect: "manual" })).status, 401);
    assert.deepEqual(await (await fetch(`${srv.url}/api/me`, { headers: { cookie } })).json(), { role: "operator", authEnabled: true });
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("role split: viewer can read but every mutating POST is 403 (read-only)", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-view");
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50, authPasswords: { operator: "op", viewer: "vw" } });
  const form = { "content-type": "application/x-www-form-urlencoded" };
  try {
    const login = await fetch(`${srv.url}/auth`, { method: "POST", headers: form, body: "password=vw", redirect: "manual" });
    const cookie = login.headers.getSetCookie()[0]?.split(";")[0] ?? "";
    assert.match(cookie, /^verdict_session=viewer\./);
    // read GET is OK
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { cookie } })).status, 200);
    assert.deepEqual(await (await fetch(`${srv.url}/api/me`, { headers: { cookie } })).json(), { role: "viewer", authEnabled: true });
    // mutating POST is 403 (read-only)
    for (const path of ["/api/run", "/api/assessments/a-view/pause", "/api/assessments/a-view/screens/s-1/exclude"]) {
      const r = await fetch(`${srv.url}${path}`, { method: "POST", headers: { cookie, "content-type": "application/json" }, body: "{}", redirect: "manual" });
      assert.equal(r.status, 403, `${path} should be forbidden for viewer`);
    }
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("control endpoints: pause/resume, exclude screen, resolve handoff (§8.3)", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-3");
  store.upsertHandoff("a-3", {
    id: "ho-001", reason: "captcha", url: "https://shop.test/login", message: "captcha wall",
    status: "pending", createdAt: new Date().toISOString(), resolvedAt: null,
  });
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50 });
  const post = async (path: string): Promise<StateView> =>
    (await (await fetch(`${srv.url}${path}`, { method: "POST" })).json()) as StateView;
  try {
    assert.equal((await post("/api/assessments/a-3/pause")).paused, true);
    assert.equal((await post("/api/assessments/a-3/resume")).paused, false);
    assert.equal((await post("/api/assessments/a-3/screens/s-0001/exclude")).coverage.byStatus.excluded, 1);
    const resolved = await post("/api/assessments/a-3/handoffs/ho-001/resolve");
    assert.equal(resolved.handoffs.find((h) => h.id === "ho-001")?.status, "resolved");
  } finally {
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});

test("WebSocket sends a snapshot then pushes events on state change", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-srv-"));
  const store = seed(runsDir, "a-2");
  store.close();
  const srv = await startServer({ runsDir, pollMs: 50 });

  const messages: WsMessage[] = [];
  const ws = new WebSocket(`${srv.url.replace("http", "ws")}/ws?id=a-2`);

  const waitFor = (pred: () => boolean, ms = 4000): Promise<void> =>
    new Promise((resolve, reject) => {
      const t0 = Date.now();
      const iv = setInterval(() => {
        if (pred()) {
          clearInterval(iv);
          resolve();
        } else if (Date.now() - t0 > ms) {
          clearInterval(iv);
          reject(new Error("timeout waiting for ws condition"));
        }
      }, 20);
    });

  try {
    ws.addEventListener("message", (ev) => messages.push(JSON.parse(String(ev.data)) as WsMessage));
    await new Promise<void>((resolve, reject) => {
      ws.addEventListener("open", () => resolve());
      ws.addEventListener("error", () => reject(new Error("ws error")));
    });

    await waitFor(() => messages.some((m) => m.type === "snapshot"));
    const snap = messages.find((m) => m.type === "snapshot");
    assert.ok(snap && snap.type === "snapshot");
    assert.equal(snap.view.screens.length, 1);

    // equivalent to a separate process: add a screen to the same state.sqlite → the server detects it via polling and pushes
    const writer = AssessmentStore.open(join(runsDir, "a-2", "state.sqlite"));
    writer.upsertScreen("a-2", screen("s-0002", "/login"));
    writer.close();

    await waitFor(() => messages.some((m) => m.type === "events"));
    const evMsg = messages.find((m) => m.type === "events");
    assert.ok(evMsg && evMsg.type === "events");
    assert.equal(evMsg.view.screens.length, 2, "pushed view reflects the new screen");
    assert.ok(evMsg.events.some((e) => e.type === "screen_discovered"));
  } finally {
    ws.close();
    await srv.close();
    rmSync(runsDir, { recursive: true, force: true });
  }
});
