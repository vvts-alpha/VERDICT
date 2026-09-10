import { test } from "node:test";
import assert from "node:assert/strict";
import { request } from "node:http";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { startServer } from "./server.js";

function wsResult(url: string, headers: Record<string, string>): Promise<boolean> {
  return new Promise((resolve) => {
    const ws = new WebSocket(url, { headers, handshakeTimeout: 2000 });
    ws.on("error", () => resolve(false));
    ws.on("open", () => { resolve(true); ws.close(); });
  });
}

test("HTTP and WS reject cross-origin and missing desktop credentials while same-origin control works", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-api-security-"));
  mkdirSync(join(runsDir, "a-1"));
  const store = AssessmentStore.open(join(runsDir, "a-1", "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: "https://app.test/", followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl("https://app.test/") });
  const localAuthToken = "test-launch-secret";
  const srv = await startServer({ runsDir, localAuthToken });
  const token = { "x-verdict-token": localAuthToken };
  try {
    assert.equal((await fetch(`${srv.url}/api/assessments`)).status, 401);
    for (const origin of ["https://target.test", "http://127.0.0.1:1", "null"]) {
      assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { ...token, origin } })).status, 403);
      assert.equal((await fetch(`${srv.url}/api/assessments/a-1/pause`, { method: "POST", headers: { ...token, origin, "content-type": "text/plain" }, body: "{}" })).status, 403);
      assert.equal(await wsResult(`${srv.url.replace("http", "ws")}/ws?id=a-1`, { ...token, origin }), false);
    }
    assert.equal(store.isPaused("a-1"), false);
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { ...token, "sec-fetch-site": "same-site" } })).status, 403);
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { ...token, host: `rebind.test:${srv.port}`, origin: `http://rebind.test:${srv.port}` } })).status, 403);
    const list = await fetch(`${srv.url}/api/assessments`, { headers: { ...token, origin: srv.url } });
    assert.equal(list.status, 200);
    assert.equal(list.headers.get("access-control-allow-origin"), null);
    assert.equal((await list.json() as unknown[]).length, 1);
    assert.equal((await fetch(`${srv.url}/api/assessments/a-1/pause`, { method: "POST", headers: { ...token, origin: srv.url } })).status, 200);
    assert.equal(store.isPaused("a-1"), true);
    assert.equal(await wsResult(`${srv.url.replace("http", "ws")}/ws?id=a-1`, { origin: srv.url }), false);
    assert.equal(await wsResult(`${srv.url.replace("http", "ws")}/ws?id=a-1`, { ...token, origin: srv.url }), true);
  } finally { await srv.close(); store.close(); rmSync(runsDir, { recursive: true, force: true }); }
});

test("standalone API rejects browser CSRF even without password auth", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-origin-"));
  const srv = await startServer({ runsDir });
  try {
    assert.equal((await fetch(`${srv.url}/api/assessments`, { headers: { origin: "https://untrusted.test" } })).status, 403);
    assert.equal((await fetch(`${srv.url}/api/run`, { method: "POST", headers: { origin: "null", "content-type": "text/plain" }, body: "{}" })).status, 403);
    assert.equal((await fetch(`${srv.url}/api/assessments`)).status, 200);
    const preview = await fetch(`${srv.url}/api/scope-preview?mode=etld&url=https%3A%2F%2Falice.github.io%2F`);
    assert.deepEqual(await preview.json(), { hosts: ["*.alice.github.io"] });
  } finally { await srv.close(); rmSync(runsDir, { recursive: true, force: true }); }
});

test("malformed paths and JSON shapes return errors without terminating the server", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-bad-request-"));
  const srv = await startServer({ runsDir });
  const rawStatus = (path: string) => new Promise<number>((resolve, reject) => {
    const req = request(srv.url, { path }, (res) => { res.resume(); resolve(res.statusCode!); });
    req.on("error", reject); req.end();
  });
  try {
    for (const path of ["/api/assessments/%ZZ", "/api/assessments/%E0%A4%A", "/api/run/%2e%2e/resume", "/api/assessments/a%2fb", "/api/assessments/a%5cb", "/assets/%ZZ", "/api/assessments/a%00"]) {
      assert.equal(await rawStatus(path), 400, path);
      assert.equal((await fetch(`${srv.url}/api/assessments`)).status, 200);
    }
    for (const body of ["null", '{"messages":{}}', '{"messages":[null]}']) {
      assert.equal((await fetch(`${srv.url}/api/assessments/a-1/chat`, { method: "POST", headers: { "content-type": "application/json" }, body })).status, 400);
    }
    assert.equal(await wsResult(`${srv.url.replace("http", "ws")}/%ZZ`, {}), false);
    assert.equal((await fetch(`${srv.url}/api/assessments`)).status, 200);
  } finally { await srv.close(); rmSync(runsDir, { recursive: true, force: true }); }
});
