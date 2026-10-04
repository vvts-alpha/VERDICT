import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { createServer, type RequestListener } from "node:http";
import { FetchHttpClient } from "./http.js";

async function server(t: TestContext, handler: RequestListener): Promise<string> {
  const app = createServer(handler);
  await new Promise<void>((resolve) => app.listen(0, "127.0.0.1", resolve));
  t.after(() => { app.closeAllConnections(); app.close(); });
  const address = app.address();
  assert.ok(address && typeof address !== "string");
  return `http://127.0.0.1:${address.port}/`;
}

test("bounded HTTP cancels a large transfer instead of downloading its tail", async (t) => {
  let sent = 0;
  let closed = false;
  const url = await server(t, (_req, res) => {
    const timer = setInterval(() => {
      res.write(Buffer.alloc(16 * 1024, 120)); sent += 16 * 1024;
      if (sent >= 2 * 1024 * 1024) { clearInterval(timer); res.end(); }
    }, 5);
    res.on("close", () => { clearInterval(timer); closed = true; });
  });
  const response = await new FetchHttpClient({ maxBodyBytes: 1024 }).send({ method: "GET", url });
  assert.equal(response.bodyBytes, 1024);
  assert.equal(response.body, "x".repeat(1024));
  assert.equal(response.truncated, true);
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.ok(closed);
  assert.ok(sent < 2 * 1024 * 1024);
});

test("a capped prefix returns even when the server never finishes its body", async (t) => {
  const url = await server(t, (_req, res) => { res.write(Buffer.alloc(4096, 120)); });
  const response = await new FetchHttpClient({ maxBodyBytes: 1024, timeoutMs: 1000 }).send({ method: "GET", url });
  assert.equal(response.bodyBytes, 1024);
  assert.equal(response.truncated, true);
});

test("complete, exact-limit, empty, encoded and per-request bodies retain correct metadata", async (t) => {
  const url = await server(t, (req, res) => {
    if (req.method === "HEAD") { res.end(); return; }
    res.end("あいうえ");
  });
  const http = new FetchHttpClient({ maxBodyBytes: 3 });
  const prefix = await http.send({ method: "GET", url });
  assert.equal(prefix.body, "あ"); assert.equal(prefix.truncated, true);
  for (const maxBodyBytes of [12, 20]) {
    const full = await http.send({ method: "GET", url, maxBodyBytes });
    assert.equal(full.body, "あいうえ"); assert.equal(full.bodyBytes, 12); assert.equal(full.truncated, false);
  }
  const head = await http.send({ method: "HEAD", url });
  assert.equal(head.bodyBytes, 0); assert.equal(head.truncated, false);
});

test("request reservations count failures, block before network, and exclude scope refusals", async (t) => {
  let requests = 0;
  let reservations = 0;
  const url = await server(t, (req, res) => { requests++; if (req.url === "/fail") req.socket.destroy(); else res.end("ok"); });
  const http = new FetchHttpClient({ allow: (u) => u.startsWith(url), beforeSend: () => { if (reservations >= 2) throw new Error("budget"); reservations++; } });
  await assert.rejects(http.send({ method: "GET", url: "http://outside.test/" }), /scope/);
  assert.equal(reservations, 0);
  await assert.rejects(http.send({ method: "GET", url: `${url}fail` }));
  await http.send({ method: "GET", url });
  await assert.rejects(http.send({ method: "GET", url }), /budget/);
  assert.equal(reservations, 2); assert.equal(requests, 2);
});
