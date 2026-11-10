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

// The bulk lane (req.bulk) exists so forced-browse wordlists (~4.7k entries) don't take an hour at the
// polite minDelay — but the polite lane and its invariants (scope, ordering) are untouched.

test("bulk sends pace at ~minDelay/8 while polite sends keep minDelay", async (t) => {
  const url = await server(t, (_req, res) => res.end("ok"));
  const http = new FetchHttpClient({ minDelayMs: 400 });
  const t0 = Date.now();
  for (let i = 0; i < 3; i++) await http.send({ method: "GET", url });
  const politeMs = Date.now() - t0;
  const t1 = Date.now();
  for (let i = 0; i < 6; i++) await http.send({ method: "GET", url, bulk: true });
  const bulkMs = Date.now() - t1;
  // polite: 2 intervals × 400ms ≈ 800ms; bulk: 5 intervals × 50ms ≈ 250ms — assert a wide margin.
  assert.ok(politeMs >= 700, `polite lane should keep ~400ms spacing, took ${politeMs}`);
  assert.ok(bulkMs < politeMs / 2, `bulk lane should be much faster, took ${bulkMs} vs ${politeMs}`);
});

test("429/503 pushback escalates the bulk lane's delay", async (t) => {
  const url = await server(t, (_req, res) => {
    res.writeHead(429);
    res.end("slow down");
  });
  const http = new FetchHttpClient({ minDelayMs: 200 });
  await http.send({ method: "GET", url, bulk: true }); // eff 25ms → escalates to 50ms
  const t0 = Date.now();
  await http.send({ method: "GET", url, bulk: true }); // waits 50ms → escalates to 100ms
  const d1 = Date.now() - t0;
  const t1 = Date.now();
  await http.send({ method: "GET", url, bulk: true }); // waits 100ms → escalates to 200ms (cap = polite)
  const d2 = Date.now() - t1;
  assert.ok(d2 > d1 * 1.5, `escalating delay expected: first wait ${d1}ms, second ${d2}ms`);
});

test("minDelay unset → bulk is unthrottled (operator asked for no rate)", async (t) => {
  const url = await server(t, (_req, res) => res.end("ok"));
  const http = new FetchHttpClient({});
  const t0 = Date.now();
  for (let i = 0; i < 20; i++) await http.send({ method: "GET", url, bulk: true });
  assert.ok(Date.now() - t0 < 500, `20 unthrottled bulk sends took ${Date.now() - t0}ms`);
});
