import { strict as assert } from "node:assert";
import { test } from "node:test";
import { runSequentialBurp, burpTaskSucceeded, type SequentialBurpOptions } from "./burp-sequential.js";
import { submitSequentialAudit, getSequentialAudit } from "./burp-audit.js";
import { startBurpScan, getBurpScan } from "./burp-rest.js";

function options(overrides: Partial<SequentialBurpOptions<number>> = {}): SequentialBurpOptions<number> {
  let clock = 0;
  return {
    items: [1, 2], start: async (n) => String(n),
    poll: async () => ({ status: "finished", issues: [] }), onResult: async () => {},
    now: () => clock, sleep: async (ms) => { clock += ms; },
    pollIntervalMs: 1, taskTimeoutMs: 10, ...overrides,
  };
}

test("next task waits for completion AND persistence, without truncating the inventory", async () => {
  const events: string[] = [];
  let polls = 0;
  const result = await runSequentialBurp(options({
    items: Array.from({ length: 301 }, (_, n) => n + 1),
    start: async (n) => { events.push(`start ${n}`); return String(n); },
    poll: async (id) => { const status = ++polls % 2 ? "auditing" : "finished"; events.push(`${id} ${status}`); return { status, issues: [] }; },
    onResult: async (_, n) => { await Promise.resolve(); events.push(`save ${n}`); },
  }));
  assert.equal(result.completed, 301);
  assert.deepEqual(events.slice(0, 5), ["start 1", "1 auditing", "1 finished", "save 1", "start 2"]);
});

test("a pending persistence operation prevents the next submission", async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => { release = resolve; });
  let saving!: () => void;
  const entered = new Promise<void>((resolve) => { saving = resolve; });
  const started: number[] = [];
  const pending = runSequentialBurp(options({
    start: async (n) => { started.push(n); return String(n); },
    onResult: async (_, n) => { if (n === 1) { saving(); await gate; } },
  }));
  await entered;
  assert.deepEqual(started, [1]);
  release();
  assert.equal((await pending).completed, 2);
});

for (const status of ["failed", "paused", "aborted", "unknown", "unfinished", "finished with errors"]) {
  test(`${status} never advances to task 2 and saves the last snapshot`, async () => {
    let saved = 0;
    const result = await runSequentialBurp(options({ poll: async () => ({ status, issues: [] }), onResult: async () => { saved++; } }));
    assert.equal(result.submitted, 1);
    assert.equal(result.completed, 0);
    assert.ok(result.stoppedReason);
    assert.equal(saved, 1);
  });
}

test("network errors stop submission even with a finished status", async () => {
  const result = await runSequentialBurp(options({ poll: async () => ({ status: "finished", errors: 1, issues: [] }) }));
  assert.equal(result.submitted, 1);
  assert.equal(result.completed, 0);
});

test("ambiguous POST failure is not retried", async () => {
  let starts = 0;
  const result = await runSequentialBurp(options({ start: async () => { starts++; throw new Error("connection lost"); } }));
  assert.equal(starts, 1);
  assert.match(result.stoppedReason!, /connection lost/);
});

test("unresponsive POST is aborted and never followed by another task", async () => {
  let signal: AbortSignal | undefined;
  const result = await runSequentialBurp(options({ requestTimeoutMs: 5, start: async (_, s) => { signal = s; return new Promise(() => {}); } }));
  assert.equal(signal?.aborted, true);
  assert.equal(result.completed, 0);
  assert.match(result.stoppedReason!, /timed out/);
});

test("poll failures preserve the last results and stop", async () => {
  let polls = 0, saves = 0;
  const result = await runSequentialBurp(options({
    poll: async () => { if (++polls > 1) throw new Error("offline"); return { status: "auditing", issues: [] }; },
    onResult: async () => { saves++; },
  }));
  assert.equal(result.submitted, 1);
  assert.equal(saves, 1);
});

test("storage failure stops new scans", async () => {
  const result = await runSequentialBurp(options({ onResult: async () => { throw new Error("disk full"); } }));
  assert.equal(result.submitted, 1);
  assert.equal(result.completed, 0);
  assert.match(result.stoppedReason!, /disk full/);
});

test("only explicit success statuses count", () => {
  for (const s of ["finished", "Finished.", "Audit finished", "succeeded", "completed successfully"]) assert.ok(burpTaskSucceeded(s));
  for (const s of ["unfinished", "paused", "not finished", "finished with errors", ""]) assert.ok(!burpTaskSucceeded(s));
});

test("old extension is refused before any legacy submission; task responses must match", async (t) => {
  const paths: string[] = [];
  const conn = { base: "http://burp.invalid:1338", token: "test-token" };
  const signal = new AbortController().signal;
  t.mock.method(globalThis, "fetch", async (url: string, init: RequestInit) => {
    paths.push(url);
    assert.equal((init.headers as Record<string, string>)["X-Scan-Token"], conn.token);
    assert.equal(init.signal, signal);
    if (init.method === "POST") return new Response("old extension", { status: 404 });
    return Response.json({ id: "wrong-task", status: "finished", errors: 0, requests_made: 1, issues: [] });
  });
  await assert.rejects(submitSequentialAudit(conn, { host: "example.com", port: 443, secure: true, auditMode: "active", request: "GET / HTTP/1.1\r\n\r\n" }, signal), /update and reload/);
  assert.deepEqual(paths, ["http://burp.invalid:1338/scan/serial"]);
  await assert.rejects(getSequentialAudit(conn, "task1", signal), /Invalid sequential/);
});

test("standard REST submits single URLs with original auth, policy and pool", async (t) => {
  const bodies: Record<string, unknown>[] = [];
  t.mock.method(globalThis, "fetch", async (_: string, init: RequestInit) => {
    assert.ok(init.signal);
    if (init.method === "POST") { bodies.push(JSON.parse(String(init.body))); return new Response(null, { status: 201, headers: { location: String(bodies.length) } }); }
    return Response.json({ scan_status: "succeeded", issue_events: [] });
  });
  const result = await runSequentialBurp(options({
    start: (n, signal) => startBurpScan({ base: "http://burp.invalid", urls: [`https://example.com/${n}`], resourcePool: "slow", customConfigs: ["policy"], logins: [{ username: "u", password: "p" }], signal }),
    poll: (id, signal) => getBurpScan("http://burp.invalid", undefined, id, signal),
  }));
  assert.equal(result.completed, 2);
  assert.deepEqual(bodies.map((b) => b.urls), [["https://example.com/1"], ["https://example.com/2"]]);
  assert.equal(bodies[0]?.resource_pool, "slow");
  assert.deepEqual(bodies[0]?.scan_configurations, [{ type: "CustomConfiguration", config: "policy" }]);
  assert.deepEqual(bodies[0]?.application_logins, [{ username: "u", password: "p" }]);
});
