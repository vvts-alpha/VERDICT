import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

// ── Parallel-diagnosis isolation invariants ──
// 1. A boundRole worker's login() cannot switch to another role (same-account parallel traffic is
//    impossible by construction; cross-role checks go through compare legs).
// 2. FetchHttpClient serializes state-changing sends per session-material: two workers mutating under
//    the SAME account can't interleave writes, while different accounts and pure reads stay parallel.

let server: Server;
let base = "";
let dir = "";
let dbN = 0;
// Server-side concurrency probe: /slow holds the request open; the handler records how many were in flight.
let inFlight = 0;
let maxInFlight = 0;
let release: (() => void) | null = null;

before(async () => {
  server = createServer((req, res) => {
    if (req.url === "/slow-write" || req.url === "/slow-read") {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      let finished = false;
      const finish = () => {
        if (finished) return; // a stale chained release must not double-end the response
        finished = true;
        inFlight -= 1;
        res.writeHead(200, { "content-type": "text/plain" });
        res.end("ok");
      };
      if (release) {
        // queue behind the currently-held request
        const prev = release;
        release = () => {
          prev();
          finish();
        };
      } else {
        release = finish;
      }
      return;
    }
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "veritas-par-"));
});
after(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

function session(extra: Partial<PilotSession> = {}): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  return {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(base.replace(/\/$/, "")) }),
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, `art-${dbN}`)),
    inv: new InventoryBuilder(),
    scope: deriveScopeFromSingleUrl(base),
    targetUrl: base,
    currentScreenId: "s-1",
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
}

async function runTool(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return (await t.handler(args, {})).content[0]!.text;
}
const close = (s: PilotSession): void => (s as unknown as { store: { close(): void } }).store.close();

/** Release every /slow-* send to completion. Serialized sends arrive at the server one at a time, so wait
 *  for each arrival (release != null) rather than releasing on a fixed timer — a fixed sleep races the
 *  write-queue dispatch and flakes. */
async function drainSends(sends: Promise<unknown>[]): Promise<void> {
  let done = 0;
  for (const p of sends) void p.then(() => (done += 1), () => (done += 1));
  for (let guard = 0; guard < 600 && done < sends.length; guard++) {
    if (release) {
      const rel = release;
      release = null;
      rel();
    }
    await new Promise((r) => setTimeout(r, 10));
  }
  await Promise.all(sends);
}

test("boundRole worker: login() to another role is rejected with compare-leg guidance", async () => {
  const s = session({ boundRole: "alice", currentRole: "alice", roleCreds: new Map([["alice", { username: "a", password: "p" }], ["admin", { username: "b", password: "q" }]]) });
  try {
    const out = await runTool(s, "login", { role: "admin" });
    assert.match(out, /bound to role 'alice'/);
    assert.match(out, /probe_authz|compareRole/, "rejection should point at the compare-leg path");
    assert.equal(s.currentRole, "alice", "session role unchanged");
  } finally {
    close(s);
  }
});

test("unauth worker (boundRole \"\"): any login is rejected", async () => {
  const s = session({ boundRole: "", roleCreds: new Map([["alice", { username: "a", password: "p" }]]) });
  try {
    const out = await runTool(s, "login", { role: "alice" });
    assert.match(out, /bound to role '\(unauthenticated\)'/);
  } finally {
    close(s);
  }
});

test("unbound session: login() to any CONFIGURED role proceeds normally (no boundRole gate)", async () => {
  const s = session({ roleNames: new Set(["alice"]), roleCreds: new Map() }); // configured role, no boundRole, no material — fails at the creds step, not the gates
  try {
    const out = await runTool(s, "login", { role: "alice" });
    assert.doesNotMatch(out, /bound to role|unknown role/);
    assert.match(out, /no credentials\/cookie/, "reaches the credentials step — neither gate fired");
  } finally {
    close(s);
  }
});

test("write queue: mutating sends under the SAME session material never overlap", async () => {
  const http = new FetchHttpClient({ allow: (url) => url.startsWith(base.replace(/\/$/, "")) });
  inFlight = 0;
  maxInFlight = 0;
  release = null;
  const headers = { cookie: "sess=alice" };
  const sends = [0, 1, 2].map(() => http.send({ method: "POST", url: `${base}slow-write`, headers, body: "x=1" }));
  await drainSends(sends);
  assert.equal(maxInFlight, 1, "mutating sends under one account must serialize (never 2 in flight)");
});

test("write queue: mutating sends under DIFFERENT session material run concurrently", async () => {
  const http = new FetchHttpClient({ allow: (url) => url.startsWith(base.replace(/\/$/, "")) });
  inFlight = 0;
  maxInFlight = 0;
  release = null;
  const sends = [
    http.send({ method: "POST", url: `${base}slow-write`, headers: { cookie: "sess=alice" }, body: "x=1" }),
    http.send({ method: "POST", url: `${base}slow-write`, headers: { cookie: "sess=admin" }, body: "x=1" }),
  ];
  await drainSends(sends);
  assert.ok(maxInFlight >= 2, "different accounts' writes must stay parallel");
});

test("write queue: plain reads under the same material are not serialized", async () => {
  const http = new FetchHttpClient({ allow: (url) => url.startsWith(base.replace(/\/$/, "")) });
  inFlight = 0;
  maxInFlight = 0;
  release = null;
  const sends = [0, 1].map(() => http.send({ method: "GET", url: `${base}slow-read`, headers: { cookie: "sess=alice" } }));
  await drainSends(sends);
  assert.ok(maxInFlight >= 2, "reads stay parallel — only writes serialize");
});
