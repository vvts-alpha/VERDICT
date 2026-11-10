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
import { buildTools, harvestBodyPaths } from "./tools.js";
import type { PilotSession } from "./tools.js";

// probe_paths discovery depth: a mount that only answers WITH a trailing slash (express app.use("/x/")),
// a bare /support 404ing while /support/logs serves, and path-shaped strings inside response bodies —
// all three were real misses vs. Juice Shop.

let server: Server;
let base = "";
let dir = "";
let dbN = 0;
const seen: string[] = [];

before(async () => {
  server = createServer((req, res) => {
    const p = new URL(req.url ?? "/", "http://x").pathname;
    seen.push(p);
    const routes: Record<string, [number, string]> = {
      "/mountonly/": [200, "index of /mountonly"],
      "/admin": [200, "<html>admin panel</html>"],
      "/admin/logs": [200, "index of /admin/logs"],
      "/support/logs": [200, "index of /support/logs"],
      "/support/logs/access.log": [200, "GET / x.x.x.x"],
      "/hidden-api/secret": [200, "ssh-rsa AAAA... leaked"],
      "/veritas-miss": [404, "nope"],
    };
    if (p.startsWith("/veritas-404-")) { res.writeHead(404); res.end("not found"); return; }
    const r = routes[p];
    if (r) { res.writeHead(r[0], { "content-type": "text/plain" }); res.end(r[1]); return; }
    res.writeHead(404); res.end("not found");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "verdict-paths-"));
});
after(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
});

function session(): PilotSession {
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
    frontier: new Set(),
    ignorePaths: [],
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function runProbePaths(s: PilotSession, args: { extra?: string[]; parents?: string[] } = {}): Promise<{ hits: { path: string }[]; harvestedPaths?: number; sent?: number; aborted?: string }> {
  const t = buildTools(s).find((x) => x.name === "probe_paths")!;
  const content = (await t.handler(args as never, {} as never)).content[0];
  assert.ok(content && content.type === "text");
  const out = content.text;
  return JSON.parse(out);
}

test("a slash-only mount (404 bare, 200 with trailing slash) is found", async () => {
  const s = session();
  try {
    const r = await runProbePaths(s, { extra: ["/mountonly"] });
    assert.ok(r.hits.some((h) => h.path === "/mountonly/"), JSON.stringify(r.hits));
  } finally {
    s.store.close();
  }
});

test("a 404 parent does NOT bury its subtree: explicit 2-level wordlist hits /support/logs", async () => {
  const s = session();
  try {
    const r = await runProbePaths(s);
    assert.ok(r.hits.some((h) => h.path === "/support/logs"), JSON.stringify(r.hits));
  } finally {
    s.store.close();
  }
});

test("descent runs only under caller-chosen parents (/admin → /admin/logs), never automatically", async () => {
  // Pass 1 alone must NOT descend: /admin hits but its child stays unprobed until asked for.
  const s1 = session();
  try {
    const r = await runProbePaths(s1);
    assert.ok(r.hits.some((h) => h.path === "/admin"), "/admin should hit");
    assert.ok(!r.hits.some((h) => h.path === "/admin/logs"), "automatic descent must not happen");
  } finally {
    s1.store.close();
  }
  // With the directory judged worth descending, one parents call sweeps its children (bare + slash).
  const s2 = session();
  try {
    const r = await runProbePaths(s2, { parents: ["/admin", "support"] });
    assert.ok(r.hits.some((h) => h.path === "/admin/logs"), `parents descent should find /admin/logs: ${JSON.stringify(r.hits)}`);
    assert.ok(r.hits.some((h) => h.path === "/support/logs"), `parents without leading slash still normalize: ${JSON.stringify(r.hits)}`);
  } finally {
    s2.store.close();
  }
});

test("path strings inside recorded response bodies are harvested and probed automatically", async () => {
  const s = session();
  try {
    // an earlier probe recorded a body that NAMES the hidden path (config / error / catalog leak)
    s.evidence.record({
      screenId: "s-1", validator: "claude-pilot", kind: "positive_replay",
      request: { method: "GET", url: `${base}api/config`, headers: {}, body: null },
      response: { status: 200, headers: {}, body: '{"logDir":"/hidden-api/secret","uploadDir":"/srv/app/uploads","nuke":"/admin/delete-all"}', bodyBytes: 100, finalUrl: `${base}api/config`, durationMs: 1 },
      note: "fixture",
    });
    const r = await runProbePaths(s);
    assert.ok(r.hits.some((h) => h.path === "/hidden-api/secret"), `harvested path should be probed: ${JSON.stringify(r.hits)}`);
    // and the server-internal FS path was NOT probed
    assert.ok(!seen.some((p) => p.startsWith("/srv/")), "server-internal paths must not be probed");
    // nor the GET-mutating route a leaked body happened to name — harvested paths are untrusted input
    assert.ok(!seen.some((p) => p.includes("delete-all")), "a harvested mutating path must never be probed");
  } finally {
    s.store.close();
  }
});

test("a wall of identical 403s aborts enumeration instead of eating the whole wordlist", async () => {
  // A WAF answering every probe with the same challenge page — 25 consecutive near-identical 403s
  // trips the abort; the run reports it instead of pretending a clean sweep.
  const waf = createServer((_req, res) => { res.writeHead(403, { "content-type": "text/html" }); res.end("<html>Access Denied — request blocked</html>"); });
  await new Promise<void>((r) => waf.listen(0, "127.0.0.1", r));
  try {
    const wafBase = `http://127.0.0.1:${(waf.address() as AddressInfo).port}/`;
    const store = AssessmentStore.open(join(dir, `waf-${dbN++}.sqlite`));
    store.createAssessment({ id: "a-waf", target: { kind: "single_url", url: wafBase, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(wafBase) });
    const s = session();
    s.store.close();
    s.store = store;
    s.assessmentId = "a-waf";
    s.targetUrl = wafBase;
    s.scope = deriveScopeFromSingleUrl(wafBase);
    s.http = new FetchHttpClient({ allow: (u: string) => u.startsWith(wafBase.replace(/\/$/, "")) });
    const r = await runProbePaths(s);
    assert.ok(r.aborted?.includes("WAF"), `expected WAF abort, got ${JSON.stringify(r)}`);
    assert.ok((r.sent ?? 0) < 60, `should stop after ~25 streak sends, sent ${r.sent}`);
    store.close();
  } finally {
    waf.close();
  }
});

test("harvestBodyPaths filters FS noise, asset extensions and mutating routes", () => {
  const paths = harvestBodyPaths('{"a":"/api/x","fs":"/var/log/app.log","stack":"/juice-shop/node_modules/express/lib.js","img":"/assets/i.png","ok":"/support/logs","del":"/admin/users/delete/5","rst":"/account/reset-password","ord":"/cart/checkout"}');
  assert.ok(paths.includes("/api/x"));
  assert.ok(paths.includes("/support/logs"));
  assert.ok(!paths.some((p) => p.startsWith("/var/")), "unix FS paths filtered");
  assert.ok(!paths.some((p) => p.includes("node_modules")), "node_modules filtered");
  assert.ok(!paths.some((p) => p.endsWith(".png")), "asset extensions filtered");
  // A leaked body naming GET-mutating routes must not turn enumeration into state changes.
  assert.ok(!paths.some((p) => p.includes("delete")), "mutating harvested path filtered");
  assert.ok(!paths.some((p) => p.includes("reset")), "mutating harvested path filtered");
  assert.ok(!paths.some((p) => p.includes("checkout")), "mutating harvested path filtered");
});
