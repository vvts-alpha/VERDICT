// New probe tools: probe_xxe / probe_cache / probe_method_bypass / probe_rate_limit /
// analyze_saml / probe_deser / probe_websocket (real local socket) — behavior fixtures only.
import { strict as assert } from "node:assert";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { createServer, type Server, type Socket } from "node:net";
import { EvidenceStore } from "@veritas/scanner";
import type { PilotSession } from "./tools.js";
import { buildTools } from "./tools.js";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

type Req = { url: string; method?: string; headers?: Record<string, string>; body?: string | null; multipart?: unknown };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string; truncated?: boolean };
type Tool = { name: string; handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
const fixtureStores = new Map<string, AssessmentStore>();

function fakeSession(dir: string, send: (req: Req) => Promise<Res>, opts: { base?: string } = {}): PilotSession {
  const base = opts.base ?? "https://app.test/";
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  fixtureStores.set(dir, store);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(base),
    targetUrl: base,
    currentScreenId: "s-1",
    currentCookie: "sid=abc",
    currentBearer: "",
    currentRole: "alice",
    roleCreds: new Map([["alice", { username: "alice", password: "x" }]]),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    findings: [],
    findingsByKey: new Map(),
    recordCalls: 0,
    findCounter: 0,
  } as unknown as PilotSession;
}

async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as Tool;
  return JSON.parse((await t.handler(args, {})).content[0]!.text) as Record<string, unknown>;
}

async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verdict-extra-"));
  try {
    await fn(dir);
  } finally {
    fixtureStores.get(dir)?.close();
    fixtureStores.delete(dir);
    rmSync(dir, { recursive: true, force: true });
  }
}

const ok = (req: Req, body: string, status = 200, headers: Record<string, string> = {}): Res => ({ status, finalUrl: req.url, durationMs: 1, headers, body });

// ── probe_xxe ────────────────────────────────────────────────────────────────
test("probe_xxe confirms inline file exfil when entity content echoes in two file legs", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const b = req.body ?? "";
      if (b.includes('SYSTEM "file:///etc/passwd"')) return ok(req, `<v>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1</v>`);
      if (b.includes("win.ini")) return ok(req, `<v>; for 16-bit app support\n[fonts]\n[extensions]</v>`);
      if (b.includes("&c;")) return ok(req, `<v>${/ENTITY c "([^"]+)"/.exec(b)?.[1] ?? ""}</v>`);
      return ok(req, `<v>plain</v>`);
    });
    const out = await run(s, "probe_xxe", { url: "https://app.test/xml" });
    assert.equal(out.verdict, "CONFIRMED");
    assert.ok(out.negativeControl && Array.isArray(out.positiveReplays) && (out.positiveReplays as string[]).length === 2);
    assert.notEqual(out.negativeControl, (out.positiveReplays as string[])[0]);
  });
});

test("probe_xxe stays UNVERIFIED when entities do not expand", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, `{"ok":true}`));
    const out = await run(s, "probe_xxe", { url: "https://app.test/xml" });
    assert.equal(out.verdict, "UNVERIFIED");
    assert.match(out.reason as string, /did not expand|probe_oob/);
  });
});

// ── probe_cache ──────────────────────────────────────────────────────────────
test("probe_cache confirms deception when unauth replay of primed static URL leaks the private body", async () => {
  await withDir(async (dir) => {
    const PRIVATE = `PRIVATE_DATA_${"x".repeat(200)}_END`;
    const authed = (req: Req) => Boolean(req.headers?.cookie ?? req.headers?.authorization);
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const u = req.url;
      if (u.endsWith(".css") || u.includes("%2e%2e%3b")) {
        // edge cache: the private body is served under the static-looking key regardless of session
        return ok(req, PRIVATE);
      }
      return authed(req) ? ok(req, PRIVATE) : ok(req, `<html>sign in</html>`, 401);
    });
    const out = await run(s, "probe_cache", { url: "https://app.test/account" });
    assert.equal(out.verdict, "CONFIRMED");
    assert.equal(out.category, "info-disclosure");
    assert.equal((out.positiveReplays as string[]).length, 2);
  });
});

test("probe_cache reports UNVERIFIED when deception suffixes do not serve the private body", async () => {
  await withDir(async (dir) => {
    const authed = (req: Req) => Boolean(req.headers?.cookie ?? req.headers?.authorization);
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      if (req.url.endsWith("/account")) return authed(req) ? ok(req, `PRIVATE_${"y".repeat(200)}`) : ok(req, "denied", 401);
      return ok(req, "not found", 404);
    });
    const out = await run(s, "probe_cache", { url: "https://app.test/account" });
    assert.equal(out.verdict, "UNVERIFIED");
    assert.match(out.note as string, /no deception suffix/);
  });
});

// ── probe_method_bypass ──────────────────────────────────────────────────────
test("probe_method_bypass flags a denial→accept method flip as suspected bypass", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      if (req.method === "PUT") return ok(req, `{"deleted":true,"id":42}`);
      return ok(req, `{"error":"forbidden"}`, 403);
    });
    const out = await run(s, "probe_method_bypass", { url: "https://app.test/api/thing/42" });
    assert.equal(out.verdict, "SUSPECTED-BYPASS");
    const matrix = out.matrix as Array<{ method: string; status: number; denied: boolean }>;
    assert.ok(matrix.find((m) => m.method === "GET")?.denied);
    assert.ok(matrix.find((m) => m.method === "PUT" && !m.denied));
  });
});

// ── probe_rate_limit ─────────────────────────────────────────────────────────
test("probe_rate_limit: 429 mid-burst = ENFORCED; all-200 on /login = UNBOUNDED-LEAD", async () => {
  await withDir(async (dir) => {
    let n = 0;
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      n++;
      return n >= 5 ? ok(req, "too many", 429) : ok(req, `{"ok":true}`);
    });
    const out = await run(s, "probe_rate_limit", { url: "https://app.test/login", count: 10 });
    assert.equal(out.verdict, "ENFORCED");
    assert.equal(out.enforcedAt, 4);
  });
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, `{"ok":true}`));
    const out = await run(s, "probe_rate_limit", { url: "https://app.test/login", count: 10 });
    assert.equal(out.verdict, "UNBOUNDED-LEAD");
    assert.equal(out.count, 10);
  });
});

// ── analyze_saml ─────────────────────────────────────────────────────────────
test("analyze_saml decodes a response and flags unsigned/missing-conditions leads", async () => {
  await withDir(async (dir) => {
    const xml = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Issuer>https://idp.example</saml:Issuer><saml:Assertion><saml:Subject><saml:NameID>a@b.c</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`;
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""));
    const out = await run(s, "analyze_saml", { samlResponse: Buffer.from(xml).toString("base64") });
    const leads = out.leads as string[];
    assert.ok(leads.some((l) => /NO signature/i.test(l)), `expected unsigned lead, got ${leads}`);
    assert.ok(leads.some((l) => /Conditions/i.test(l)), `expected conditions lead`);
    assert.ok(leads.some((l) => /NotOnOrAfter/i.test(l)));
  });
});

// ── probe_deser ──────────────────────────────────────────────────────────────
test("probe_deser names the deserializer when a format-specific error returns", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const decoded = decodeURIComponent(req.body ?? "");
      if (decoded.includes('O:13:"VERDICT_NOPE"')) {
        return ok(req, `<b>Warning</b>: unserialize(): Error at offset 0 of 21 bytes — __PHP_Incomplete_Class`, 500);
      }
      return ok(req, `{"ok":true}`);
    });
    const out = await run(s, "probe_deser", { url: "https://app.test/import", param: "data" });
    assert.equal(out.verdict, "CONSUMES-SERIALIZED");
    const results = out.results as Array<{ fmt: string; consumed: boolean }>;
    assert.ok(results.find((r) => r.fmt === "php")?.consumed);
  });
});

// ── probe_method_bypass: verb tunneling ─────────────────────────────────────
test("probe_method_bypass tunnels verbs via X-HTTP-Method-Override when baseline is denied", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const tunneled = req.headers?.["X-HTTP-Method-Override"] === "PUT" || req.url.includes("_method=PUT");
      if (tunneled && req.method === "POST") return ok(req, `{"deleted":true}`);
      return ok(req, `{"error":"forbidden"}`, 403);
    });
    const out = await run(s, "probe_method_bypass", { url: "https://app.test/api/thing/42" });
    assert.equal(out.verdict, "SUSPECTED-BYPASS");
    const matrix = out.matrix as Array<{ method: string; denied: boolean }>;
    assert.ok(matrix.some((m) => /X-HTTP-Method-Override|_method/.test(m.method) && !m.denied), `expected a tunnel leg to reach, got ${JSON.stringify(matrix)}`);
  });
});

// ── probe_cache_poison ───────────────────────────────────────────────────────
test("probe_cache_poison confirms when a primed key replays the injected header value to plain GETs", async () => {
  await withDir(async (dir) => {
    const poisoned = new Map<string, string>();
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const xfh = req.headers?.["X-Forwarded-Host"];
      if (xfh) {
        poisoned.set(req.url, xfh); // cache stores this response under the URL key
        return ok(req, `<a href="https://${xfh}/x">go</a>`);
      }
      const stored = poisoned.get(req.url);
      if (stored) return ok(req, `<a href="https://${stored}/x">go</a>`); // served from cache, no header needed
      return ok(req, `<html>clean</html>`);
    });
    const out = await run(s, "probe_cache_poison", { url: "https://app.test/page" });
    assert.equal(out.verdict, "CONFIRMED");
    assert.equal(out.poisonedHeader, "X-Forwarded-Host");
    assert.equal((out.positiveReplays as string[]).length, 2);
    assert.notEqual(out.negativeControl, (out.positiveReplays as string[])[0]);
  });
});

test("probe_cache_poison is clean when the cache keys on the header (completed negative)", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const xfh = req.headers?.["X-Forwarded-Host"];
      return ok(req, xfh ? `<a href="https://${xfh}/x">go</a>` : `<html>clean</html>`); // reflected only with header
    });
    const out = await run(s, "probe_cache_poison", { url: "https://app.test/page" });
    assert.equal(out.verdict, "NOT CONFIRMED");
    assert.equal(out.result, "clean");
    assert.match(out.reason as string, /keyed|shared cache/i);
  });
});

// ── probe_smuggling (raw loopback socket simulating front/back agreement) ────
async function desyncServer(mode: "vulnerable" | "consistent" | "hardened"): Promise<{ port: number; close: () => Promise<void> }> {
  const socks = new Set<Socket>();
  const srv: Server = createServer((sock) => {
    socks.add(sock);
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const headEnd = buf.indexOf("\r\n\r\n");
      if (headEnd < 0) return;
      const head = buf.subarray(0, headEnd).toString("latin1").toLowerCase();
      const body = buf.subarray(headEnd + 4);
      const cl = Number(head.match(/content-length: (\d+)/)?.[1] ?? -1);
      const hasTe = head.includes("transfer-encoding: chunked");
      if (mode === "hardened" && hasTe && cl >= 0) {
        sock.write("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
        return;
      }
      const respond = () => sock.write("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
      if (!hasTe) {
        if (body.length >= cl) respond();
        return; // wait for more body or hang
      }
      if (mode === "vulnerable") {
        // CL.TE: front-CL needs `cl` bytes, then back-TE needs a complete `0\r\n\r\n` in those bytes
        if (body.length < cl) return; // front still waiting
        if (!body.subarray(0, cl).toString("latin1").includes("0\r\n\r\n")) return; // back-TE waits
        respond();
      } else {
        // consistent CL.CL: respond exactly when the declared body arrived
        if (body.length === cl) respond();
      }
    });
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => socks.delete(sock));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  return { port, close: async () => { for (const s of socks) s.destroy(); await new Promise<void>((r) => srv.close(() => r())); } };
}

test("probe_smuggling: dual-timeout on a vulnerable pair = SUSPECTED-DESYNC (never confirmed)", async () => {
  const srv = await desyncServer("vulnerable");
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_smuggling", { url: base, timeoutMs: 600 });
      assert.equal(out.verdict, "SUSPECTED-DESYNC");
      const legs = out.legs as Array<{ tag: string; timedOut: boolean }>;
      assert.ok(legs.find((l) => /P2/.test(l.tag))?.timedOut && legs.find((l) => /P3/.test(l.tag))?.timedOut);
    });
  } finally {
    await srv.close();
  }
});

test("probe_smuggling: one-timeout consistent pair = CONSISTENT, not a lead", async () => {
  const srv = await desyncServer("consistent");
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_smuggling", { url: base, timeoutMs: 600 });
      assert.equal(out.verdict, "CONSISTENT");
    });
  } finally {
    await srv.close();
  }
});

test("probe_smuggling: dual-header 400 = HARDENED", async () => {
  const srv = await desyncServer("hardened");
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_smuggling", { url: base, timeoutMs: 600 });
      assert.equal(out.verdict, "HARDENED");
    });
  } finally {
    await srv.close();
  }
});

// ── probe_crlf ──────────────────────────────────────────────────────────────
test("probe_crlf confirms when ≥2 encodings split a marker header into the response", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const q = req.url.split("vcr=")[1] ?? "";
      if (q.startsWith("%0d%0aX-VCrlf") || q.startsWith("%0aX-VCrlf")) {
        return ok(req, `<html>ok</html>`, 200, { "x-vcrlf": /X-VCrlf:%20(\S+)/.exec(q)?.[1] ?? "x" });
      }
      return ok(req, `<html>ok</html>`);
    });
    const out = await run(s, "probe_crlf", { url: "https://app.test/search" });
    assert.equal(out.verdict, "CONFIRMED");
    assert.equal(out.category, "crlf-injection");
    assert.equal((out.positiveReplays as string[]).length, 2);
  });
});

test("probe_crlf reports CLEAN-HERE when nothing splits", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, `<html>ok</html>`));
    const out = await run(s, "probe_crlf", { url: "https://app.test/search" });
    assert.equal(out.verdict, "CLEAN-HERE");
  });
});

// ── probe_host_header (raw socket — Host control) ────────────────────────────
async function hostReflectServer(): Promise<{ port: number; close: () => Promise<void> }> {
  const socks = new Set<Socket>();
  const srv: Server = createServer((sock) => {
    socks.add(sock);
    let buf = Buffer.alloc(0);
    sock.on("data", (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (!buf.includes("\r\n\r\n")) return;
      const head = buf.toString("latin1");
      const host = /^Host: (.*)$/im.exec(head)?.[1]?.trim() ?? "";
      const xfh = /^X-Forwarded-Host: (.*)$/im.exec(head)?.[1]?.trim();
      const absHost = /^GET http:\/\/([^/\s]+)/im.exec(head)?.[1];
      const effective = xfh ?? absHost ?? host;
      const body = `<html><link rel="canonical" href="http://${effective}/"></html>`;
      sock.write(`HTTP/1.1 200 OK\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`);
    });
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => socks.delete(sock));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  return { port, close: async () => { for (const s of socks) s.destroy(); await new Promise<void>((r) => srv.close(() => r())); } };
}

test("probe_host_header confirms multi-vector host reflection", async () => {
  const srv = await hostReflectServer();
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_host_header", { url: base, timeoutMs: 1500 });
      assert.equal(out.verdict, "CONFIRMED");
      const legs = out.legs as Array<{ tag: string; reflected: boolean }>;
      assert.ok(legs.filter((l) => l.reflected).length >= 2);
      assert.ok(!legs.find((l) => /control/.test(l.tag))?.reflected);
    });
  } finally {
    await srv.close();
  }
});

// ── probe_deser: ruby + viewstate ────────────────────────────────────────────
test("probe_deser: ruby marshal + viewstate formats reach their deserializers", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const decoded = decodeURIComponent(req.body ?? "");
      if (decoded.includes("\x04\x08o:")) return ok(req, `ArgumentError: undefined class/module VERDICT_NOPE`, 500);
      if (decoded.includes("_MAC_TAMPER")) return ok(req, `ViewStateException: Invalid viewstate. Validation of viewstate MAC failed`, 500);
      return ok(req, `{"ok":true}`);
    });
    const out = await run(s, "probe_deser", { url: "https://app.test/import", param: "data", formats: ["ruby", "viewstate"] });
    const results = out.results as Array<{ fmt: string; consumed: boolean }>;
    assert.equal(out.verdict, "CONSUMES-SERIALIZED");
    assert.ok(results.find((r) => r.fmt === "ruby")?.consumed);
    assert.ok(results.find((r) => r.fmt === "viewstate")?.consumed);
  });
});

// ── probe_xxe: alternate exfil legs (XInclude / parameter-entity) ───────────
test("probe_xxe confirms via XInclude+param-entity legs when classic file reads miss", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const b = req.body ?? "";
      if (b.includes("XInclude")) return ok(req, `<v>root:x:0:0:root:/root:/bin/bash</v>`);
      if (b.includes("% a SYSTEM") || b.includes("%25%20a%20SYSTEM")) return ok(req, `error: entity 'c' -> ; for 16-bit app support\n[fonts]`);
      if (b.includes("&c;") || b.includes("%26c%3B")) return ok(req, `<v>${/ENTITY c "([^"]+)"/.exec(decodeURIComponent(b))?.[1] ?? tokMarker(b)}</v>`);
      return ok(req, `<v>plain</v>`);
    });
    const out = await run(s, "probe_xxe", { url: "https://app.test/xml" });
    assert.equal(out.verdict, "CONFIRMED");
    assert.match(out.effectMarker as string, /alternate exfil legs/);
  });
});
function tokMarker(b: string): string {
  return /vXxe[0-9a-z]+/.exec(b)?.[0] ?? "";
}

// ── probe_oauth ──────────────────────────────────────────────────────────────
const AUTHORIZE = "https://app.test/oauth/authorize?client_id=web&redirect_uri=https%3A%2F%2Fapp.test%2Fcb&response_type=code&scope=openid";

test("probe_oauth confirms open redirect_uri when ≥2 tampered URIs 302 to the marker", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const u = new URL(req.url);
      const ru = u.searchParams.get("redirect_uri") ?? "";
      // AS validates only the scheme — any host is honored (vulnerable)
      if (ru.startsWith("https://")) return { ...ok(req, ""), status: 302, headers: { location: `${ru}?code=abc` } };
      return ok(req, "invalid uri", 400);
    });
    const out = await run(s, "probe_oauth", { authorizeUrl: AUTHORIZE });
    assert.equal(out.verdict, "CONFIRMED");
    assert.equal(out.category, "oauth-misconfig");
    const leads = out.staticLeads as string[];
    assert.ok(leads.some((l) => /state/i.test(l)), `expected missing-state lead, got ${leads}`);
  });
});

test("probe_oauth: strict AS rejecting tampered URIs → CLEAN-HERE; login-gated → UNVERIFIED", async () => {
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      const u = new URL(req.url);
      const ru = u.searchParams.get("redirect_uri") ?? "";
      if (ru === "https://app.test/cb") return { ...ok(req, ""), status: 302, headers: { location: "https://app.test/cb?code=abc" } };
      return ok(req, "redirect_uri mismatch", 400);
    });
    const out = await run(s, "probe_oauth", { authorizeUrl: AUTHORIZE });
    assert.equal(out.verdict, "CLEAN-HERE");
  });
  await withDir(async (dir) => {
    const s = fakeSession(dir, async (req: Req): Promise<Res> => {
      return { ...ok(req, ""), status: 302, headers: { location: "https://app.test/login?next=/oauth/authorize" } };
    });
    const out = await run(s, "probe_oauth", { authorizeUrl: AUTHORIZE });
    assert.equal(out.verdict, "UNVERIFIED");
  });
});

// ── probe_websocket (real loopback socket — a fake WS endpoint) ──────────────
async function fakeWsServer(accept: (headers: string) => number, opts: { frameOnEvil?: boolean; echo?: boolean } = {}): Promise<{ port: number; close: () => Promise<void> }> {
  const socks = new Set<Socket>();
  const srv: Server = createServer((sock) => {
    socks.add(sock);
    let buf = Buffer.alloc(0);
    let done = false;
    sock.on("data", (chunk) => {
      if (done) return;
      buf = Buffer.concat([buf, chunk]);
      const head = buf.toString("latin1");
      if (!head.includes("\r\n\r\n")) return;
      done = true;
      const status = accept(head.toLowerCase());
      const accepted = status === 101;
      sock.write(accepted ? "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: x\r\n\r\n" : `HTTP/1.1 ${status} Forbidden\r\nContent-Length: 0\r\n\r\n`);
      if (accepted && opts.frameOnEvil && head.toLowerCase().includes("evil.example")) {
        const payload = Buffer.from(`{"secret":"x"}`);
        sock.write(Buffer.concat([Buffer.from([0x81, payload.length]), payload])); // unmasked server frame
      }
      if (accepted && opts.echo) {
        sock.once("data", (frame: Buffer) => {
          // minimal masked-frame decode → echo the payload back as a server frame
          const len = frame[1]! & 0x7f;
          const mask = frame.subarray(2, 6);
          const out = Buffer.alloc(len);
          for (let i = 0; i < len; i++) out[i] = frame[6 + i]! ^ mask[i % 4]!;
          sock.write(Buffer.concat([Buffer.from([0x81, out.length]), out]));
        });
      }
    });
    sock.on("close", () => socks.delete(sock));
    sock.on("error", () => socks.delete(sock));
  });
  await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
  const port = (srv.address() as { port: number }).port;
  return {
    port,
    close: async () => {
      for (const s of socks) s.destroy();
      await new Promise<void>((r) => srv.close(() => r()));
    },
  };
}

test("probe_websocket: unauth+forged-origin 101s surface CSWSH/unauth leads", async () => {
  const srv = await fakeWsServer(() => 101);
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_websocket", { url: `ws://127.0.0.1:${srv.port}/sock`, timeoutMs: 300 });
      assert.equal(out.verdict, "LEADS");
      const leads = out.leads as string[];
      assert.ok(leads.some((l) => /unauthenticated/i.test(l)));
      assert.ok(leads.some((l) => /Origin/i.test(l)));
    });
  } finally {
    await srv.close();
  }
});

test("probe_websocket: forged-Origin leg receiving a server frame upgrades the CSWSH lead", async () => {
  const srv = await fakeWsServer(() => 101, { frameOnEvil: true });
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_websocket", { url: `ws://127.0.0.1:${srv.port}/sock`, timeoutMs: 300 });
      const leads = out.leads as string[];
      assert.ok(leads.some((l) => /cross-origin data read demonstrated/i.test(l)), `expected frame-received lead, got ${leads}`);
      assert.ok((out.evilOrigin as { firstFrame?: { payloadPreview?: string } }).firstFrame?.payloadPreview?.includes("secret"));
    });
  } finally {
    await srv.close();
  }
});

test("probe_websocket: message echo on forged-Origin leg = bidirectional CSWSH lead", async () => {
  const srv = await fakeWsServer(() => 101, { echo: true });
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_websocket", { url: `ws://127.0.0.1:${srv.port}/sock`, message: "vprobe-marker", timeoutMs: 400 });
      const leads = out.leads as string[];
      assert.ok(leads.some((l) => /bidirectional|ANSWERED our message/i.test(l)), `expected echo lead, got ${leads}`);
      assert.ok((out.evilOrigin as { echoed?: boolean }).echoed);
    });
  } finally {
    await srv.close();
  }
});

test("probe_websocket: denied legs report enforcement, not a finding", async () => {
  const srv = await fakeWsServer((head) => (head.includes("sec-websocket-key") && head.includes("cookie:") ? 101 : 401));
  try {
    await withDir(async (dir) => {
      const base = `http://127.0.0.1:${srv.port}/`;
      const s = fakeSession(dir, async (req: Req): Promise<Res> => ok(req, ""), { base });
      const out = await run(s, "probe_websocket", { url: `ws://127.0.0.1:${srv.port}/sock`, timeoutMs: 300 });
      // unauth → 401; forged-origin carries the session cookie → accepted → CSWSH lead only
      assert.equal(out.verdict, "LEADS");
      const leads = out.leads as string[];
      assert.ok(leads.some((l) => /Origin/i.test(l)) && !leads.some((l) => /unauthenticated/i.test(l)));
    });
  } finally {
    await srv.close();
  }
});
