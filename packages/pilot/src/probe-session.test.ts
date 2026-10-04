// analyze_session's deterministic session-cookie attribute audit (absence class, FakeHttpClient):
// the session cookie's Set-Cookie flags (Secure/HttpOnly/SameSite/Domain scope) are checked mechanically
// over two authed GETs like probe_headers — noise cookies (locale/lang/csrf/analytics) are never checked,
// unstable replays confirm nothing, unknown flags are never inferred, and record_finding's session absence
// gate re-parses the cited Set-Cookie end-to-end (rejects when the attribute is actually present).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

type Req = { url: string; method?: string; headers?: Record<string, string>; body?: string | null };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string; truncated?: boolean };
type Tool = { name: string; handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };

function fakeSession(
  dir: string,
  send: (req: Req) => Promise<Res>,
  opts: { base?: string; currentCookie?: string } = {},
): PilotSession {
  const base = opts.base ?? "https://app.test/";
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(base),
    targetUrl: base,
    currentScreenId: "s-1",
    currentCookie: opts.currentCookie ?? "",
    currentBearer: "",
    currentRole: "alice",
    roleCreds: new Map([["alice", { username: "alice", password: "x" }]]),
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

/** Run a tool and parse its JSON output (record_finding returns a plain string — use runRaw for it). */
async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as Tool;
  return JSON.parse((await t.handler(args, {})).content[0]!.text) as Record<string, unknown>;
}

async function runRaw(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as Tool;
  return (await t.handler(args, {})).content[0]!.text;
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verdict-session-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const SID = "sid=a1b2c3d4e5f6789012345678";

/** Static fake: every GET returns the same status/body/set-cookie. */
function staticServer(status: number, setCookie: string, log: Req[] = []): (req: Req) => Promise<Res> {
  return async (req: Req): Promise<Res> => {
    log.push(req);
    return { status, finalUrl: req.url, durationMs: 2, headers: setCookie ? { "set-cookie": setCookie } : {}, body: "<html><body>me</body></html>" };
  };
}

type Det = { key: string; cookieName: string; severity: string; evidenceIds: string[] };

test("analyze_session confirms missing Secure/HttpOnly/SameSite on a bare https session cookie", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; Path=/`), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    const det = out.deterministic as Det[];
    assert.deepEqual(
      det.map((f) => [f.key, f.severity]),
      [
        ["secure", "medium"],
        ["httponly", "medium"],
        ["samesite", "low"],
      ],
    );
    assert.ok(det.every((f) => f.cookieName === "sid"));
    const nc = out.negativeControl as string;
    const pr = out.positiveReplays as string[];
    assert.ok(nc);
    assert.equal(pr.length, 2);
    assert.equal(pr[0], nc); // absence class: the control response is legitimately reused as positive #1
    assert.notEqual(pr[1], nc);
    assert.ok(det.every((f) => f.evidenceIds.includes(nc) && f.evidenceIds.includes(pr[1]!)));
    assert.match(String(out.deterministicVerdict), /SESSION COOKIE FLAG FINDINGS/);
    assert.equal((s as unknown as { httpProbes: number }).httpProbes, 2, "two authed GETs fired");
    // end-to-end: record_finding(category session, param secure) accepts the probe's evidence.
    assert.match(
      await runRaw(s, "record_finding", {
        title: "Session cookie without Secure",
        severity: "medium",
        category: "session",
        endpoint: "/me",
        param: "secure",
        description: "The sid session cookie is issued without the Secure attribute over https.",
        reproSteps: "GET /me (authed) twice; inspect Set-Cookie.",
        negativeControl: nc,
        positiveReplays: pr,
      }),
      /recorded|merged/,
    );
  }));

test("analyze_session reports no findings on a hardened session cookie", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; Secure; HttpOnly; SameSite=Lax; Path=/`), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
    assert.match(String(out.deterministicVerdict), /no deterministic session-cookie flag findings/);
  }));

test("noise cookies (locale/csrf/analytics) are never checked — only the session cookie", () =>
  withDir(async (dir) => {
    const setCookie = `lang=en; Path=/\nXSRF-TOKEN=t0k3n; Path=/\n${SID}; Secure; HttpOnly; SameSite=Lax; Path=/`;
    const s = fakeSession(dir, staticServer(200, setCookie), { currentCookie: `lang=en; XSRF-TOKEN=t0k3n; ${SID}` });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
  }));

test("SameSite=None without Secure trips samesite AND secure; with Secure only samesite", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; SameSite=None; HttpOnly`), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(
      (out.deterministic as Det[]).map((f) => f.key).sort(),
      ["samesite", "secure"],
    );
  }).then(() =>
    withDir(async (dir) => {
      const s = fakeSession(dir, staticServer(200, `${SID}; SameSite=None; HttpOnly; Secure`), { currentCookie: SID });
      const out = await run(s, "analyze_session", { url: "https://app.test/me" });
      assert.deepEqual(
        (out.deterministic as Det[]).map((f) => f.key),
        ["samesite"],
      );
    }),
  ));

test("unstable replays (status flip between the two GETs) confirm nothing", () =>
  withDir(async (dir) => {
    let n = 0;
    const s = fakeSession(dir, async (req: Req) => {
      n += 1;
      return { status: n === 1 ? 200 : 500, finalUrl: req.url, durationMs: 2, headers: { "set-cookie": `${SID}; Path=/` }, body: "<html>x</html>" };
    }, { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
    assert.match(String(out.deterministicVerdict), /unstable, not confirmed/);
  }));

test("record_finding rejects when the cited response actually HAS the attribute", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; Secure; HttpOnly; SameSite=Lax; Path=/`), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
    assert.match(
      await runRaw(s, "record_finding", {
        title: "Session cookie without HttpOnly",
        severity: "medium",
        category: "session",
        endpoint: "/me",
        param: "httponly",
        description: "x",
        reproSteps: "x",
        negativeControl: out.negativeControl,
        positiveReplays: out.positiveReplays,
      }),
      /REJECTED/,
    );
  }));

test("record_finding refuses these absence findings as verdict:suspected (no sessionGlance exemption)", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; Path=/`), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.match(
      await runRaw(s, "record_finding", {
        title: "Session cookie without Secure",
        severity: "medium",
        category: "session",
        endpoint: "/me",
        param: "secure",
        description: "x",
        reproSteps: "x",
        verdict: "suspected",
        anomaly: "The sid session cookie observed on the authed GET of /me carries no Secure attribute over https.",
        observation: out.evidenceId,
      }),
      /REJECTED/,
    );
  }));

test("domain-scope fires only when Domain is a parent of the request host", () =>
  withDir(async (dir) => {
    // app.corp.example with Domain=corp.example → the cookie flows to sibling subdomains.
    const s = fakeSession(dir, staticServer(200, `${SID}; Secure; HttpOnly; SameSite=Lax; Domain=corp.example; Path=/`), {
      base: "https://app.corp.example/",
      currentCookie: SID,
    });
    const out = await run(s, "analyze_session", { url: "https://app.corp.example/me" });
    assert.deepEqual(
      (out.deterministic as Det[]).map((f) => [f.key, f.severity]),
      [["domain-scope", "low"]],
    );
  }).then(() =>
    withDir(async (dir) => {
      // Domain == the request host itself is not a widening → no finding.
      const s = fakeSession(dir, staticServer(200, `${SID}; Secure; HttpOnly; SameSite=Lax; Domain=app.corp.example; Path=/`), {
        base: "https://app.corp.example/",
        currentCookie: SID,
      });
      const out = await run(s, "analyze_session", { url: "https://app.corp.example/me" });
      assert.deepEqual(out.deterministic, []);
    }),
  ));

test("secure is skipped on non-TLS targets (like HSTS)", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, `${SID}; Path=/`), { base: "http://app.test/", currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "http://app.test/me" });
    assert.deepEqual(
      (out.deterministic as Det[]).map((f) => f.key),
      ["httponly", "samesite"],
    );
  }));

test("no session cookie identified → deterministic [] with the probe_jwt note (Bearer/JWT sessions)", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, "lang=en; Path=/"), { currentCookie: "lang=en; pref=abc" });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
    const notes = (out.deterministicNotes as string[]) ?? [];
    assert.ok(notes.some((x) => /no session cookie identified/.test(x) && /probe_jwt/.test(x)));
  }));

test("no Set-Cookie and a flag-less jar → flags reported unknown, never inferred", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, staticServer(200, ""), { currentCookie: SID });
    const out = await run(s, "analyze_session", { url: "https://app.test/me" });
    assert.deepEqual(out.deterministic, []);
    const notes = (out.deterministicNotes as string[]) ?? [];
    assert.ok(notes.some((x) => /sid: .*unknown/.test(x)), `expected unknown notes, got ${JSON.stringify(notes)}`);
  }));
