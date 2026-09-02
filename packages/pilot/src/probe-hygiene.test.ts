import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { HttpRequest } from "@veritas/scanner";

const BASE = "https://app.test/";
const resp = (status: number, body: string, headers: Record<string, string> = {}) => ({
  status,
  finalUrl: BASE,
  durationMs: 1,
  headers,
  body,
});

function fakeSession(
  dir: string,
  send: (req: HttpRequest) => Promise<unknown>,
  extra: { currentCookie?: string; currentBearer?: string; currentRole?: string } = {},
): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    currentScreenId: "s-1",
    currentCookie: extra.currentCookie ?? "",
    currentBearer: extra.currentBearer ?? "",
    currentRole: extra.currentRole ?? "",
    roleCreds: extra.currentRole ? new Map([[extra.currentRole, { username: extra.currentRole, password: "x" }]]) : new Map(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: HttpRequest) => Promise<unknown>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  s.store.close();
  return JSON.parse(out.content[0]!.text);
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-hyg-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("probe_user_enum CONFIRMS wrong-password vs user-not-found", async () => {
  await withDir(async (dir) => {
    const send = async (req: HttpRequest) => {
      const blob = `${req.url} ${req.body ?? ""}`;
      if (blob.includes("alice")) return resp(401, '{"error":"invalid password"}');
      return resp(401, '{"error":"user not found"}');
    };
    const out = await callTool(dir, "probe_user_enum", { url: `${BASE}login`, body: "user={{USER}}&password=x", validUser: "alice" }, send);
    assert.match(String(out.verdict), /USER ENUMERATION CONFIRMED/);
    assert.ok(out.effectMarker);
    assert.equal((out.positiveReplays as string[]).length, 2);
  });
});

test("probe_user_enum does NOT confirm identical generic errors", async () => {
  await withDir(async (dir) => {
    const send = async () => resp(401, '{"error":"invalid credentials"}');
    const out = await callTool(dir, "probe_user_enum", { url: `${BASE}login`, body: "user={{USER}}", validUser: "alice" }, send);
    assert.match(String(out.verdict), /not confirmed/);
  });
});

test("probe_user_enum CONFIRMS a status flip (200 vs 404)", async () => {
  await withDir(async (dir) => {
    const send = async (req: HttpRequest) =>
      (req.body ?? "").includes("alice") ? resp(200, "ok") : resp(404, "nope");
    const out = await callTool(dir, "probe_user_enum", { url: `${BASE}login`, body: '{"user":"{{USER}}"}', validUser: "alice" }, send);
    assert.match(String(out.verdict), /USER ENUMERATION CONFIRMED/);
    assert.equal(out.effectMarker, "status:200");
  });
});

test("probe_secrets CONFIRMS directory listing vs clean 404 control", async () => {
  await withDir(async (dir) => {
    const send = async (req: HttpRequest) =>
      req.url.includes("verdict-nonexistent") ? resp(404, "not found") : resp(200, "<html><title>Index of /backup</title>");
    const out = await callTool(dir, "probe_secrets", { url: `${BASE}backup/` }, send);
    assert.match(String(out.verdict), /INFO DISCLOSURE CONFIRMED/);
    assert.equal(out.category, "info-disclosure");
    assert.equal(out.effectMarker, "Index of");
  });
});

test("probe_user_enum does not attach the session cookie/Bearer (pre-auth surface)", async () => {
  await withDir(async (dir) => {
    const seen: HttpRequest[] = [];
    const send = async (req: HttpRequest) => {
      seen.push(req);
      return resp(401, '{"error":"invalid credentials"}');
    };
    const s = fakeSession(dir, send, { currentCookie: "sid=authed", currentBearer: "eyJ.live.tok" });
    const t = buildTools(s).find((x) => (x as { name: string }).name === "probe_user_enum") as {
      handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>;
    };
    await t.handler({ url: `${BASE}login`, body: "user={{USER}}", validUser: "alice" }, {});
    s.store.close();
    assert.ok(seen.length >= 3);
    for (const req of seen) {
      const h = req.headers ?? {};
      assert.equal(h.cookie ?? h.Cookie, undefined);
      assert.equal(h.authorization ?? h.Authorization, undefined);
    }
  });
});

test("probe_secrets does NOT confirm a Maps JavaScript API key in the loader", async () => {
  await withDir(async (dir) => {
    const key = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";
    const html = `<script src="https://maps.googleapis.com/maps/api/js?v=weekly&key=${key}"></script>`;
    const send = async (req: HttpRequest) =>
      req.url.includes("verdict-nonexistent") ? resp(404, "not found") : resp(200, html);
    const out = await callTool(dir, "probe_secrets", { url: `${BASE}` }, send);
    assert.match(String(out.verdict), /not confirmed/);
  });
});

test("probe_secrets CONFIRMS a live AWS key vs a clean control", async () => {
  await withDir(async (dir) => {
    const key = "AKIA" + "ABCDEFGHIJKLMNOP";
    const send = async (req: HttpRequest) =>
      req.url.includes("verdict-nonexistent") ? resp(404, "not found") : resp(200, `AWS_ACCESS_KEY_ID=${key}`);
    const out = await callTool(dir, "probe_secrets", { url: `${BASE}.env` }, send);
    assert.match(String(out.verdict), /SECRET EXPOSURE CONFIRMED/);
    assert.equal(out.category, "secret-exposure");
  });
});

test("probe_headers reports missing CSP (and does not invent a hit when CSP is present)", async () => {
  await withDir(async (dir) => {
    const send = async () => resp(200, "ok", { "content-type": "text/html" });
    const out = await callTool(dir, "probe_headers", { url: `${BASE}` }, send);
    assert.match(String(out.verdict), /MISSING HEADERS/);
    const missing = out.missing as Array<{ key: string }>;
    assert.ok(missing.some((m) => m.key === "csp"));
  });
  await withDir(async (dir) => {
    const send = async () =>
      resp(200, "ok", {
        "content-security-policy": "default-src 'self'",
        "strict-transport-security": "max-age=31536000",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "geolocation=()",
      });
    const out = await callTool(dir, "probe_headers", { url: `${BASE}` }, send);
    assert.match(String(out.verdict), /not confirmed/);
    assert.equal((out.missing as unknown[]).length, 0);
  });
});

test("analyze_session dumps the live Cookie request for the model to judge", async () => {
  await withDir(async (dir) => {
    const send = async () => resp(200, "me", { "set-cookie": "session=alice; Path=/" });
    const s = fakeSession(dir, send, { currentCookie: "session=alice", currentRole: "alice" });
    const t = buildTools(s).find((x) => (x as { name: string }).name === "analyze_session") as {
      handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>;
    };
    const raw = await t.handler({ url: `${BASE}me` }, {});
    s.store.close();
    const out = JSON.parse(raw.content[0]!.text) as Record<string, unknown>;
    assert.ok(out.evidenceId);
    assert.match(String(out.requestDump), /Cookie: session=alice/);
    const cookies = out.cookies as Array<{ name: string; hints: string[] }>;
    assert.ok(cookies.some((c) => c.name === "session" && c.hints.some((h) => /alice/.test(h))));
  });
});

test("probe_ssrf CONFIRMS AWS metadata vs .invalid control", async () => {
  await withDir(async (dir) => {
    const send = async (req: HttpRequest) => {
      const blob = `${req.url} ${req.body ?? ""}`;
      if (blob.includes("169.254.169.254")) return resp(200, "ami-id\ninstance-id\niam/security-credentials/\n");
      return resp(502, "cannot fetch verdict-ssrf-control.invalid");
    };
    const out = await callTool(dir, "probe_ssrf", { url: `${BASE}stock`, param: "stockApi" }, send);
    assert.match(String(out.verdict), /IN-BAND SSRF CONFIRMED/);
    assert.equal(out.effectMarker, "ami-id");
    assert.equal((out.positiveReplays as string[]).length, 2);
  });
});

test("probe_ssrf does NOT confirm when the URL is only echoed", async () => {
  await withDir(async (dir) => {
    const send = async (req: HttpRequest) => resp(400, `bad host ${req.url}`);
    const out = await callTool(dir, "probe_ssrf", { url: `${BASE}stock`, param: "stockApi" }, send);
    assert.match(String(out.verdict), /not confirmed/);
  });
});

test("probe_upload CONFIRMS SVG XSS by fetching the returned URL", async () => {
  await withDir(async (dir) => {
    const store = new Map<string, string>();
    const send = async (req: HttpRequest) => {
      if (req.multipart?.files[0]) {
        const f = req.multipart.files[0];
        store.set(f.filename, Buffer.from(f.base64, "base64").toString("utf8"));
        return resp(200, JSON.stringify({ url: `${BASE}files/${f.filename}` }), { "content-type": "application/json" });
      }
      const name = req.url.split("/files/")[1] ?? "";
      const body = store.get(name) ?? "missing";
      return resp(200, body, { "content-type": "image/svg+xml" });
    };
    const out = await callTool(dir, "probe_upload", { url: `${BASE}upload` }, send);
    assert.match(String(out.verdict), /UPLOAD SVG XSS CONFIRMED/);
    assert.equal(out.category, "xss-stored");
    assert.ok(out.effectMarker);
  });
});

test("probe_upload does NOT confirm accept-alone (no fetch URL, no XXE)", async () => {
  await withDir(async (dir) => {
    const send = async () => resp(200, JSON.stringify({ ok: true, filename: "x.svg" }));
    const out = await callTool(dir, "probe_upload", { url: `${BASE}upload` }, send);
    assert.match(String(out.verdict), /not confirmed/);
    assert.equal(out.uploaded, true);
  });
});
