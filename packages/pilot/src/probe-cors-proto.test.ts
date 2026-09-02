// probe_cors + probe_proto through the real tool handlers (FakeHttpClient): a reflecting-Origin server confirms CORS;
// a deep-merge server that leaks an injected __proto__ property confirms prototype pollution.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";

const BASE = "https://app.test/";
type Req = { url: string; method?: string; headers?: Record<string, string>; body?: string | null };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string };

function fakeSession(dir: string, send: (req: Req) => Promise<Res>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE), targetUrl: BASE, currentScreenId: "s-1", currentCookie: "", currentBearer: "",
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
}
async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: Req) => Promise<Res>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  (s as unknown as { store: AssessmentStore }).store.close();
  return JSON.parse(out.content[0]!.text);
}
function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-cp-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("probe_cors confirms arbitrary-origin reflection WITH credentials (high)", () =>
  withDir(async (dir) => {
    const send = async (req: Req): Promise<Res> => {
      const origin = req.headers?.origin;
      const headers: Record<string, string> = origin ? { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } : {};
      return { status: 200, finalUrl: req.url, durationMs: 3, headers, body: "{}" };
    };
    const r = await callTool(dir, "probe_cors", { url: BASE + "api/me" }, send);
    assert.equal(r.confirmed, true);
    assert.equal(r.severity, "high");
    assert.ok(Array.isArray(r.positiveReplays) && (r.positiveReplays as unknown[]).length === 2);
  }));

test("probe_cors does NOT confirm a server that ignores Origin", () =>
  withDir(async (dir) => {
    const send = async (req: Req): Promise<Res> => ({ status: 200, finalUrl: req.url, durationMs: 3, headers: {}, body: "{}" });
    const r = await callTool(dir, "probe_cors", { url: BASE + "api/me" }, send);
    assert.equal(r.confirmed, false);
  }));

test("probe_proto confirms a deep-merge sink that leaks the injected __proto__ property", () =>
  withDir(async (dir) => {
    let polluted = false;
    const send = async (req: Req): Promise<Res> => {
      if ((req.method ?? "GET").toUpperCase() === "POST" && (req.body ?? "").includes("__proto__")) {
        polluted = true;
        return { status: 200, finalUrl: req.url, durationMs: 3, headers: {}, body: "{}" };
      }
      // GET follow-up: after pollution the app serializes an object that now inherits the polluted property
      return { status: 200, finalUrl: req.url, durationMs: 3, headers: {}, body: polluted ? '{"ok":true,"verdictPP9137":"verdictPP9137VAL"}' : '{"ok":true}' };
    };
    const r = await callTool(dir, "probe_proto", { url: BASE + "api/profile", followUrl: BASE + "api/config" }, send);
    assert.equal(r.confirmed, true);
    assert.equal(r.effectMarker, "verdictPP9137VAL");
  }));

test("probe_proto does NOT confirm when nothing leaks", () =>
  withDir(async (dir) => {
    const send = async (req: Req): Promise<Res> => ({ status: 200, finalUrl: req.url, durationMs: 3, headers: {}, body: '{"ok":true}' });
    const r = await callTool(dir, "probe_proto", { url: BASE + "api/profile" }, send);
    assert.equal(r.confirmed, false);
  }));
