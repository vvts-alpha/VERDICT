// probe_nosql end-to-end through the real tool handler (FakeHttpClient): SQL-only probing leaves a Mongo-backed app
// looking clean, so this fires operator payloads ({$ne:null}) + a $where sleep and confirms via the bypass/time oracle.
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

type Req = { url: string; body?: string | null };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string };

function fakeSession(dir: string, send: (req: Req) => Promise<Res>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  const http = { send, effectiveHeaders: (h: Record<string, string>) => h };
  return {
    http, store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
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
  const dir = mkdtempSync(join(tmpdir(), "veritas-nosql-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const parsePw = (body: string | null | undefined): unknown => { try { return JSON.parse(body ?? "").password; } catch { return undefined; } };

test("probe_nosql confirms a Mongo $ne auth-bypass on a login endpoint (operator succeeds, string fails)", () =>
  withDir(async (dir) => {
    // password as an OPERATOR OBJECT bypasses; a plain string 401s (classic Mongo auth bypass).
    const send = async (req: Req): Promise<Res> => {
      const pw = parsePw(req.body);
      const bypass = pw !== null && typeof pw === "object";
      return { status: bypass ? 200 : 401, finalUrl: req.url, durationMs: 4, headers: {}, body: bypass ? '{"authentication":{"token":"eyJabc"}}' : "Invalid email or password" };
    };
    const r = await callTool(dir, "probe_nosql", { url: BASE + "rest/user/login", body: '{"email":"admin@x","password":{{NOSQL}}}', successMarker: "authentication" }, send);
    assert.equal(r.technique, "operator-bypass");
    assert.ok(typeof r.negativeControl === "string" && Array.isArray(r.positiveReplays) && (r.positiveReplays as unknown[]).length === 2);
  }));

test("probe_nosql confirms blind $where time-based injection", () =>
  withDir(async (dir) => {
    // operators do NOT bypass (always 200, same body), but a $where sleep delays — the blind case.
    const send = async (req: Req): Promise<Res> => {
      const slept = (req.body ?? "").includes("$where") && (req.body ?? "").includes("sleep");
      return { status: 200, finalUrl: req.url, durationMs: slept ? 3200 : 5, headers: {}, body: '{"results":[]}' };
    };
    const r = await callTool(dir, "probe_nosql", { url: BASE + "api/find", body: '{"filter":{{NOSQL}}}' }, send);
    assert.equal(r.technique, "time-based");
  }));

test("probe_nosql does NOT confirm a non-injectable login (control and operators both fail)", () =>
  withDir(async (dir) => {
    const send = async (req: Req): Promise<Res> => ({ status: 401, finalUrl: req.url, durationMs: 4, headers: {}, body: "Invalid email or password" });
    const r = await callTool(dir, "probe_nosql", { url: BASE + "rest/user/login", body: '{"email":"admin@x","password":{{NOSQL}}}', successMarker: "authentication" }, send);
    assert.equal(r.technique, null);
  }));
