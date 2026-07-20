// C: probe_race (concurrency / TOCTOU) and probe_reset_poison (in-band reset host-header poisoning). These classes used
// to only ever be recordable as "suspected"; the probes mechanically confirm them. Invokes the real MCP tool handlers
// (buildTools(...).handler) against a stateful fake http client.

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
const resp = (status: number, body: string, headers: Record<string, string> = {}) => ({ status, finalUrl: BASE, durationMs: 1, headers, body });

function fakeSession(dir: string, send: (req: { headers?: Record<string, string> }) => Promise<unknown>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  const http = { send, effectiveHeaders: (h: Record<string, string>) => h };
  return {
    http,
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    currentScreenId: "s-1",
    currentCookie: "",
    currentBearer: "",
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: { headers?: Record<string, string> }) => Promise<unknown>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  (s as unknown as { store: AssessmentStore }).store.close();
  return JSON.parse(out.content[0]!.text);
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-cx-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("probe_race CONFIRMS when a single-use action is overrun by concurrency (>=2 succeed)", async () => {
  await withDir(async (dir) => {
    let n = 0; // the "coupon" is overrun: the first 3 concurrent redemptions slip through, the rest are rejected
    const send = async () => (++n <= 3 ? resp(200, `{"status":"redeemed","order":${n}}`) : resp(409, '{"error":"already redeemed"}'));
    const out = await callTool(dir, "probe_race", { url: `${BASE}redeem`, body: '{"coupon":"X"}', successMarker: "redeemed", count: 10 }, send);
    assert.match(String(out.verdict), /RACE CONDITION CONFIRMED/);
    assert.equal(out.concurrentSuccesses, 3);
    assert.equal((out.positiveReplays as string[]).length, 2);
    assert.ok(out.negativeControl, "a rejected concurrent attempt is the control");
  });
});

test("probe_race does NOT confirm a concurrency-safe limit (only 1 succeeds)", async () => {
  await withDir(async (dir) => {
    let n = 0;
    const send = async () => (++n === 1 ? resp(200, '{"status":"redeemed"}') : resp(409, '{"error":"already redeemed"}'));
    const out = await callTool(dir, "probe_race", { url: `${BASE}redeem`, body: "{}", successMarker: "redeemed", count: 10 }, send);
    assert.match(String(out.verdict), /^not confirmed/);
  });
});

test("probe_reset_poison CONFIRMS in-band poisoning (attacker host reflected in the reset response)", async () => {
  await withDir(async (dir) => {
    // the reset link in the response is built from X-Forwarded-Host when present
    const send = async (req: { headers?: Record<string, string> }) => {
      const host = req.headers?.["x-forwarded-host"] || "app.test";
      return resp(200, `{"message":"reset link sent: https://${host}/reset?token=abc"}`);
    };
    const out = await callTool(dir, "probe_reset_poison", { url: `${BASE}reset`, body: '{"email":"victim@x.io"}' }, send);
    assert.match(String(out.verdict), /RESET HOST-HEADER POISONING CONFIRMED/);
    const r = out.reflected as { control: boolean; poisoned1: boolean };
    assert.ok(r.poisoned1 && !r.control);
  });
});

test("probe_reset_poison does NOT confirm when the response doesn't echo the forwarded host (email-only)", async () => {
  await withDir(async (dir) => {
    const send = async () => resp(200, '{"message":"if the account exists, a reset email was sent"}'); // canonical host, nothing reflected
    const out = await callTool(dir, "probe_reset_poison", { url: `${BASE}reset`, body: '{"email":"victim@x.io"}' }, send);
    assert.match(String(out.verdict), /not confirmed IN-BAND/);
  });
});
