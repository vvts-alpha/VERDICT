// FAM-1 integration: probe_sqli can now aim its oracle at a request HEADER and a JSON body field (not just query/body).
// Invokes the real MCP tool handler (buildTools(...).handler) against a stateful fake http client (same pattern as
// race-reset.test.ts).
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

function fakeSession(dir: string, send: (req: { url: string; headers?: Record<string, string>; body?: string | null }) => Promise<unknown>): PilotSession {
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

async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: { url: string; headers?: Record<string, string>; body?: string | null }) => Promise<unknown>): Promise<Record<string, unknown>> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  (s as unknown as { store: AssessmentStore }).store.close();
  return JSON.parse(out.content[0]!.text);
}

function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-loc-"));
  return fn(dir).finally(() => rmSync(dir, { recursive: true, force: true }));
}

const hdr = (r: { headers?: Record<string, string> }, name: string): string => {
  const e = Object.entries(r.headers ?? {}).find(([k]) => k.toLowerCase() === name.toLowerCase());
  return e?.[1] ?? "";
};

test("probe_sqli confirms BLIND time-based SQLi injected into a request HEADER (X-Forwarded-For)", async () => {
  await withDir(async (dir) => {
    const sent: Array<{ url: string; headers?: Record<string, string> }> = [];
    const send = async (req: { url: string; headers?: Record<string, string> }) => {
      sent.push(req);
      const slow = /SLEEP\(5\)|pg_sleep|WAITFOR/i.test(hdr(req, "X-Forwarded-For"));
      return { status: 200, finalUrl: BASE, durationMs: slow ? 5200 : 3, headers: {}, body: '{"ok":true,"rows":3}' };
    };
    const out = await callTool(dir, "probe_sqli", { url: BASE + "search", location: "header:X-Forwarded-For" }, send);
    assert.equal(out.technique, "time-based");
    assert.ok(Array.isArray(out.positiveReplays) && (out.positiveReplays as unknown[]).length === 2);
    // the payload rode in the header, and NEVER leaked into the query string
    assert.ok(sent.some((r) => /SLEEP\(5\)/.test(hdr(r, "X-Forwarded-For"))), "a SLEEP payload was sent in the header");
    assert.ok(sent.every((r) => !new URL(r.url).search.includes("SLEEP")), "no payload leaked into the query");
  });
});

test("probe_sqli json location sends the payload as an application/json body field, not text/plain", async () => {
  await withDir(async (dir) => {
    const sent: Array<{ url: string; headers?: Record<string, string>; body?: string | null }> = [];
    const send = async (req: { url: string; headers?: Record<string, string>; body?: string | null }) => {
      sent.push(req);
      return { status: 200, finalUrl: BASE, durationMs: 3, headers: {}, body: '{"ok":true}' };
    };
    await callTool(dir, "probe_sqli", { url: BASE + "api/search", location: "json:/q" }, send);
    const jsonReqs = sent.filter((r) => hdr(r, "content-type") === "application/json");
    assert.ok(jsonReqs.length > 0, "at least one request was sent as application/json");
    // a probe payload actually landed inside the JSON field `q`
    assert.ok(
      jsonReqs.some((r) => {
        try {
          const v = (JSON.parse(r.body ?? "{}") as { q?: unknown }).q;
          return typeof v === "string" && v.length > 1;
        } catch {
          return false;
        }
      }),
      "a payload was placed in the JSON body field q",
    );
  });
});
