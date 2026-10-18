// probe_graphql through the real tool handler (FakeHttpClient): introspection exposure, field-suggestion leakage
// and batching acceptance are judged from raw GraphQL response shapes; an echo/catch-all server must confirm nothing;
// record_finding's marker gate accepts the probe's evidence end-to-end.
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
const fixtureStores = new Map<string, AssessmentStore>();
type Req = { url: string; method?: string; headers?: Record<string, string>; body?: string | null };
type Res = { status: number; finalUrl: string; durationMs: number; headers: Record<string, string>; body: string; truncated?: boolean };

function fakeSession(dir: string, send: (req: Req) => Promise<Res>): PilotSession {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  fixtureStores.set(dir, store);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return {
    http: { send, effectiveHeaders: (h: Record<string, string>) => h },
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(BASE), targetUrl: BASE, currentScreenId: "s-1", currentCookie: "", currentBearer: "", currentRole: "",
    roleCreds: new Map(), roleCookieFiles: new Map(), roleDescriptions: new Map(),
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
    findings: [], findingsByKey: new Map(), recordCalls: 0, findCounter: 0,
  } as unknown as PilotSession;
}
async function callTool(dir: string, name: string, args: Record<string, unknown>, send: (req: Req) => Promise<Res>): Promise<{ out: Record<string, unknown>; s: PilotSession }> {
  const s = fakeSession(dir, send);
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = JSON.parse((await t.handler(args, {})).content[0]!.text) as Record<string, unknown>;
  return { out, s };
}
async function withDir(fn: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "verdict-graphql-"));
  try {
    await fn(dir);
  } finally {
    fixtureStores.get(dir)?.close();
    fixtureStores.delete(dir);
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A GraphQL-ish fake. Validation errors return 400 (express-graphql style) so markers must be provable on non-2xx bodies. */
function gqlServer(opts: { introspection: boolean; suggestions: boolean; batching: boolean }, log: Req[] = []) {
  return async (req: Req): Promise<Res> => {
    log.push(req);
    const raw = req.body ?? "";
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      parsed = undefined;
    }
    if (Array.isArray(parsed))
      return opts.batching
        ? { status: 200, finalUrl: req.url, durationMs: 2, headers: {}, body: '[{"data":{"__typename":"Query"}},{"data":{"__typename":"Query"}}]' }
        : { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"batching is not allowed"}]}' };
    const q = (parsed as { query?: string } | undefined)?.query ?? "";
    if (q.includes("__schemaX"))
      return { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"Cannot query field \\"__schemaX\\" on type \\"Query\\"."}]}' };
    if (q.includes("__schema"))
      return opts.introspection
        ? {
            status: 200,
            finalUrl: req.url,
            durationMs: 2,
            headers: {},
            // A REAL bounded catalog: queryType + types[] with field/arg names — the probe's marker is "types",
            // a bare queryType name alone is NOT confirmable evidence.
            body: JSON.stringify({
              data: {
                __schema: {
                  queryType: { name: "Query" },
                  mutationType: { name: "Mutation" },
                  types: [
                    { kind: "OBJECT", name: "Query", fields: [{ name: "user", args: [{ name: "id" }] }, { name: "orders", args: [] }], inputFields: null, enumValues: null },
                    { kind: "OBJECT", name: "Mutation", fields: [{ name: "setFlag", args: [] }], inputFields: null, enumValues: null },
                    { kind: "OBJECT", name: "User", fields: [{ name: "id", args: [] }], inputFields: null, enumValues: null },
                  ],
                },
              },
            }),
          }
        : { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"GraphQL introspection is not allowed, but the query contained __schema."}]}' };
    // The probe typos a REAL harvested root field when the catalog is available ("user" → "usr" — the third
    // char dropped); "__typenme" is only the no-schema fallback.
    if (q.includes("usr") || q.includes("__typenme"))
      return opts.suggestions
        ? { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"Cannot query field \\"usee\\" on type \\"Query\\". Did you mean \\"user\\"?"}]}' }
        : { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"Cannot query field \\"usee\\" on type \\"Query\\"."}]}' };
    if (q.includes("__typename"))
      return { status: 200, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"data":{"__typename":"Query"}}' };
    return { status: 400, finalUrl: req.url, durationMs: 2, headers: {}, body: '{"errors":[{"message":"Unknown query"}]}' };
  };
}

test("probe_graphql confirms introspection + field suggestions + batching on an open server", () =>
  withDir(async (dir) => {
    const reqs: Req[] = [];
    const { out, s } = await callTool(dir, "probe_graphql", { url: `${BASE}graphql` }, gqlServer({ introspection: true, suggestions: true, batching: true }, reqs));
    const checks = out.checks as Array<{ name: string; confirmed: boolean; negativeControl: string; positiveReplays: string[]; effectMarker: string }>;
    const intro = checks.find((c) => c.name === "introspection")!;
    const suggest = checks.find((c) => c.name === "field-suggestions")!;
    assert.equal(intro.confirmed, true);
    assert.equal(suggest.confirmed, true);
    assert.equal((out.batching as { accepted: boolean }).accepted, true);
    for (const c of [intro, suggest]) {
      assert.ok(c.positiveReplays.length === 2);
      assert.ok(c.negativeControl);
      assert.ok(c.effectMarker);
    }
    const schemaOps = out.schemaOps as { queries: Array<{ name: string }>; mutations: Array<{ name: string }> } | undefined;
    assert.ok(schemaOps?.queries.some((f) => f.name === "user"), "harvested op names must reach schemaOps");
    assert.match(String(out.verdict), /GRAPHQL OBSERVATIONS/);
    assert.ok((s as unknown as { httpProbes: number }).httpProbes > 0, "probe_graphql must count as an ACTIVE probe for the coverage gate");
    assert.equal(reqs.every((r) => (r.method ?? "GET").toUpperCase() === "POST" && r.headers?.["content-type"] === "application/json"), true);
  }));

test("probe_graphql confirms nothing on a hardened server", () =>
  withDir(async (dir) => {
    const { out } = await callTool(dir, "probe_graphql", { url: `${BASE}graphql` }, gqlServer({ introspection: false, suggestions: false, batching: false }));
    const checks = out.checks as Array<{ name: string; confirmed: boolean }>;
    assert.ok(checks.every((c) => !c.confirmed));
    assert.equal((out.batching as { accepted: boolean }).accepted, false);
    assert.match(String(out.verdict), /^not confirmed/);
  }));

test("probe_graphql still confirms field suggestions when introspection is disabled", () =>
  withDir(async (dir) => {
    const { out } = await callTool(dir, "probe_graphql", { url: `${BASE}graphql` }, gqlServer({ introspection: false, suggestions: true, batching: false }));
    const checks = out.checks as Array<{ name: string; confirmed: boolean }>;
    assert.equal(checks.find((c) => c.name === "introspection")!.confirmed, false);
    assert.equal(checks.find((c) => c.name === "field-suggestions")!.confirmed, true);
  }));

test("probe_graphql refuses a non-GraphQL endpoint after a single ping", () =>
  withDir(async (dir) => {
    const reqs: Req[] = [];
    const send = async (req: Req): Promise<Res> => {
      reqs.push(req);
      return { status: 200, finalUrl: req.url, durationMs: 2, headers: { "content-type": "text/html" }, body: "<html><body>home</body></html>" };
    };
    const { out } = await callTool(dir, "probe_graphql", { url: `${BASE}api` }, send);
    assert.match(String(out.verdict), /NOT CONFIRMED/);
    assert.equal(reqs.length, 1);
  }));

test("probe_graphql confirms nothing on an echo/catch-all server that satisfies the GraphQL-shape gate", () =>
  withDir(async (dir) => {
    // Wraps the request body in {"data":{"echo": ...}} so the ping passes the data/errors gate, then echoes everything.
    const send = async (req: Req): Promise<Res> => ({ status: 200, finalUrl: req.url, durationMs: 2, headers: {}, body: `{"data":{"echo":${req.body ?? "null"}}}` });
    const { out } = await callTool(dir, "probe_graphql", { url: `${BASE}graphql` }, send);
    const checks = out.checks as Array<{ name: string; confirmed: boolean }>;
    assert.ok(checks.every((c) => !c.confirmed), `echo server must confirm nothing (got ${JSON.stringify(checks.map((c) => [c.name, c.confirmed]))})`);
    assert.equal((out.batching as { accepted: boolean }).accepted, false);
  }));

test("record_finding: batching acceptance is info-disclosure at most — a rate-limit claim is rejected", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, gqlServer({ introspection: true, suggestions: true, batching: true }));
    const tools = buildTools(s);
    const probe = tools.find((x) => x.name === "probe_graphql")!;
    const probeOut = JSON.parse((await (probe.handler as (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>)({ url: `${BASE}graphql` }, {})).content[0]!.text) as {
      batching: { accepted: boolean; negativeControl: string; positiveReplays: string[] };
    };
    assert.equal(probeOut.batching.accepted, true);
    const record = tools.find((x) => x.name === "record_finding")!;
    const rec = (args: Record<string, unknown>): Promise<{ content: { text: string }[] }> =>
      (record.handler as (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>)(args, {});
    // Structural acceptance alone is a CAPABILITY observation — never a demonstrated rate-limit bypass.
    assert.match(
      (
        await rec({
          title: "GraphQL request batching accepted",
          severity: "low",
          category: "rate-limit",
          endpoint: "/graphql",
          param: "batching",
          description: "An array body of two queries is executed in one request — a rate-limit/lockout bypass primitive.",
          reproSteps: 'POST /graphql [{"query":"{__typename}"},{"query":"{__typename}"}]',
          negativeControl: probeOut.batching.negativeControl,
          positiveReplays: probeOut.batching.positiveReplays,
        })
      ).content[0]!.text,
      /REJECTED.*rate limit|rate limit.*REJECTED|REJECTED/s,
    );
    // A parameter named batching must not bypass marker requirements for other vulnerability classes.
    assert.match(
      (
        await rec({
          title: "Unproven reflected XSS",
          severity: "medium",
          category: "xss-reflected",
          endpoint: "/graphql",
          param: "batching",
          description: "No reflection or execution marker was observed.",
          reproSteps: "Replay the two GraphQL queries.",
          negativeControl: probeOut.batching.negativeControl,
          positiveReplays: probeOut.batching.positiveReplays,
        })
      ).content[0]!.text,
      /REJECTED: xss-reflected requires effectMarker/,
    );
    // The same evidence under the honest category is accepted.
    assert.match(
      (
        await rec({
          title: "GraphQL request batching accepted",
          severity: "info",
          category: "info-disclosure",
          endpoint: "/graphql",
          param: "batching",
          description: "The endpoint executes a JSON array of queries — a capability observation.",
          reproSteps: 'POST /graphql [{"query":"{__typename}"},{"query":"{__typename}"}]',
          negativeControl: probeOut.batching.negativeControl,
          positiveReplays: probeOut.batching.positiveReplays,
        })
      ).content[0]!.text,
      /recorded|merged/,
    );
    // Citing the single-object control as a positive must still be REJECTED (structural gate works both ways).
    (s as unknown as { findingsByKey: Map<string, unknown> }).findingsByKey.clear();
    assert.match(
      (
        await rec({
          title: "Not batching",
          severity: "info",
          category: "info-disclosure",
          endpoint: "/graphql",
          param: "batching",
          description: "x",
          reproSteps: "x",
          negativeControl: probeOut.batching.negativeControl,
          positiveReplays: [probeOut.batching.negativeControl, probeOut.batching.negativeControl],
        })
      ).content[0]!.text,
      /REJECTED/,
    );
  }));

test("probe_graphql is scope-gated, and record_finding accepts the introspection evidence end-to-end", () =>
  withDir(async (dir) => {
    const s = fakeSession(dir, gqlServer({ introspection: true, suggestions: true, batching: true }));
    const tools = buildTools(s);
    const probe = tools.find((x) => x.name === "probe_graphql")!;
    const blocked = await (probe.handler as (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>)({ url: "https://evil.example/graphql" }, {});
    assert.match(blocked.content[0]!.text, /^BLOCKED/);

    const probeOut = JSON.parse((await (probe.handler as (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>)({ url: `${BASE}graphql` }, {})).content[0]!.text) as {
      checks: Array<{ name: string; confirmed: boolean; negativeControl: string; positiveReplays: string[]; effectMarker: string }>;
    };
    const intro = probeOut.checks.find((c) => c.name === "introspection")!;
    assert.equal(intro.confirmed, true);
    const record = tools.find((x) => x.name === "record_finding")!;
    const rec = await (record.handler as (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }>)(
      {
        title: "GraphQL introspection publicly enabled",
        severity: "low",
        category: "info-disclosure",
        endpoint: "/graphql",
        param: "introspection",
        description: "The __schema meta-field returns the bounded schema catalog to an unauthenticated caller.",
        reproSteps: 'POST /graphql {"query":"{__schema{queryType{name}}}")',
        negativeControl: intro.negativeControl,
        positiveReplays: intro.positiveReplays,
        effectMarker: intro.effectMarker,
      },
      {},
    );
    assert.match(rec.content[0]!.text, /recorded|merged/);
  }));
