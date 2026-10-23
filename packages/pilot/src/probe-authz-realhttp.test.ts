// REAL-HTTP acceptance for the evidence-backed authorization path (probe_authz → authz ledger →
// record_finding gate → check ledger → reopen). A real in-process server models:
//   * tenants t1/t2; users A(u-a,t1), B(u-b,t1), C(u-c,t2), admin(u-admin,t1), aliasA(=u-a)
//   * two orders per owner (o-a1/o-a2, o-b1/o-b2), a shared object (pub-1), same-id across tenants (doc-1)
//   * a SAFE route (/api/orders/{id}: owner-only) and a deliberately vulnerable route
//     (/api/vuln/orders/{id}: any authenticated principal reads any order)
//   * a GraphQL endpoint answering HTTP 200 with errors/partial data
//   * /api/me identity endpoint per session (identity-binding ownership)
// Sessions are stubbed RoleSessions (bearer tokens); all traffic stays on 127.0.0.1.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl, screenChecks } from "@veritas/core";

// ── principals / tokens / objects ──
const PRINCIPAL: Record<string, { id: string; tenant: string }> = {
  "tok-a": { id: "u-a", tenant: "t1" },
  "tok-b": { id: "u-b", tenant: "t1" },
  "tok-alias": { id: "u-a", tenant: "t1" }, // a SECOND session for the SAME account A (alias, not a second user)
  "tok-c": { id: "u-c", tenant: "t2" },
  "tok-admin": { id: "u-admin", tenant: "t1" },
};
const ORDERS: Record<string, { owner: string; tenant: string; total: number }> = {
  "o-a1": { owner: "u-a", tenant: "t1", total: 1200 },
  "o-a2": { owner: "u-a", tenant: "t1", total: 340 },
  "o-b1": { owner: "u-b", tenant: "t1", total: 77 },
  "o-b2": { owner: "u-b", tenant: "t1", total: 960 },
  "pub-1": { owner: "", tenant: "t1", total: 0 }, // shared/public object — readable by any authenticated user
};
// Same object id in two tenants — distinct objects, distinct owners.
const TENANT_DOCS: Record<string, Record<string, { owner: string; secret: string }>> = {
  t1: { "doc-1": { owner: "u-a", secret: "t1-private-doc" } },
  t2: { "doc-1": { owner: "u-c", secret: "t2-private-doc" } },
};

interface WireHit { path: string; auth: string; }
const wire: WireHit[] = [];

const readBody = (req: http.IncomingMessage): Promise<string> =>
  new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });

function principalOf(req: http.IncomingMessage): { id: string; tenant: string } | null {
  const tok = (req.headers.authorization ?? "").replace(/^Bearer /, "");
  return PRINCIPAL[tok] ?? null;
}
const json = (res: http.ServerResponse, status: number, body: unknown) => {
  res.statusCode = status;
  res.setHeader("content-type", "application/json");
  res.end(JSON.stringify(body));
};

let server: http.Server;
let base = "";
let dir = "";
let dbN = 0;
const fixtureStores: AssessmentStore[] = [];

before(async () => {
  server = http.createServer(async (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    wire.push({ path: u.pathname, auth: String(req.headers.authorization ?? "") });
    const who = principalOf(req);

    if (u.pathname === "/api/me") {
      if (!who) return json(res, 401, { error: "unauthenticated" });
      return json(res, 200, { id: who.id, tenant: who.tenant });
    }
    let m = /^\/api\/orders\/([^/]+)$/.exec(u.pathname);
    if (m) {
      const o = ORDERS[m[1]!];
      if (!o) return json(res, 404, { error: "not found" });
      if (!who) return json(res, 401, { error: "unauthenticated" });
      if (o.owner && o.owner !== who.id && who.id !== "u-admin") return json(res, 403, { error: "forbidden" });
      return json(res, 200, { id: m[1], ownerId: o.owner || "shared", tenant: o.tenant, total: o.total, invoice: `INV-${m[1]}`, items: ["widget"] });
    }
    m = /^\/api\/vuln\/orders\/([^/]+)$/.exec(u.pathname);
    if (m) {
      const o = ORDERS[m[1]!];
      if (!o) return json(res, 404, { error: "not found" });
      if (!who) return json(res, 401, { error: "unauthenticated" });
      return json(res, 200, { id: m[1], ownerId: o.owner || "shared", tenant: o.tenant, total: o.total, invoice: `INV-${m[1]}`, items: ["widget"] }); // BUG: no owner check
    }
    m = /^\/api\/t\/(t\d)\/orders\/([^/]+)$/.exec(u.pathname);
    if (m) {
      const doc = TENANT_DOCS[m[1]!]?.[m[2]!];
      if (!doc) return json(res, 404, { error: "not found" });
      if (!who) return json(res, 401, { error: "unauthenticated" });
      if (doc.owner !== who.id) return json(res, 403, { error: "forbidden" }); // safe tenant route
      return json(res, 200, { id: m[2], ownerId: doc.owner, tenant: m[1], invoice: `INV-${m[1]}-${m[2]}`, secret: doc.secret });
    }
    m = /^\/api\/vuln\/t\/(t\d)\/orders\/([^/]+)$/.exec(u.pathname);
    if (m) {
      const doc = TENANT_DOCS[m[1]!]?.[m[2]!];
      if (!doc) return json(res, 404, { error: "not found" });
      if (!who) return json(res, 401, { error: "unauthenticated" });
      return json(res, 200, { id: m[2], ownerId: doc.owner, tenant: m[1], invoice: `INV-${m[1]}-${m[2]}`, secret: doc.secret }); // BUG: cross-tenant
    }
    if (u.pathname === "/graphql" && req.method === "POST") {
      const body = await readBody(req).catch(() => "");
      const id = /"id"\s*:\s*"([^"]+)"/.exec(body)?.[1] ?? "";
      const vuln = /vulnOrder/.test(body);
      const o = ORDERS[id];
      if (!o) return json(res, 200, { data: { order: null }, errors: [{ message: "not found", path: ["order"] }] });
      if (!who) return json(res, 200, { data: { order: null }, errors: [{ message: "FORBIDDEN", path: ["order"] }] });
      if (o.owner && o.owner !== who.id && who.id !== "u-admin" && !vuln)
        return json(res, 200, { data: { order: null }, errors: [{ message: "FORBIDDEN", path: ["order"], extensions: { code: "FORBIDDEN" } }] });
      // vulnOrder: returns the object plus an unrelated field error (HTTP200 partial data)
      return json(res, 200, { data: { order: { id, ownerId: o.owner || "shared", total: o.total } }, errors: vuln ? [{ message: "deprecated field", path: ["note"] }] : [] });
    }
    res.statusCode = 404; res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "veritas-authz-"));
});

after(async () => {
  await new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve())));
  server.closeAllConnections();
  for (const store of fixtureStores) try { store.close(); } catch { /* already closed */ }
  rmSync(dir, { recursive: true, force: true });
});

/** A live-session stub for a role: the driver only needs sessionCookieHeader + bearerToken for the raw path. */
function roleSession(bearer: string) {
  return {
    driver: {
      sessionCookieHeader: async () => "",
      bearerToken: async () => bearer,
    },
    cookie: "",
  } as never;
}

function session(opts: {
  currentRole?: string;
  bearer?: string;
  roles?: Record<string, string>; // role -> bearer token (live sessions)
  principals?: Record<string, string>; // operator-declared principals
  tenants?: Record<string, string>; // operator-declared tenants
  identity?: boolean; // give every role an identityUrl (/api/me)
  expectedAccess?: Array<{ object?: string; endpoint?: string; role: string; allow: boolean; tenant?: string }>;
  dbName?: string;
} = {}): PilotSession {
  const store = AssessmentStore.open(join(dir, `${opts.dbName ?? `s${dbN++}`}.sqlite`));
  fixtureStores.push(store);
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  } catch { /* exists */ }
  const roleSessions = new Map<string, never>();
  for (const [role, tok] of Object.entries(opts.roles ?? {})) roleSessions.set(role, roleSession(tok));
  const roleIdentityUrls = new Map<string, string>();
  if (opts.identity !== false) for (const role of Object.keys(opts.roles ?? {})) roleIdentityUrls.set(role, `${base}api/me`);
  return {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(base.replace(/\/$/, "")) }),
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, "artifacts")),
    scope: deriveScopeFromSingleUrl(base), targetUrl: base, currentScreenId: "s-1",
    currentCookie: "", currentBearer: opts.bearer ?? "", currentRole: opts.currentRole ?? "userA",
    roleSessions, roleCookieFiles: new Map(), roleCreds: new Map(), roleDescriptions: new Map(),
    roleIdentityUrls,
    rolePrincipals: new Map(Object.entries(opts.principals ?? {})),
    roleTenants: new Map(Object.entries(opts.tenants ?? {})),
    expectedAccess: opts.expectedAccess ?? [],
    sessionPrincipals: new Map(), invalidRoleSessions: new Set(),
    visitedByRole: new Map(), roleSurveyBlocked: new Map(),
    findings: [], findingsByKey: new Map(), findCounter: 0, accessVerdicts: new Map(),
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
    plans: new Map(), visited: new Set(), frontier: new Set(), refererGated: new Set(), ignorePaths: [],
    inv: { screens: () => [], seed: () => {}, observe: () => null },
  } as unknown as PilotSession;
}

async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = await t.handler(args, {});
  const text = out.content[0]!.text;
  try { return JSON.parse(text); } catch { return { raw: text }; }
}

const FULL_ROLES = { userA: "tok-a", userB: "tok-b", aliasA: "tok-alias", userC: "tok-c", admin: "tok-admin" };
const FULL_TENANTS = { userA: "t1", userB: "t1", aliasA: "t1", userC: "t2", admin: "t1" };

// ───────────────────────── A/B authorization acceptance ─────────────────────────

test("probe_authz: vulnerable read confirms ONLY with verified owner + denied control + stable replays", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ object: "o-a1", role: "userB", allow: false }], // operator policy: B denied on o-a1
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
    ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(r.outcome, "unexpected-access", JSON.stringify(r));
  // Ownership proven by identity-binding (owner field bound to u-a via /api/me of the owner session).
  const objs = s.store.authzObjects("a-1");
  const obj = objs.find((o) => o.objectId === "o-a1");
  assert.ok(obj, "authz object persisted");
  assert.equal(obj.owner, "userA");
  assert.equal(obj.ownerBasis, "identity-binding");
  assert.ok(obj.ownerEvidenceIds?.length, "ownership carries establishing evidence");
  assert.deepEqual(obj.deniedFor, [], "real-object access must NOT inherit the nonexistent-id control denial");
  // Comparison provenance: the legs are evidence.
  const cmps = s.store.authzComparisons("a-1");
  assert.equal(cmps.length, 1);
  assert.equal(cmps[0]!.comparePrincipal, "u-b");
  assert.equal(cmps[0]!.ownerPrincipal, "u-a");
  assert.equal(cmps[0]!.expectationBasis, "operator");
  // record_finding confirms only when the cited evidence IS the comparison's legs.
  const ev = r.evidence as { deniedControl: string[]; compareReplays: string[] };
  const ep = (r.object as { endpoint: string }).endpoint;
  const fr = await run(s, "record_finding", {
    title: "IDOR: any authenticated user reads any order", severity: "high", category: "idor",
    endpoint: ep, param: "id", description: "x".repeat(30), reproSteps: "y".repeat(30),
    verdict: "confirmed", negativeControl: ev.deniedControl[0], positiveReplays: ev.compareReplays,
  });
  assert.match(String(fr.raw ?? JSON.stringify(fr)), /recorded f-\d+/, JSON.stringify(fr));
  const checks = s.store.checks("a-1");
  assert.ok(checks.some((c) => c.checkClass === "idor" && c.status === "found"));
});

test("A's own second order via a same-principal ALIAS is not a cross-user finding", async () => {
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b" });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a2", resourceType: "order",
    ownerRole: "userA", compareRole: "aliasA",
  });
  assert.equal(r.outcome, "unverified", JSON.stringify(r));
  assert.match(String(r.reason), /same principal|identity collision/i);
  assert.equal(s.store.authzComparisons("a-1").length, 1); // the attempt is recorded honestly
});

test("B denied on A's object is denied-as-expected (that exact comparison is clean)", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ object: "o-a1", role: "userB", allow: false }],
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
    ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(r.outcome, "denied-as-expected", JSON.stringify(r));
  const obj = s.store.authzObjects("a-1").find((o) => o.objectId === "o-a1");
  assert.deepEqual(obj?.deniedFor, ["userB"], "the real-object denial (not the control) lands in deniedFor");
  assert.ok(s.store.checks("a-1").some((c) => c.checkClass === "idor" && c.status === "tested-clean"));
});

test("shared object + operator allow rule resolves 'allowed' — never an IDOR", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ object: "pub-1", role: "userB", allow: true }],
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "pub-1", resourceType: "order",
    ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(r.outcome, "allowed", JSON.stringify(r));
  assert.ok(s.store.checks("a-1").some((c) => c.status === "tested-clean"));
});

test("admin role declared allowed is not reported as an IDOR", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "admin", bearer: "tok-admin",
    expectedAccess: [{ role: "admin", allow: true }],
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-b1", resourceType: "order",
    ownerRole: "userB", compareRole: "admin",
  });
  assert.equal(r.outcome, "allowed", JSON.stringify(r));
});

test("cross-tenant exposure confirms with tenantBoundary only when BOTH tenants are declared", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userA", bearer: "tok-a",
    expectedAccess: [{ role: "userA", allow: false }],
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/t/t2/orders/{{ID}}`, objectId: "doc-1", resourceType: "doc",
    ownerRole: "userC", compareRole: "userA",
  });
  assert.equal(r.outcome, "unexpected-access", JSON.stringify(r));
  assert.equal(s.store.authzComparisons("a-1")[0]!.tenantBoundary, true);

  // Same exposure, NO declared tenants → the access is still real, but no boundary claim is manufactured.
  const s2 = session({
    roles: FULL_ROLES, currentRole: "userA", bearer: "tok-a",
    expectedAccess: [{ role: "userA", allow: false }],
  });
  const r2 = await run(s2, "probe_authz", {
    url: `${base}api/vuln/t/t2/orders/{{ID}}`, objectId: "doc-1", resourceType: "doc",
    ownerRole: "userC", compareRole: "userA",
  });
  assert.equal(r2.outcome, "unexpected-access", JSON.stringify(r2));
  assert.equal(s2.store.authzComparisons("a-1")[0]!.tenantBoundary, false);
});

test("same object id in different tenants is a DIFFERENT object (doc-1 t1 vs t2)", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userA", bearer: "tok-a",
    expectedAccess: [{ role: "userB", allow: false }, { role: "userA", allow: false }],
  });
  // t1 doc-1 owned by u-a — B denied on the SAFE route.
  await run(s, "probe_authz", { url: `${base}api/t/t1/orders/{{ID}}`, objectId: "doc-1", resourceType: "doc", ownerRole: "userA", compareRole: "userB" });
  // t2 doc-1 owned by u-c — A reads via the VULN route.
  await run(s, "probe_authz", { url: `${base}api/vuln/t/t2/orders/{{ID}}`, objectId: "doc-1", resourceType: "doc", ownerRole: "userC", compareRole: "userA" });
  const objs = s.store.authzObjects("a-1");
  const keys = objs.map((o) => o.key);
  assert.equal(new Set(keys).size, objs.length, "two distinct objects — no key collapse");
  const t1 = objs.find((o) => o.tenant === "t1");
  const t2 = objs.find((o) => o.tenant === "t2");
  assert.equal(t1?.owner, "userA");
  assert.equal(t2?.owner, "userC");
  // One object's clean denial does NOT erase the other's finding.
  const cmps = s.store.authzComparisons("a-1");
  assert.equal(cmps[0]!.outcome, "denied-as-expected");
  assert.equal(cmps[1]!.outcome, "unexpected-access");
});

test("GraphQL: HTTP 200 with FORBIDDEN errors is a DENIAL; partial data still counts as access", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ role: "userB", allow: false }],
  });
  const safe = await run(s, "probe_authz", {
    url: `${base}graphql`, method: "POST",
    body: `{"query":"query Q($id:ID!){order(id:$id){id ownerId total}}","variables":{"id":"{{ID}}"}}`,
    objectId: "o-a1", resourceType: "order", ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(safe.outcome, "denied-as-expected", JSON.stringify(safe));
  const vuln = await run(s, "probe_authz", {
    url: `${base}graphql`, method: "POST",
    body: `{"query":"query V($id:ID!){vulnOrder(id:$id){id ownerId total}}","variables":{"id":"{{ID}}"}}`,
    objectId: "o-a1", resourceType: "order", ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(vuln.outcome, "unexpected-access", JSON.stringify(vuln));
});

test("record_finding direct bypass is REJECTED — probe-lookalike evidence is not an authz comparison", async () => {
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b" });
  // Model fabricates the usual evidence shape by hand via http_request (2 reads + a 404 control).
  const p1 = await run(s, "http_request", { method: "GET", url: `${base}api/vuln/orders/o-a1`, kind: "positive_replay" });
  const p2 = await run(s, "http_request", { method: "GET", url: `${base}api/vuln/orders/o-a1`, kind: "positive_replay" });
  const ctl = await run(s, "http_request", { method: "GET", url: `${base}api/vuln/orders/o-x1`, kind: "negative_control" });
  const ev = (r: Record<string, unknown>) => String(r.evidenceId ?? "");
  const fr = await run(s, "record_finding", {
    title: "claimed IDOR", severity: "high", category: "idor", endpoint: "/api/vuln/orders/o-a1", param: "id",
    description: "x".repeat(30), reproSteps: "y".repeat(30), verdict: "confirmed",
    negativeControl: ev(ctl), positiveReplays: [ev(p1), ev(p2)],
  });
  assert.match(String(fr.raw ?? JSON.stringify(fr)), /REJECTED: idor confirmation requires a probe_authz/, JSON.stringify(fr));
  assert.equal(s.findings.length, 0);
});

test("a missing/expired comparison session is BLOCKED — never falls back to the current session", async () => {
  wire.length = 0;
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userA", bearer: "tok-a" });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
    ownerRole: "userA", compareRole: "ghost", // no session material for 'ghost'
  });
  assert.equal(r.outcome, "unverified", JSON.stringify(r));
  assert.ok(s.store.checks("a-1").some((c) => c.status === "blocked"));
  // No compare leg was ever sent — under any token (a fallback would have leaked A's session here).
  assert.ok(!wire.some((w) => w.path.includes("vuln")), `compare leg must not fire: ${JSON.stringify(wire)}`);
});

test("check ledger survives reopen and finding+unverified coexist on one screen", async () => {
  const dbName = `persist-${dbN++}`;
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b", dbName, expectedAccess: [{ role: "userB", allow: false }] });
  await run(s, "probe_authz", { url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a1", resourceType: "order", ownerRole: "userA", compareRole: "userB" });
  const ev = s.store.authzComparisons("a-1")[0]!;
  await run(s, "record_finding", {
    title: "IDOR confirmed", severity: "high", category: "idor", endpoint: ev.endpoint, param: "id",
    description: "x".repeat(30), reproSteps: "y".repeat(30), verdict: "confirmed",
    negativeControl: ev.deniedEvidenceIds[0], positiveReplays: ev.compareEvidenceIds,
  });
  // An honest unverified row on ANOTHER object (blocked compare) coexists with the finding row.
  await run(s, "probe_authz", { url: `${base}api/orders/{{ID}}`, objectId: "o-b1", resourceType: "order", ownerRole: "userB", compareRole: "ghost" });
  s.store.close();
  const reopened = AssessmentStore.open(join(dir, `${dbName}.sqlite`));
  fixtureStores.push(reopened);
  const st = reopened.loadAssessment("a-1")!;
  const view = screenChecks({ checkExecutions: st.checkExecutions }, "s-1");
  const statuses = new Set(view.classes.map((c) => c.status));
  assert.ok(statuses.has("found"), "the finding's check row persisted");
  assert.ok(st.checkExecutions.some((c) => c.status === "blocked"), "the blocked gap persisted");
  assert.equal(st.authzComparisons.length, 2);
});

test(">301 events: check ledger reads the FULL table, not a capped event window", async () => {
  const dbName = `many-${dbN++}`;
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b", dbName });
  // 340 arbitrary events push past any tail-window — plus 40 real check rows.
  for (let i = 0; i < 340; i++)
    s.store.appendEvent("a-1", { type: "note", payload: { message: `pad ${i}` } });
  for (let i = 0; i < 40; i++)
    await run(s, "probe_authz", { url: `${base}api/orders/{{ID}}`, objectId: `none-${i}`, resourceType: "order", ownerRole: "userA", compareRole: "userB" });
  s.store.close();
  const reopened = AssessmentStore.open(join(dir, `${dbName}.sqlite`));
  fixtureStores.push(reopened);
  const st = reopened.loadAssessment("a-1")!;
  assert.ok(st.checkExecutions.length >= 40, `expected >=40 check rows, got ${st.checkExecutions.length}`);
  assert.ok(st.authzComparisons.length >= 40);
});

test("conflicting allow+deny rules on the same object are AMBIGUOUS — never resolved by rule order", async () => {
  for (const rules of [
    [{ role: "userB", object: "o-a1", allow: false }, { role: "userB", object: "o-a1", allow: true }],
    [{ role: "userB", object: "o-a1", allow: true }, { role: "userB", object: "o-a1", allow: false }],
  ]) {
    const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b", expectedAccess: rules });
    const r = await run(s, "probe_authz", {
      url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
      ownerRole: "userA", compareRole: "userB",
    });
    assert.equal(r.outcome, "inconclusive", JSON.stringify(r));
    assert.equal(s.store.authzComparisons("a-1")[0]!.expectation, "unknown");
    assert.ok(!s.store.checks("a-1").some((c) => c.status === "found"), "an ambiguous rule set must never found");
  }
});

test("an endpoint-scoped rule does NOT bleed onto a different path (no suffix matching)", async () => {
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ role: "userB", endpoint: "/api/orders/{id}", allow: false }], // safe route only
  });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "o-a1", resourceType: "order", // different endpoint
    ownerRole: "userA", compareRole: "userB",
  });
  // The safe-route deny must not transfer to the vuln route — no trusted expectation → inconclusive, not a finding.
  assert.equal(r.outcome, "inconclusive", JSON.stringify(r));
  assert.ok(!s.store.checks("a-1").some((c) => c.status === "found"));
});

test("a GraphQL errors-only second replay is NOT stable — access once does not confirm", async () => {
  let graphqlReads = 0;
  const s = session({
    roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b",
    expectedAccess: [{ role: "userB", allow: false }],
  });
  // Point the session's own http client at a wrapper that makes the SECOND vuln replay errors-only.
  const inner = s.http;
  s.http = {
    async send(req: { url: string; method?: string; headers?: Record<string, string>; body?: string | null }) {
      const isB = Object.entries(req.headers ?? {}).some(([k, v]) => k.toLowerCase() === "authorization" && v === "Bearer tok-b");
      if (req.url.endsWith("/graphql") && (req.body ?? "").includes("vulnOrder") && (req.body ?? "").includes('"o-a1"') && isB) {
        graphqlReads++;
        if (graphqlReads === 2)
          return { status: 200, headers: { "content-type": "application/json" }, body: JSON.stringify({ data: null, errors: [{ message: "resolver failed", extensions: { code: "INTERNAL_SERVER_ERROR" } }] }), finalUrl: req.url };
      }
      return inner.send(req as never);
    },
    effectiveHeaders: inner.effectiveHeaders.bind(inner),
  } as never;
  const r = await run(s, "probe_authz", {
    url: `${base}graphql`, method: "POST",
    body: `{"query":"query V($id:ID!){vulnOrder(id:$id){id ownerId total}}","variables":{"id":"{{ID}}"}}`,
    objectId: "o-a1", resourceType: "order", ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(graphqlReads, 2, "both compare replays ran");
  assert.equal(r.outcome, "inconclusive", JSON.stringify(r));
  assert.ok(!s.store.checks("a-1").some((c) => c.status === "found"), "an errors-only replay must never found");
});

test("session isolation: each leg carries ONLY its own role's credentials", async () => {
  wire.length = 0;
  const s = session({ roles: FULL_ROLES, tenants: FULL_TENANTS, currentRole: "userB", bearer: "tok-b" });
  await run(s, "probe_authz", { url: `${base}api/orders/{{ID}}`, objectId: "o-b1", resourceType: "order", ownerRole: "userB", compareRole: "userC" });
  const orderHits = wire.filter((w) => w.path.includes("/api/orders/"));
  const meHits = wire.filter((w) => w.path === "/api/me");
  assert.ok(orderHits.some((w) => w.auth === "Bearer tok-b"), "owner leg used B's token");
  assert.ok(orderHits.some((w) => w.auth === "Bearer tok-c"), "compare leg used C's token");
  assert.ok(!orderHits.some((w) => w.auth === "Bearer tok-b" && w.path.includes("o-c")), "B's token never sent on C's object leg");
  assert.ok(meHits.some((w) => w.auth === "Bearer tok-b") && meHits.some((w) => w.auth === "Bearer tok-c"), "each whoami ran under its own session");
});

// ───────────────────────── objectId:'auto' (owner-object discovery) ─────────────────────────

test("probe_authz objectId:'auto' adopts the first observed id the OWNER can actually read", async () => {
  const s = session({
    roles: { userA: "tok-a", userB: "tok-b" }, tenants: { userA: "t1", userB: "t1" },
    currentRole: "userA", bearer: "tok-a",
    expectedAccess: [{ object: "o-a1", role: "userB", allow: false }],
  });
  // Earlier traffic observed the owner's own order — real ids are harvested from recorded response
  // bodies, so 'auto' never guesses an id the app never served.
  await run(s, "http_request", { method: "GET", url: `${base}api/orders/o-a1`, kind: "positive_replay" });
  const r = await run(s, "probe_authz", {
    url: `${base}api/vuln/orders/{{ID}}`, objectId: "auto", resourceType: "order",
    ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(r.outcome, "unexpected-access", JSON.stringify(r));
  assert.equal((r.object as { id: string }).id, "o-a1", "the adopted object is what the comparison records");
  const cmp = s.store.authzComparisons("a-1")[0];
  assert.ok(cmp, "the comparison persisted — auto is a discovery step, not an evidence shortcut");
});

test("probe_authz objectId:'auto' with no READABLE observed ids reports honestly instead of guessing", async () => {
  // A fresh session still harvests the identity-endpoint bodies (u-a/u-b are real observed ids — and on
  // /api/users/{id}-style endpoints a principal id IS a legitimate object candidate). None is a readable
  // order, so the outcome must be an honest unverified naming the recovery step — never a guess.
  const s = session({ roles: { userA: "tok-a", userB: "tok-b" }, currentRole: "userA", bearer: "tok-a" });
  const r = await run(s, "probe_authz", {
    url: `${base}api/orders/{{ID}}`, objectId: "auto", resourceType: "order",
    ownerRole: "userA", compareRole: "userB",
  });
  assert.equal(r.outcome, "unverified", JSON.stringify(r));
  assert.match(String(r.reason), /objectId:'auto' tried \d+ observed id\(s\)/);
  assert.match(String(r.reason), /none was a readable object/);
  assert.match(String(r.reason), /List the owner's own resources/, "the reason names the recovery step");
  assert.ok(!s.store.checks("a-1").some((c) => c.status === "found"), "no readable candidate → no fabricated comparison");
});

test("a missing owner/compare session reports which sessions ARE usable — never falls back", async () => {
  const s = session({ roles: { userA: "tok-a" }, currentRole: "userA", bearer: "tok-a" });
  const r = await run(s, "probe_authz", {
    url: `${base}api/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
    ownerRole: "ghost", compareRole: "userB",
  });
  assert.equal(r.outcome, "unverified", JSON.stringify(r));
  assert.match(String(r.reason), /no usable session for ownerRole 'ghost'/);
  assert.match(String(r.reason), /Sessions usable now: .*userA/, "the failure enumerates the usable sessions");
  // The compare-side message carries the same enumeration.
  const r2 = await run(s, "probe_authz", {
    url: `${base}api/orders/{{ID}}`, objectId: "o-a1", resourceType: "order",
    ownerRole: "userA", compareRole: "ghost",
  });
  assert.equal(r2.outcome, "unverified", JSON.stringify(r2));
  assert.match(String(r2.reason), /no usable session for compareRole 'ghost'/);
  assert.match(String(r2.reason), /Sessions usable now: .*userA/);
});
