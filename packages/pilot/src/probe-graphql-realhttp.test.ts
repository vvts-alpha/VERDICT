// REAL-ENGINE end-to-end for the GraphQL detection work: an in-process HTTP server backed by graphql-js —
// real parsing, validation, variable coercion, selection execution, aliases, fragments, nested inputs,
// resolver-level ownership/field authorization, and a stateful non-destructive mutation — exercised by the
// ACTUAL probe handlers over real sockets. No FakeHttpClient, no LLM, no regex-routed resolver.
// Proves: baseline establishment gating (unverified ≠ clean), field-level authz diff, held-vs-broken operation
// authz, nested-variable surgical edits, mutation write verification, authz-vs-internal error separation,
// and the corrected meta-probe claims (public-vs-authed introspection, batching as a capability observation only).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  graphql, buildSchema, GraphQLError,
  type GraphQLFieldResolver,
} from "graphql";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { ApiCall } from "@veritas/core";
import { InventoryBuilder, apiCallToBuiltScreen, describeGraphqlOperation } from "@veritas/crawler";

const readBody = (req: http.IncomingMessage): Promise<string> => new Promise((res) => { let b = ""; req.on("data", (c) => (b += c)); req.on("end", () => res(b)); });

// ── real GraphQL schema (graphql-js) ─────────────────────────────────────────
interface Ctx { role: string; secure: boolean }
type Src = Record<string, unknown>;

const ORDERS: Record<string, { id: string; ownerId: string; total: number; phone?: string }> = {
  "1": { id: "1", ownerId: "user1", total: 100 },
  // victim carries a phone → cross-user impact fires (public-directory would suppress it)
  "2": { id: "2", ownerId: "user2", phone: "+81-90-2222-3333", total: 5000 },
};
interface NoteRow { text: string; owner: string }
const NOTES: Record<string, NoteRow> = { n1: { text: "original", owner: "user1" }, nerr: { text: "boom", owner: "user1" } };

const forbidden = (msg: string): never => { throw new GraphQLError(msg, { extensions: { code: "FORBIDDEN" } }); };
const unauth = (): never => { throw new GraphQLError("not authenticated", { extensions: { code: "UNAUTHENTICATED" } }); };

/** SDL + per-type resolver map. `dbPing`/`dbNote` throw an INTERNAL error whose MESSAGE borrows auth wording —
 *  the classifier must not read a resolver/DB failure as authorization enforcement. */
const SDL = `
  type Order { id: ID, ownerId: ID, total: Int, phone: String }
  type User { id: ID, name: String, email: String, salary: Int, dbNote: String }
  type Note { id: ID, text: String, status: String }
  input OrderFilter { ownerId: ID, tag: String, limit: Int }
  type Query {
    order(id: ID!): Order
    orderByOwner(input: OrderFilter!): Order
    user(id: ID!): User
    note(id: ID!): Note
    dbPing: String
  }
  type Mutation {
    updateNote(id: ID!, text: String!): Note
    appendNote(id: ID!, text: String!): Note
    guardedNote(id: ID!, text: String!): Note
    deleteNote(id: ID!): Note
  }
`;
const schema = buildSchema(SDL);

type Root = Record<string, GraphQLFieldResolver<Src, Ctx>>;
const queryRoot: Root = {
  order: (_s, { id }, ctx) => {
    if (!ctx.role) unauth();
    const o = ORDERS[String(id)];
    if (!o) return null;
    if (ctx.secure && o.ownerId !== ctx.role && ctx.role !== "admin")
      forbidden("Forbidden: not your order");
    return o; // permissive endpoint: ANY authed role reads ANY order (the hole)
  },
  // Real InputObject: the resolver receives a coerced {ownerId, tag, limit} — a surgical edit to ONE nested
  // leaf (variables.in.ownerId) must reach this resolver while siblings stay intact.
  orderByOwner: (_s, { input }, ctx) => {
    if (!ctx.role) unauth();
    const o = Object.values(ORDERS).find((x) => x.ownerId === String((input as { ownerId?: unknown }).ownerId ?? ""));
    if (!o) return null;
    if (ctx.secure && o.ownerId !== ctx.role && ctx.role !== "admin") forbidden("Forbidden: not your order");
    return o;
  },
  user: (_s, { id }, ctx) => {
    if (!ctx.role) unauth();
    return { id: String(id), name: "alice", email: "alice@corp.test", salary: 99000, __role: ctx.role };
  },
  note: (_s, { id }) => {
    const n = NOTES[String(id)];
    return n ? { id: String(id), text: n.text } : null;
  },
  dbPing: (_s, _a, ctx) => {
    if (!ctx.role) unauth();
    if (ctx.role !== "admin")
      throw new GraphQLError("Access denied for user 'app'@'db' (using password: YES)", { extensions: { code: "INTERNAL_SERVER_ERROR" } });
    return "pong";
  },
};
const mutationRoot: Root = {
  updateNote: (_s, { id, text }, ctx) => {
    if (!ctx.role) unauth();
    const nid = String(id);
    if (ctx.secure && ctx.role !== "admin" && NOTES[nid] && NOTES[nid].owner !== ctx.role)
      forbidden("Forbidden: not your note");
    NOTES[nid] = { text: String(text), owner: NOTES[nid]?.owner ?? ctx.role };
    return { id: nid, text: NOTES[nid].text };
  },
  // Non-idempotent: each execution appends — needed so two replays each move observable state.
  appendNote: (_s, { id, text }, ctx) => {
    if (!ctx.role) unauth();
    const nid = String(id);
    NOTES[nid] = { text: (NOTES[nid]?.text ?? "") + String(text), owner: NOTES[nid]?.owner ?? ctx.role };
    return { id: nid, text: NOTES[nid].text };
  },
  // Soft-deny: admin writes; everyone else gets a 200-shaped response but NOTHING is persisted — the replay
  // must NOT be attributed a state change just because data came back.
  guardedNote: (_s, { id, text }, ctx) => {
    if (!ctx.role) unauth();
    const nid = String(id);
    if (ctx.role === "admin") NOTES[nid] = { text: String(text), owner: NOTES[nid]?.owner ?? ctx.role };
    return { id: nid, text: NOTES[nid]?.text ?? String(text) };
  },
  deleteNote: (_s, { id }, ctx) => {
    if (!ctx.role) unauth();
    const nid = String(id);
    const old = NOTES[nid];
    delete NOTES[nid];
    return old ? { id: nid, text: old.text } : null;
  },
};

/** Field-level resolvers graphql-js can't express via rootValue — attached onto the compiled schema fields.
 *  `salary`: FORBIDDEN for non-admin. `status`: INTERNAL for note nerr. `dbNote`: INTERNAL with auth-looking
 *  wording for non-admin. `reqId`: volatile (different every read — noise the verify path must ignore). */
function attachFieldResolvers(): void {
  const user = schema.getType("User") as { getFields(): Record<string, { resolve?: GraphQLFieldResolver<Src, Ctx> }> };
  user.getFields().salary!.resolve = (u, _a, ctx) => {
    if (ctx.role !== "admin") forbidden("Forbidden");
    return (u as { salary?: number }).salary ?? null;
  };
  user.getFields().dbNote!.resolve = (_u, _a, ctx) => {
    if (ctx.role !== "admin")
      throw new GraphQLError("Access denied for user 'app'@'db' (using password: YES)", { extensions: { code: "INTERNAL_SERVER_ERROR" } });
    return "replication ok";
  };
  const note = schema.getType("Note") as { getFields(): Record<string, { resolve?: GraphQLFieldResolver<Src, Ctx> }> };
  note.getFields().status!.resolve = (n) => {
    if ((n as { id?: string }).id === "nerr")
      throw new GraphQLError("status backend timeout", { extensions: { code: "INTERNAL_SERVER_ERROR" } });
    return "ok";
  };
}
attachFieldResolvers();

/** Execute ONE GraphQL request payload through the real engine (parse → validate → execute, with real
 *  variable coercion and operation selection). Unauth on the SECURE endpoint is rejected before execution —
 *  a plausible pre-resolver auth gate; introspection denial falls out of the same rule. */
async function execOp(payload: { query?: string; operationName?: string; variables?: Record<string, unknown> }, ctx: Ctx): Promise<Record<string, unknown>> {
  if (ctx.secure && !ctx.role)
    return { errors: [{ message: "not authenticated", extensions: { code: "UNAUTHENTICATED" } }] };
  const r = await graphql({
    schema,
    source: String(payload.query ?? ""),
    rootValue: {},
    contextValue: ctx,
    variableValues: payload.variables,
    operationName: payload.operationName,
    fieldResolver: (source, args, context, info) => {
      // Root ops live on queryRoot/mutationRoot; otherwise default field resolution.
      const root = info.parentType.name === "Mutation" ? mutationRoot : queryRoot;
      const fn = root[info.fieldName];
      if (info.parentType.name === "Query" || info.parentType.name === "Mutation") {
        if (!fn) return undefined; // validation already rejected unknown fields
        return fn(source, args, context, info);
      }
      const v = (source as Src)[info.fieldName];
      return typeof v === "function" ? (v as GraphQLFieldResolver<Src, Ctx>)(source, args, context, info) : v;
    },
  });
  return r as unknown as Record<string, unknown>;
}

let server: http.Server;
let base = "";
let dir = "";
let dbN = 0;
/** Bodies + auth headers the server actually received — proves refused ops were never sent, and that each leg
 *  carried exactly its own identity on the wire (no silently inherited admin auth). */
const wireLog: Array<{ body: string; cookie: string; authorization: string }> = [];

before(async () => {
  server = http.createServer(async (req, res) => {
    const u = new URL(req.url ?? "/", "http://x");
    const secure = u.pathname === "/graphql-secure";
    if ((u.pathname === "/graphql" || secure) && req.method === "POST") {
      const raw = await readBody(req);
      const cookie = req.headers.cookie ?? "";
      const authz = req.headers.authorization ?? "";
      wireLog.push({ body: raw, cookie, authorization: authz });
      // Identity on the wire: session cookie OR a Bearer of the form 'role-<name>'.
      const role =
        /(?:^|;\s*)role=([a-z0-9_-]+)/i.exec(cookie)?.[1] ??
        /bearer\s+role-([a-z0-9_-]+)/i.exec(authz)?.[1] ??
        "";
      res.setHeader("content-type", "application/json");
      try {
        const j = JSON.parse(raw) as unknown;
        if (Array.isArray(j)) {
          if (secure) { res.end(JSON.stringify({ errors: [{ message: "batching not supported", extensions: { code: "BAD_REQUEST" } }] })); return; } // capability OFF
          res.end(JSON.stringify(await Promise.all(j.map((b) => execOp(b as { query?: string }, { role, secure: false })))));
          return;
        }
        const o = j as { query?: string; operationName?: string; variables?: Record<string, unknown> };
        res.end(JSON.stringify(await execOp(o, { role, secure })));
      } catch {
        res.statusCode = 400;
        res.end('{"errors":[{"message":"bad json"}]}');
      }
      return;
    }
    res.statusCode = 404;
    res.end("nf");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}/`;
  dir = mkdtempSync(join(tmpdir(), "veritas-gql-"));
  for (const r of ["user2", "admin"]) writeFileSync(join(dir, `${r}.cookies`), `role=${r}`);
});
after(() => { server.close(); rmSync(dir, { recursive: true, force: true }); });

/** One session per test — its OWN sqlite (closed before return… caller closes via s.store.close()).
 *  `defaultHeaders` simulates a client configured with site-wide auth (run.ts supplies Basic/cookie/custom
 *  auth there); isolated legs must NOT inherit them. */
function session(opts: { role?: string; apis?: ApiCall[]; defaultHeaders?: Record<string, string> }): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(base) });
  const inv = new InventoryBuilder();
  let screenId = "s-1";
  for (const api of opts.apis ?? []) {
    const built = apiCallToBuiltScreen(api, base);
    if (built) screenId = inv.ingestBuilt(built).screen.screenId;
  }
  return {
    http: new FetchHttpClient({ allow: (url: string) => url.startsWith(base.replace(/\/$/, "")), headers: opts.defaultHeaders }),
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, `art-${dbN}`)), inv,
    scope: deriveScopeFromSingleUrl(base), targetUrl: base, currentScreenId: screenId,
    currentCookie: opts.role ? `role=${opts.role}` : "", currentBearer: "", currentRole: opts.role ?? "",
    roleCreds: new Map(), roleSessions: undefined,
    roleCookieFiles: new Map([["user2", join(dir, "user2.cookies")], ["admin", join(dir, "admin.cookies")]]),
    roleDescriptions: new Map([["admin", "site administrator"], ["user2", "ordinary user"]]),
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
}
async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = (await t.handler(args, {})).content[0]!.text;
  try { return JSON.parse(out) as Record<string, unknown>; } catch { return { raw: out }; }
}
const close = (s: PilotSession): void => (s as unknown as { store: { close(): void } }).store.close();

const GET_ORDER: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "query", operationName: "GetOrder", operationKey: "name:GetOrder:x", rootFields: ["order"], responseKeys: ["order"], variablesShape: { id: "string" }, document: "query GetOrder($id: ID!) { order(id: $id) { id ownerId total phone } }", variablesExample: { id: "1" } },
};
const GET_ORDER_SECURE: ApiCall = { ...GET_ORDER, urlTemplate: "/graphql-secure" };
const GET_USER: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "query", operationName: "GetUser", operationKey: "name:GetUser:x", rootFields: ["user"], responseKeys: ["user"], variablesShape: { id: "string" }, document: "query GetUser($id: ID!) { user(id: $id) { id name email salary dbNote } }", variablesExample: { id: "1" } },
};
const DB_PING: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "query", operationName: "DbPing", operationKey: "name:DbPing:x", rootFields: ["dbPing"], responseKeys: ["dbPing"], variablesShape: {}, document: "query DbPing { dbPing }", variablesExample: {} },
};
const APPEND_NOTE: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "mutation", operationName: "AppendNote", operationKey: "name:AppendNote:x", rootFields: ["appendNote"], responseKeys: ["appendNote"], variablesShape: { id: "string", text: "string" }, document: "mutation AppendNote($id: ID!, $text: String!) { appendNote(id: $id, text: $text) { id text } }", variablesExample: { id: "n1", text: "X" } },
};
const GUARDED_NOTE: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "mutation", operationName: "GuardedNote", operationKey: "name:GuardedNote:x", rootFields: ["guardedNote"], responseKeys: ["guardedNote"], variablesShape: { id: "string", text: "string" }, document: "mutation GuardedNote($id: ID!, $text: String!) { guardedNote(id: $id, text: $text) { id text } }", variablesExample: { id: "n1", text: "ghost" } },
};
const UPDATE_NOTE_SECURE: ApiCall = {
  method: "POST", urlTemplate: "/graphql-secure", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "mutation", operationName: "UpdateNote", operationKey: "name:UpdateNote:x", rootFields: ["updateNote"], responseKeys: ["updateNote"], variablesShape: { id: "string", text: "string" }, document: "mutation UpdateNote($id: ID!, $text: String!) { updateNote(id: $id, text: $text) { id text } }", variablesExample: { id: "n1", text: "y" } },
};
const GET_ORDER_BY_OWNER: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "query", operationName: "GetOrderByOwner", operationKey: "name:GetOrderByOwner:x", rootFields: ["orderByOwner"], responseKeys: ["orderByOwner"], variablesShape: { in: "object" }, document: "query GetOrderByOwner($in: OrderFilter!) { orderByOwner(input: $in) { id ownerId total phone } }", variablesExample: { in: { ownerId: "user1", tag: "keepme", limit: 5 } } },
};
const DELETE_NOTE: ApiCall = {
  method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
  graphql: { operationType: "mutation", operationName: "DeleteNote", operationKey: "name:DeleteNote:x", rootFields: ["deleteNote"], responseKeys: ["deleteNote"], variablesShape: { id: "string" }, document: "mutation DeleteNote($id: ID!) { deleteNote(id: $id) { id text } }", variablesExample: { id: "n1" } },
};
const verifyNote = { document: "query GetNote($id: ID!) { note(id: $id) { id text } }", operationName: "GetNote", variables: { id: "n1" } };
const verifyNoteStatus = { document: "query GetNoteS($id: ID!) { note(id: $id) { id status } }", operationName: "GetNoteS", variables: { id: "nerr" } };

test("REAL-ENGINE probe_graphql: bounded schema catalog harvested by real introspection, PUBLIC proven by unauth replay, schemaOps surfaced, batching = capability note", async () => {
  const s = session({ role: "user1" });
  try {
    const r = await run(s, "probe_graphql", { url: base + "graphql" });
    const checks = r.checks as Array<Record<string, unknown>>;
    const intro = checks.find((c) => c.name === "introspection")!;
    assert.equal(intro.confirmed, true, JSON.stringify(r));
    assert.equal(intro.public, true); // schema readable with NO auth headers → genuinely public
    assert.ok(intro.unauthControl);
    const ops = r.schemaOps as { queries: Array<{ name: string }>; mutations: Array<{ name: string }> };
    assert.ok(ops.queries.some((q) => q.name === "order") && ops.mutations.some((m) => m.name === "updateNote"));
    const sugg = checks.find((c) => c.name === "field-suggestions")!;
    assert.equal(sugg.confirmed, true); // the real engine's "Did you mean __typename?" — not a fixture string
    const batch = r.batching as Record<string, unknown>;
    assert.equal(batch.accepted, true);
    assert.match(String(batch.note), /capability observation/i); // phrased as a capability, not a bypass
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql on the secure endpoint: introspection confirmed under auth but public=false; batching not accepted", async () => {
  const s = session({ role: "user1" });
  try {
    const r = await run(s, "probe_graphql", { url: base + "graphql-secure" });
    const intro = (r.checks as Array<Record<string, unknown>>).find((c) => c.name === "introspection")!;
    assert.equal(intro.confirmed, true);
    assert.equal(intro.public, false); // unauth replay was denied → authenticated-context only, NOT anonymous exposure
    assert.match(String(intro.note), /authenticated context|current session/i);
    assert.equal((r.batching as { accepted: boolean }).accepted, false);
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: baseline established; cross-role SAME ACCESS on the permissive resolver (the hole)", async () => {
  const s = session({ role: "user1", apis: [GET_ORDER] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrder", compareRole: "user2" });
    const b = r.baseline as { evidenceId?: string; fields?: string[] };
    assert.ok(b.evidenceId && (b.fields ?? []).includes("order"), JSON.stringify(r)); // baseline EXECUTED first
    assert.match(String(r.verdict), /SAME ACCESS/); // user2 read user1's order fields — the anomaly the model must now judge
    assert.equal((r.unauthControl as { dataReturned: boolean }).dataReturned, false); // unauth was denied
    assert.ok(((r.compare as { replays: string[] }).replays).length === 2);
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: ACCESS HELD on the secure resolver (ownership enforced → real FORBIDDEN)", async () => {
  const s = session({ role: "user1", apis: [GET_ORDER_SECURE] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql-secure", operationName: "GetOrder", compareRole: "user2" });
    assert.match(String(r.verdict), /ACCESS HELD/, JSON.stringify(r));
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: field-level authz vs resolver failure — salary FORBIDDEN is authz, dbNote INTERNAL is NOT", async () => {
  const s = session({ role: "admin", apis: [GET_USER] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetUser", compareRole: "user2" });
    const cmp = r.compare as { errorFields?: string[]; failedFields?: string[] };
    assert.match(String(r.verdict), /FIELD-LEVEL AUTHZ/, JSON.stringify(r)); // partial data → the denied field surfaced
    assert.ok((cmp.errorFields ?? []).some((f) => f.includes("salary")), JSON.stringify(cmp)); // real FORBIDDEN at user.salary
    assert.ok((cmp.failedFields ?? []).some((f) => f.includes("dbNote")), JSON.stringify(cmp)); // INTERNAL — reported separately, NOT as protection
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: errors-only INTERNAL with auth-looking wording → UNVERIFIED, never tested-clean", async () => {
  const s = session({ role: "admin", apis: [DB_PING] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "DbPing", compareRole: "user2" });
    // 'Access denied for user app@db' is a DATABASE failure — it proves neither enforcement nor bypass.
    assert.match(String(r.verdict), /UNVERIFIED/, JSON.stringify(r));
    assert.ok(!/ACCESS HELD|SAME ACCESS/.test(String(r.verdict)), JSON.stringify(r));
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: baseline UNVERIFIED when the op rejects the request (missing required variable)", async () => {
  const s = session({ role: "user1", apis: [{ ...GET_ORDER, graphql: { ...GET_ORDER.graphql!, variablesExample: {} } }] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrder" });
    assert.match(String(r.verdict), /UNVERIFIED/, JSON.stringify(r));
    assert.match(String((r.baseline as { kind?: string }).kind), /errors/);
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: aliases + named fragments — baseline keys on the RESPONSE key (data.current)", async () => {
  const s = session({ role: "admin" });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql",
      document: "query Aliased($id: ID!) { current: user(id: $id) { id ...F } } fragment F on User { name email }",
      operationName: "Aliased",
      variables: { id: "1" },
    });
    const b = r.baseline as { kind?: string; returnedFields?: string[] };
    assert.equal(b.kind ?? "ok", "ok", JSON.stringify(r));
    assert.deepEqual(b.returnedFields, ["current"]); // data.current — NOT data.user
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: setVariable surgically replaces ONE nested leaf (typed) — resolver sees the swap", async () => {
  const s = session({ role: "user1", apis: [{ ...GET_ORDER, graphql: { ...GET_ORDER.graphql!, variablesExample: { id: "1", extra: { keep: "yes" } }, variablesShape: { id: "string", extra: "object" } } }] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrder", setVariable: { path: "variables.id", value: "2" } });
    const b = r.baseline as { kind?: string; evidenceId?: string; variableEdits?: string[] };
    assert.equal(b.kind ?? "ok", "ok", JSON.stringify(r));
    assert.ok((b.variableEdits ?? []).some((p) => p.includes("variables.id")));
    // The evidence's baseline response must carry victim order 2 (the swap reached the resolver, other vars intact)
    const ev = (s as unknown as { evidence: EvidenceStore }).evidence;
    const rec = ev.records.find((x) => x.id === b.evidenceId)!;
    assert.match(rec.response.body, /"ownerId":"user2"/);
    const sentVars = JSON.parse(rec.request.body!) as { variables: Record<string, unknown> };
    assert.equal((sentVars.variables.extra as { keep: string }).keep, "yes"); // sibling leaf untouched
    // replace-only refuses a missing path
    const bad = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrder", setVariable: { path: "variables.nonexistent", value: "1" } });
    assert.match(String(bad.raw ?? bad.error ?? ""), /ERROR|does not exist/);
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: mutation requires explicit opt-in — no mutationAck → refused, zero wire requests", async () => {
  wireLog.length = 0;
  const s = session({ role: "admin", apis: [APPEND_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "AppendNote", compareRole: "user2", verifyQuery: verifyNote, verifyPath: "note.text" });
    assert.match(String(r.raw ?? r.error ?? r.verdict ?? ""), /requires explicit opt-in|mutationAck/, JSON.stringify(r));
    assert.equal(wireLog.filter((b) => b.body.includes("appendNote")).length, 0); // nothing was ever sent
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: destructive-named mutation refused even WITH mutationAck — zero wire requests", async () => {
  wireLog.length = 0;
  const s = session({ role: "admin", apis: [DELETE_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "DeleteNote", mutationAck: "DeleteNote", compareRole: "user2", verifyQuery: verifyNote, verifyPath: "note.text" });
    assert.match(String(r.raw ?? r.error ?? r.verdict ?? ""), /destructive/i, JSON.stringify(r));
    assert.equal(wireLog.filter((b) => b.body.includes("deleteNote")).length, 0);
    assert.equal(typeof NOTES["n1"]?.text, "string"); // state untouched
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: non-idempotent mutation under another role + verifyQuery — BOTH replays move state → MUTATION EXECUTED", async () => {
  NOTES["n1"] = { text: "original", owner: "user1" };
  const s = session({ role: "admin", apis: [APPEND_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql", operationName: "AppendNote", mutationAck: "AppendNote", variables: { id: "n1", text: "+u2" },
      compareRole: "user2", verifyQuery: verifyNote, verifyPath: "note.text",
    });
    assert.match(String(r.verdict), /MUTATION EXECUTED/, JSON.stringify(r));
    assert.deepEqual((r.verifyQuery as { perReplayAttribution: unknown[] }).perReplayAttribution, [true, true]);
    assert.ok(NOTES["n1"].text.endsWith("+u2+u2")); // baseline + 2 replays actually appended (real state)
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: baseline write + low-role no-op response → NOT attributed (guardedNote soft-deny)", async () => {
  NOTES["n1"] = { text: "original", owner: "user1" };
  const s = session({ role: "admin", apis: [GUARDED_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql", operationName: "GuardedNote", mutationAck: "GuardedNote", variables: { id: "n1", text: "ghost-write" },
      compareRole: "user2", verifyQuery: verifyNote, verifyPath: "note.text",
    });
    // admin baseline DID write; each user2 replay returned data but moved nothing → neither attributable.
    assert.match(String(r.verdict), /NEITHER replay|UNVERIFIED/, JSON.stringify(r));
    assert.ok(!/MUTATION EXECUTED/.test(String(r.verdict)), JSON.stringify(r));
    assert.equal(NOTES["n1"].text, "ghost-write"); // only the baseline write landed
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: denied write on the secure endpoint (ownership) → ACCESS HELD", async () => {
  NOTES["n1"] = { text: "original", owner: "user1" };
  const s = session({ role: "user1", apis: [UPDATE_NOTE_SECURE] });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql-secure", operationName: "UpdateNote", mutationAck: "UpdateNote", variables: { id: "n1", text: "hijack" },
      compareRole: "user2", verifyQuery: verifyNote, verifyPath: "note.text",
    });
    assert.match(String(r.verdict), /ACCESS HELD/, JSON.stringify(r));
    assert.equal(NOTES["n1"].text, "hijack"); // baseline (owner) wrote; user2 replay denied
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: verify read erroring ON verifyPath → attribution unknowable → UNVERIFIED", async () => {
  NOTES["nerr"] = { text: "boom", owner: "user1" };
  const s = session({ role: "admin", apis: [APPEND_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql", operationName: "AppendNote", mutationAck: "AppendNote", variables: { id: "nerr", text: "+" },
      compareRole: "user2", verifyQuery: verifyNoteStatus, verifyPath: "note.status",
    });
    // note.status resolver throws INTERNAL_SERVER_ERROR at path ["note","status"] — a failed read at the very
    // path we'd compare must NOT be read as a delta.
    assert.match(String(r.verdict), /UNVERIFIED/, JSON.stringify(r));
    assert.ok(!/MUTATION EXECUTED/.test(String(r.verdict)), JSON.stringify(r));
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: verifyQuery that is a MUTATION is refused (read-only enforcement)", async () => {
  const s = session({ role: "admin", apis: [APPEND_NOTE] });
  try {
    const r = await run(s, "probe_graphql_op", {
      url: base + "graphql", operationName: "AppendNote", mutationAck: "AppendNote", compareRole: "user2",
      verifyQuery: { document: "mutation X($id: ID!) { updateNote(id: $id, text: \"x\") { id } }", operationName: "X", variables: { id: "n1" } },
      verifyPath: "note.text",
    });
    assert.match(String(r.raw ?? r.error ?? r.verdict ?? ""), /read-only query/, JSON.stringify(r));
  } finally { close(s); }
});

test("REAL-ENGINE probe_idor SWEEP discovers the GraphQL variables.id leaf and hands the observed hole to probe_authz — mutations excluded", async () => {
  wireLog.length = 0;
  const s = session({ role: "user1", apis: [GET_ORDER, DELETE_NOTE] }); // a destructive op sits in inventory beside the query
  try {
    const r = await run(s, "probe_idor", { url: base + "graphql" }); // no param → sweep every id-bearing field incl. graphql vars
    assert.equal(r.mode, "sweep", JSON.stringify(r));
    assert.equal(r.param, "vars.id");
    assert.equal(r.via, "json-field");
    // The sweep OBSERVES the cross-user read but no longer self-confirms — confirmation is
    // probe_authz's verified ownership + denied-control comparison (record_finding requires it).
    assert.match(String(r.verdict), /CROSS-USER READ OBSERVED/);
    assert.match(String(r.verdict), /probe_authz/);
    assert.ok(Array.isArray(r.positiveReplays) && (r.positiveReplays as unknown[]).length === 2);
    assert.ok(r.negativeControl);
    // The observed DESTRUCTIVE mutation was never replayed by the sweep — zero wire requests for it.
    assert.equal(wireLog.filter((b) => b.body.includes("deleteNote")).length, 0);
    assert.equal(typeof NOTES["n1"], "object"); // nothing deleted
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: setVariable into a real InputObject — variables.in.ownerId swapped, siblings intact on the wire", async () => {
  const s = session({ role: "user1", apis: [GET_ORDER_BY_OWNER] });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrderByOwner", setVariable: { path: "variables.in.ownerId", value: "user2" } });
    const b = r.baseline as { kind?: string; evidenceId?: string };
    assert.equal(b.kind ?? "ok", "ok", JSON.stringify(r));
    // The nested leaf reached the resolver through real input coercion — user2's order came back.
    const rec = (s as unknown as { evidence: EvidenceStore }).evidence.records.find((x) => x.id === b.evidenceId)!;
    assert.match(rec.response.body, /"ownerId":"user2"/);
    const sent = JSON.parse(rec.request.body!) as { variables: { in: Record<string, unknown> } };
    assert.equal(sent.variables.in.ownerId, "user2"); // the one surgical edit
    assert.equal(sent.variables.in.tag, "keepme"); // sibling string preserved
    assert.equal(sent.variables.in.limit, 5); // sibling NUMBER kept typed (not stringified)
  } finally { close(s); }
});

test("REAL-ENGINE auth isolation: default admin headers reach the wire ONLY on the session legs — anonymous/compare legs carry their own identity", async () => {
  wireLog.length = 0;
  // Client configured with site-wide auth (as run.ts does): Basic-ish bearer + admin cookie as DEFAULTS.
  const s = session({
    role: "", // current session has no cookie of its own — identity comes from the client's default headers
    apis: [GET_USER],
    defaultHeaders: { cookie: "role=admin", authorization: "Bearer role-admin" },
  });
  try {
    // (a) probe_graphql meta: introspection succeeds via inherited admin defaults; the anonymous replay must
    //     arrive with NO auth → on the secure endpoint that means the gate denies it → public=false.
    const meta = await run(s, "probe_graphql", { url: base + "graphql-secure" });
    const intro = (meta.checks as Array<Record<string, unknown>>).find((c) => c.name === "introspection")!;
    assert.equal(intro.confirmed, true, JSON.stringify(meta));
    assert.equal(intro.public, false); // anonymous leg really was anonymous
    const schemaReqs = wireLog.filter((w) => w.body.includes("__schema"));
    // control + 2 positives rode the inherited admin identity; the unauth replay did not.
    assert.ok(schemaReqs.length >= 4, JSON.stringify(schemaReqs));
    assert.ok(schemaReqs.slice(0, -1).every((w) => /role=admin/.test(w.cookie) && /role-admin/.test(w.authorization)));
    const lastSchema = schemaReqs[schemaReqs.length - 1]!;
    assert.equal(lastSchema.cookie, ""); // no cookie on the wire
    assert.equal(lastSchema.authorization, ""); // no bearer either

    // (b) probe_graphql_op: baseline (current session) inherits admin → salary/dbNote resolve;
    //     compareRole=user2 sends ONLY role=user2; the unauth control sends nothing.
    wireLog.length = 0;
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetUser", compareRole: "user2" });
    assert.match(String(r.verdict), /FIELD-LEVEL AUTHZ|SAME ACCESS/, JSON.stringify(r));
    const legs = wireLog.filter((w) => w.body.includes("GetUser"));
    assert.equal(legs.length, 4, JSON.stringify(legs.map((w) => w.cookie))); // baseline + unauth + 2 replays
    assert.match(legs[0]!.cookie, /role=admin/); // baseline = the session's inherited identity
    assert.match(legs[0]!.authorization, /role-admin/);
    assert.equal(legs[1]!.cookie, ""); // unauth control — nothing inherited
    assert.equal(legs[1]!.authorization, "");
    for (const l of legs.slice(2)) {
      assert.match(l.cookie, /role=user2/); // compare role — and ONLY that role
      assert.ok(!/admin/.test(l.cookie));
      assert.equal(l.authorization, ""); // the admin bearer did NOT leak onto the user2 leg
    }
  } finally { close(s); }
});

test("REAL-ENGINE auth isolation: baselineRole:'unauth' sends its baseline + verify reads with NO inherited auth", async () => {
  wireLog.length = 0;
  const s = session({
    role: "",
    apis: [GET_ORDER],
    defaultHeaders: { cookie: "role=admin", authorization: "Bearer role-admin" },
  });
  try {
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrder", baselineRole: "unauth" });
    // The baseline genuinely arrived anonymous → the op denied it → baseline not established → UNVERIFIED.
    assert.match(String(r.verdict), /UNVERIFIED/, JSON.stringify(r));
    const baseReq = wireLog.find((w) => w.body.includes("GetOrder"))!;
    assert.equal(baseReq.cookie, "", JSON.stringify(baseReq));
    assert.equal(baseReq.authorization, "", JSON.stringify(baseReq));
  } finally { close(s); }
});

test("REAL-ENGINE probe_idor on the secure endpoint does NOT confirm (ownership enforced)", async () => {
  const s = session({ role: "user1", apis: [GET_ORDER_SECURE] });
  try {
    const r = await run(s, "probe_idor", { url: base + "graphql-secure" });
    assert.equal(r.mode, "sweep");
    assert.match(String(r.verdict), /CLEAN|not confirmed|scoping holds/i, JSON.stringify(r)); // enforced → no finding
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: setVariable must NOT mutate stored inventory or the caller's variables — the next baseline uses the original values", async () => {
  const s = session({ role: "user1", apis: [GET_ORDER_BY_OWNER] });
  const callerVars = { in: { ownerId: "user1", tag: "mine" } };
  try {
    // Run 1: surgical swap of ONE nested leaf.
    const r1 = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrderByOwner", variables: callerVars, setVariable: { path: "variables.in.ownerId", value: "user2" } });
    assert.equal((r1.baseline as { kind?: string }).kind ?? "ok", "ok", JSON.stringify(r1));
    // The stored op's example and the caller's object are both untouched.
    assert.equal((GET_ORDER_BY_OWNER.graphql!.variablesExample!.in as { ownerId: string }).ownerId, "user1");
    assert.equal(callerVars.in.ownerId, "user1");
    assert.equal(callerVars.in.tag, "mine");
    // Run 2: no edit — the baseline must resolve the ORIGINAL ownerId (user1's order 1, not a polluted user2 read).
    const r2 = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "GetOrderByOwner" });
    const rec = (s as unknown as { evidence: EvidenceStore }).evidence.records.find((x) => x.id === (r2.baseline as { evidenceId?: string }).evidenceId)!;
    assert.match(rec.response.body, /"ownerId":"user1"/, `next baseline must replay the stored values, not the last edit (${rec.response.body})`);
  } finally { close(s); }
});

test("REAL-ENGINE probe_graphql_op: operationKey resolves EXACTLY; a same-named pair is ambiguous by name and refused", async () => {
  // Two stored ops share the operationName "Same" but differ structurally — identity is the key, not the name.
  const mkOp = (doc: string): ApiCall => {
    const d = describeGraphqlOperation(JSON.stringify({ query: doc, operationName: "Same", variables: { id: "1" } }))!;
    return {
      method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
      graphql: { operationType: d.operationType, operationName: d.operationName, operationKey: d.operationKey, rootFields: d.rootFields, responseKeys: d.responseKeys, variablesShape: d.variablesShape, document: d.document, variablesExample: d.variablesExample },
    };
  };
  const opIdOnly = mkOp('query Same($id: ID!) { order(id: $id) { id } }');
  const opWithTotal = mkOp('query Same($id: ID!) { order(id: $id) { id total } }');
  assert.notEqual(opIdOnly.graphql!.operationKey, opWithTotal.graphql!.operationKey);
  const s = session({ role: "user1", apis: [opIdOnly, opWithTotal] });
  try {
    // By name → ambiguous: refused, and the error lists BOTH candidate keys.
    const amb = await run(s, "probe_graphql_op", { url: base + "graphql", operationName: "Same" });
    const ambText = String(amb.raw ?? amb.error ?? "");
    assert.match(ambText, /ambiguous/i);
    assert.ok(ambText.includes(opIdOnly.graphql!.operationKey) && ambText.includes(opWithTotal.graphql!.operationKey), ambText);
    // By exact key → THAT document executes (the {id total} variant returns a total on the wire).
    const r = await run(s, "probe_graphql_op", { url: base + "graphql", operationKey: opWithTotal.graphql!.operationKey });
    const b = r.baseline as { kind?: string; evidenceId?: string };
    assert.equal(b.kind ?? "ok", "ok", JSON.stringify(r));
    const rec = (s as unknown as { evidence: EvidenceStore }).evidence.records.find((x) => x.id === b.evidenceId)!;
    assert.match(rec.request.body!, /total/, "the keyed (wider) document must be the one sent");
    // An unknown key does NOT silently fall back to the first same-named op.
    const none = await run(s, "probe_graphql_op", { url: base + "graphql", operationKey: "name:Same:deadbeef" });
    assert.match(String(none.raw ?? none.error ?? ""), /ERROR|no GraphQL operation matched/);
  } finally { close(s); }
});
