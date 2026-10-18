// GraphQL operation parsing + identity + inventory merge. The contract: distinct operations on one POST /graphql
// endpoint stay distinct (operationKey), while the SAME operation replayed with different variable VALUES shares
// one identity (structure-only canonicalization) — value churn must not multiply inventory entries.
import { test } from "node:test";
import assert from "node:assert/strict";
import { describeGraphqlOperation, parseGraphqlDocument, maskVariables } from "./graphql.js";
import { inferApiCall, apiKey } from "./api.js";
import { InventoryBuilder } from "./inventory.js";
import { apiCallToBuiltScreen } from "./openapi-ingest.js";
import type { CapturedExchange } from "./types.js";
import type { ApiCall } from "@veritas/core";

const ex = (over: Partial<CapturedExchange>): CapturedExchange => ({
  method: "POST",
  url: "https://app.test/graphql",
  resourceType: "fetch",
  hasAuthorizationHeader: false,
  hasCookieHeader: true,
  requestBody: null,
  status: 200,
  responseBodySample: null,
  responseContentType: "application/json",
  ...over,
});

const apiFor = (body: string): ApiCall => inferApiCall(ex({ requestBody: body }));

test("parse: named operation → name:key, root fields, variable names", () => {
  const d = parseGraphqlDocument("query GetOrder($id: ID!, $opts: Opts = {full: true}) { order(id: $id) { id total } }");
  assert.ok(d);
  assert.equal(d.operations.length, 1);
  const op = d.operations[0]!;
  assert.equal(op.operationType, "query");
  assert.equal(op.operationName, "GetOrder");
  assert.deepEqual(op.variableNames, ["id", "opts"]);
  assert.deepEqual(op.rootFields, ["order"]);
});

test("parse: anonymous shorthand `{...}` is a query with null name", () => {
  const d = parseGraphqlDocument("{ me { id name } }");
  assert.ok(d);
  assert.equal(d.operations[0]!.operationName, null);
  assert.deepEqual(d.operations[0]!.rootFields, ["me"]);
});

test("parse: mutation + subscription types recognized; SDL/type defs rejected", () => {
  assert.equal(parseGraphqlDocument("mutation M($x: Int) { setX(v: $x) }")!.operations[0]!.operationType, "mutation");
  assert.equal(parseGraphqlDocument("subscription S { tick }")!.operations[0]!.operationType, "subscription");
  // SDL is not an executable document — must not become a replayable "operation".
  assert.equal(parseGraphqlDocument("type User { id: ID! name: String }"), null);
  assert.equal(parseGraphqlDocument("schema { query: RootQuery }"), null);
  assert.equal(parseGraphqlDocument("input Filter { a: Int }"), null);
});

test("identity: same op, different variable VALUES → same operationKey (no per-value proliferation)", () => {
  const mk = (id: number) =>
    describeGraphqlOperation(JSON.stringify({ query: "query GetOrder($id: ID!) { order(id: $id) { id } }", operationName: "GetOrder", variables: { id } }));
  assert.equal(mk(1)!.operationKey, mk(9999)!.operationKey);
  // Anonymous docs: value differences in literals also collapse to the same doc-hash.
  const a = describeGraphqlOperation(JSON.stringify({ query: '{ order(id: 1) { id total } }', variables: {} }));
  const b = describeGraphqlOperation(JSON.stringify({ query: '{ order(id: 777) { id total } }', variables: {} }));
  assert.ok(a && b && a.operationKey.startsWith("doc:"));
  assert.equal(a.operationKey, b.operationKey);
  // …but a genuinely different SHAPE is a different operation.
  const c = describeGraphqlOperation(JSON.stringify({ query: '{ order(id: 777) { id total items { sku } } }', variables: {} }));
  assert.notEqual(a!.operationKey, c!.operationKey);
});

test("identity: aliases resolve to real field names; inline-fragment fields count as root fields", () => {
  const d = parseGraphqlDocument("query Q { myOrder: order(id: 1) { id } ... on Query { second: cart { id } } ...Frag } fragment Frag on Query { x }");
  assert.ok(d);
  const op = d.operations[0]!;
  assert.ok(op.rootFields.includes("order"));
  assert.ok(op.rootFields.includes("cart")); // reached through the inline fragment
  assert.ok(!op.rootFields.includes("myOrder") && !op.rootFields.includes("second")); // aliases → real names
});

test("maskVariables: credential-looking names are redacted RECURSIVELY (nested objects + arrays), ids kept", () => {
  const m = maskVariables({
    id: "42",
    password: "hunter2",
    input: { ownerId: "7", secret: "nested-leak", creds: [{ token: "t1" }, { token: "t2" }] },
    list: [{ apiKey: "k1" }, { key: "plain" }],
  });
  assert.equal(m!.id, "42");
  assert.equal(m!.password, "<redacted>");
  const input = m!.input as Record<string, unknown>;
  assert.equal(input.ownerId, "7"); // non-secret nested id survives
  assert.equal(input.secret, "<redacted>"); // nested credential field masked
  assert.deepEqual(input.creds, [{ token: "<redacted>" }, { token: "<redacted>" }]); // array of objects
  assert.deepEqual(m!.list, [{ apiKey: "<redacted>" }, { key: "plain" }]);
});

test("describe: variable REFERENCED from a sensitive position is masked even when its name is innocent", () => {
  // login(password: $p) — $p's value is the credential; name "p" alone would never match the regex.
  const op = describeGraphqlOperation(JSON.stringify({
    query: "mutation Login($u: String, $p: String) { login(username: $u, password: $p) { ok } }",
    operationName: "Login",
    variables: { u: "alice", p: "hunter2" },
  }));
  assert.ok(op);
  assert.equal(op.variablesExample!.u, "alice"); // username: not credential-looking
  assert.equal(op.variablesExample!.p, "<redacted>"); // masked by USE, not by name
});

test("describe: inline literals under credential-looking args/input fields are nulled; benign literals kept", () => {
  const op = describeGraphqlOperation(JSON.stringify({
    query: 'mutation Login($id: ID!) { login(user: "alice", password: "hunter2", opts: { token: "t", id: $id }) { ok } }',
    operationName: "Login",
    variables: { id: "u-1" },
  }));
  assert.ok(op);
  const doc = op.document;
  assert.match(doc, /user:\s*"alice"/); // non-secret literal preserved
  assert.match(doc, /password:\s*null/); // credential arg literal masked
  assert.match(doc, /token:\s*null/); // nested input credential field masked
  assert.match(doc, /id:\s*\$id/); // variable refs untouched
  assert.ok(!doc.includes("hunter2") && !doc.includes('"t"'));
  // The sanitized document still parses to the same canonical identity.
  const re = describeGraphqlOperation(JSON.stringify({ query: doc, operationName: "Login" }));
  assert.equal(re!.operationKey, op.operationKey);
});

test("describe: variable defaults — benign default preserved verbatim, credential-named and sensitively-used dropped whole", () => {
  // Benign default: replayable doc keeps it (null would be invalid on ID!).
  const keep = describeGraphqlOperation(JSON.stringify({
    query: 'query Q($id: ID! = "known-id") { order(id: $id) { id } }',
    operationName: "Q",
  }));
  assert.match(keep!.document, /\$id:\s*ID!\s*=\s*"known-id"/);
  // Credential-NAMED default dropped (name says it's a secret).
  const cred = describeGraphqlOperation(JSON.stringify({
    query: 'mutation M($apiKey: String! = "k-secret") { use(key: $apiKey) }',
    operationName: "M",
  }));
  assert.match(cred!.document, /\$apiKey:\s*String!\s*[,)]/);
  assert.ok(!cred!.document.includes("k-secret"));
  // Innocent NAME but sensitive USE: login(password:$p) — the default is a password by use, drop it too.
  const used = describeGraphqlOperation(JSON.stringify({
    query: 'mutation Login($p: String! = "synthetic-alias-default") { login(password: $p) { ok } }',
    operationName: "Login",
  }));
  assert.match(used!.document, /\$p:\s*String!\s*\)/);
  assert.ok(!used!.document.includes("synthetic-alias-default"));
});

test("identity: same operationName, different selection → different operationKeys (no name-only collision)", () => {
  const a = describeGraphqlOperation(JSON.stringify({ query: "query Same { user { id } }", operationName: "Same" }));
  const b = describeGraphqlOperation(JSON.stringify({ query: "query Same { user { id name } }", operationName: "Same" }));
  assert.ok(a && b);
  assert.equal(a.operationName, "Same");
  assert.equal(b.operationName, "Same");
  assert.notEqual(a.operationKey, b.operationKey); // the name alone must NOT be the identity
});

test("identity: used fragment bodies are part of the key — same op, different fragment = different op", () => {
  const a = describeGraphqlOperation(JSON.stringify({
    query: "query Same { ...F } fragment F on Query { user { id } }", operationName: "Same",
  }));
  const b = describeGraphqlOperation(JSON.stringify({
    query: "query Same { ...F } fragment F on Query { user { id email } }", operationName: "Same",
  }));
  assert.ok(a && b);
  assert.notEqual(a.operationKey, b.operationKey); // fragment body changed → identity changed
});

test("identity: root MUTATION selections execute in order — order is part of identity", () => {
  const a = describeGraphqlOperation(JSON.stringify({ query: "mutation M { setFlag { id } clearFlag { id } }", operationName: "M" }));
  const b = describeGraphqlOperation(JSON.stringify({ query: "mutation M { clearFlag { id } setFlag { id } }", operationName: "M" }));
  assert.ok(a && b);
  assert.notEqual(a.operationKey, b.operationKey); // reversed order is a DIFFERENT operation
  // but QUERY root order stays semantic-free (sorted): same op either way
  const qa = describeGraphqlOperation(JSON.stringify({ query: "query Q { b { id } a { id } }", operationName: "Q" }));
  const qb = describeGraphqlOperation(JSON.stringify({ query: "query Q { a { id } b { id } }", operationName: "Q" }));
  assert.equal(qa!.operationKey, qb!.operationKey);
});

test("identity: mutation execution order survives INLINE and NAMED Mutation fragments", () => {
  // Inline fragments at a mutation root execute serially — reversed members are a different operation.
  const iFwd = describeGraphqlOperation(JSON.stringify({ query: "mutation M { ... on Mutation { setFlag clearFlag } }" }));
  const iRev = describeGraphqlOperation(JSON.stringify({ query: "mutation M { ... on Mutation { clearFlag setFlag } }" }));
  assert.ok(iFwd && iRev);
  assert.notEqual(iFwd.operationKey, iRev.operationKey);
  // Named fragments ON the Mutation type likewise carry ordered members into the root identity.
  const nFwd = describeGraphqlOperation(JSON.stringify({ query: "mutation M { ...F } fragment F on Mutation { setFlag clearFlag }" }));
  const nRev = describeGraphqlOperation(JSON.stringify({ query: "mutation M { ...F } fragment F on Mutation { clearFlag setFlag }" }));
  assert.ok(nFwd && nRev);
  assert.notEqual(nFwd.operationKey, nRev.operationKey);
  // …while a fragment on a non-root type inside a QUERY remains order-insensitive.
  const qFwd = describeGraphqlOperation(JSON.stringify({ query: "query { user { ...F } } fragment F on User { name email }" }));
  const qRev = describeGraphqlOperation(JSON.stringify({ query: "query { user { ...F } } fragment F on User { email name }" }));
  assert.equal(qFwd!.operationKey, qRev!.operationKey);
});

test("identity: response aliases are part of the key — first:user and second:user are different operations", () => {
  const first = describeGraphqlOperation(JSON.stringify({ query: "{ first: user(id: 1) { id } }" }));
  const second = describeGraphqlOperation(JSON.stringify({ query: "{ second: user(id: 1) { id } }" }));
  assert.ok(first && second);
  assert.notEqual(first.operationKey, second.operationKey); // response shapes differ → identities differ
  assert.deepEqual(first.responseKeys, ["first"]);
  assert.deepEqual(second.responseKeys, ["second"]);
});

test("describe: a sensitive NESTED default clause is removed whole — overlapping inner edits must not corrupt the document", () => {
  const op = describeGraphqlOperation(
    JSON.stringify({ query: 'mutation M($token: Input! = { password: "synthetic-long-secret", id: 1 }) { use(input: $token) { id } }' }),
  );
  assert.ok(op);
  assert.ok(!op.document.includes("synthetic-long-secret"), "the secret inside the nested default must not persist");
  assert.ok(!/password/.test(op.document), `the whole default clause goes, not just the literal (got ${op.document})`);
  assert.ok(op.document.includes("$token: Input!"), "the variable declaration survives intact");
  assert.match(op.document, /use\(input:\s*\$token\)/, "the body stays executable");
  // The sanitized document reparses to the SAME identity (structure canonicalization ignores the dropped default).
  const re = describeGraphqlOperation(JSON.stringify({ query: op.document, operationName: "M" }));
  assert.equal(re!.operationKey, op.operationKey);
});

test("inventory merge: a stored op missing responseKeys is backfilled from a fresh observation — never unioned", () => {
  const inv = new InventoryBuilder();
  const base = "https://app.test/";
  const mkApi = (vars: Record<string, unknown>): ApiCall =>
    apiFor(JSON.stringify({ query: "query { viewer: user(id: $id) { id } }", variables: vars }));
  const noKeys = mkApi({ id: "1" });
  delete (noKeys.graphql as unknown as Record<string, unknown>).responseKeys; // an older stored record lacks the metadata
  inv.ingestBuilt(apiCallToBuiltScreen(noKeys, base)!);
  const s = inv.ingestBuilt(apiCallToBuiltScreen(mkApi({ id: "2" }), base)!).screen; // same doc re-observed
  const apis = s.apis.filter((a) => a.graphql);
  assert.equal(apis.length, 1);
  assert.deepEqual(apis[0]!.graphql!.responseKeys, ["viewer"]); // filled, matching the persisted document
});

test("selection: multi-op document without operationName is NOT attributed to the first op", () => {
  const op = describeGraphqlOperation(JSON.stringify({
    query: "query A { a } query B { b }",
    // no operationName — the executed op is undecidable
  }));
  assert.equal(op, null);
});

test("selection: operationName that matches NO operation in the document → null (never silently first)", () => {
  const op = describeGraphqlOperation(JSON.stringify({
    query: "query A { a } query B { b }",
    operationName: "Zzz",
  }));
  assert.equal(op, null);
});

test("selection: operationName selects the right op out of a multi-op document", () => {
  const op = describeGraphqlOperation(JSON.stringify({
    query: "query A { a } query B { b }",
    operationName: "B",
  }));
  assert.ok(op);
  assert.equal(op.operationName, "B");
  assert.deepEqual(op.rootFields, ["b"]);
  // …and a document whose only op is named still resolves when operationName is omitted.
  const solo = describeGraphqlOperation(JSON.stringify({ query: "query Solo { x }" }));
  assert.equal(solo!.operationName, "Solo");
});

test("responseKeys: aliases are the keys present in data; fragment spreads expand into root fields+keys", () => {
  const op = describeGraphqlOperation(JSON.stringify({
    query: "query Q { current: user(id: 1) { id } ...F } fragment F on Query { cart { id } }",
    operationName: "Q",
  }));
  assert.ok(op);
  assert.deepEqual(op.responseKeys, ["current", "cart"]); // data.current + data.cart
  assert.deepEqual(op.rootFields, ["user", "cart"]); // real names, alias resolved, spread expanded
});

test("inferApiCall: POST JSON GraphQL body → api.graphql set; apiKey includes operationKey", () => {
  const a = apiFor(JSON.stringify({ query: "query GetOrder($id: ID!) { order(id: $id) { id } }", operationName: "GetOrder", variables: { id: 1 } }));
  const b = apiFor(JSON.stringify({ query: "query GetCart { cart { items { sku } } }", operationName: "GetCart", variables: {} }));
  assert.ok(a.graphql && b.graphql);
  assert.match(a.graphql.operationKey, /^name:GetOrder:[a-z0-9]+$/); // name + structure hash (not the name alone)
  assert.equal(a.graphql.operationType, "query");
  assert.equal(a.graphql.variablesShape.id, "number");
  assert.notEqual(apiKey(a), apiKey(b)); // same endpoint, different operations → distinct keys
  assert.match(apiKey(a), /POST \/graphql name:GetOrder:[a-z0-9]+$/);
  // Non-GraphQL POST JSON is untouched.
  const rest = apiFor(JSON.stringify({ item: 1, qty: 2 }));
  assert.equal(rest.graphql, undefined);
  assert.equal(apiKey(rest), "POST /graphql");
  // GET is never GraphQL-body parsed.
  const get = inferApiCall(ex({ method: "GET", requestBody: JSON.stringify({ query: "{x}" }) }));
  assert.equal(get.graphql, undefined);
});

test("inventory merge: two ops on one endpoint both kept; same op re-observed merges (vars unioned, example refreshed)", () => {
  const inv = new InventoryBuilder();
  const mkApi = (doc: string, vars: Record<string, unknown>, name?: string): ApiCall =>
    apiFor(JSON.stringify({ query: doc, ...(name ? { operationName: name } : {}), variables: vars }));
  const base = "https://app.test/";
  const s1 = inv.ingestBuilt(apiCallToBuiltScreen(mkApi("query A($id: ID!){a(id:$id){id}}", { id: "1" }, "A"), base)!).screen;
  inv.ingestBuilt(apiCallToBuiltScreen(mkApi("query B($id: ID!){b(id:$id){id}}", { id: "9" }, "B"), base)!);
  // Same document re-observed with DIFFERENT variable VALUES (and a wider shape) → merges into A, example refreshed.
  const s2 = inv.ingestBuilt(apiCallToBuiltScreen(mkApi("query A($id: ID!){a(id:$id){id}}", { id: "5" }, "A"), base)!).screen;
  assert.equal(s2.screenId, s1.screenId);
  const apis = s2.apis.filter((a) => a.graphql);
  assert.equal(apis.length, 2); // A and B — not collapsed into one POST /graphql, and no duplicate A
  const a = apis.find((x) => x.graphql!.operationName === "A")!;
  assert.deepEqual(Object.keys(a.graphql!.variablesShape).sort(), ["id"]); // unchanged shape key set
  assert.equal(a.graphql!.variablesExample!.id, "5"); // refreshed example (newest observed)
  // …but a structurally DIFFERENT document under the same name is a DIFFERENT operation (not merged).
  const s3 = inv.ingestBuilt(apiCallToBuiltScreen(mkApi("query A($id: ID!, $flag: Boolean){a(id:$id){id}}", { id: "5", flag: true }, "A"), base)!).screen;
  assert.equal(s3.apis.filter((x) => x.graphql).length, 3);
  // resSchema filled on merge when the first observation lacked it
  const withSchema = apiFor(JSON.stringify({ query: "query B($id: ID!){b(id:$id){id}}", operationName: "B", variables: { id: "9" } }));
  withSchema.resSchema = { type: "object", fields: { data: { type: "object", fields: {} } } };
  inv.ingestBuilt(apiCallToBuiltScreen(withSchema, base)!);
  const b = s2.apis.find((x) => x.graphql!.operationName === "B")!;
  assert.ok(b.resSchema);
});
