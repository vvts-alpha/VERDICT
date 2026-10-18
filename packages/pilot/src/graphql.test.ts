// GraphQL response classification + baseline gating + typed JSON-path writes. The probes depend on these to tell
// "resolver ran and returned data" apart from "rejected / denied / empty / not even GraphQL" — an HTTP 200 means
// nothing on a GraphQL endpoint, and an unestablished baseline must come out UNVERIFIED, never clean.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseGraphqlResponse, baselineVerdict, fieldDiff, graphqlErrorIsAuthz, graphqlIdLeafPaths, graphqlRequestBody, mutationLooksDestructive, redactedVariablePaths } from "./graphql.js";
import { readJsonPath, writeJsonPath, coerceJsonLike } from "./inject.js";
import { graphqlIdParamLocs } from "./tools.js";
import type { ApiCall } from "@veritas/core";

test("classifier: ok / errors / partial / empty / not-graphql are distinct", () => {
  assert.equal(parseGraphqlResponse(200, '{"data":{"order":{"id":1}}}').kind, "ok");
  const errs = parseGraphqlResponse(200, '{"errors":[{"message":"Cannot query field \\"nope\\" on type \\"Query\\"."}]}');
  assert.equal(errs.kind, "errors");
  assert.equal(errs.requestRejected, true); // validation error — the request never executed
  const partial = parseGraphqlResponse(200, '{"data":{"user":{"id":1,"salary":null}},"errors":[{"message":"Forbidden","extensions":{"code":"FORBIDDEN"},"path":["user","salary"]}]}');
  assert.equal(partial.kind, "partial"); // data AND errors — a real, meaningful state
  assert.equal(partial.authzDenied, true);
  assert.equal(parseGraphqlResponse(200, '{"data":{"order":null}}').kind, "empty"); // object absent
  assert.equal(parseGraphqlResponse(200, '{"data":null}').kind, "empty");
  assert.equal(parseGraphqlResponse(200, "not json at all").kind, "not-graphql");
  assert.equal(parseGraphqlResponse(200, "<html>login</html>").kind, "not-graphql");
  assert.equal(parseGraphqlResponse(200, '{"ok":true}').kind, "not-graphql"); // JSON but no data/errors envelope
  // HTTP-level denial is honored even with a terse/non-JSON body.
  assert.equal(parseGraphqlResponse(403, "forbidden").authzDenied, true);
  assert.equal(parseGraphqlResponse(401, '{"errors":[{"message":"nope"}]}').authzDenied, true);
});

test("baselineVerdict: established only when real data returned; failure is explicit, not clean", () => {
  const ok = baselineVerdict(parseGraphqlResponse(200, '{"data":{"order":{"id":1}}}'), ["order"]);
  assert.equal(ok.established, true);
  const partial = baselineVerdict(parseGraphqlResponse(200, '{"data":{"order":{"id":1}},"errors":[{"message":"f","path":["order","x"]}]}'), ["order"]);
  assert.equal(partial.established === true && partial.partial, true);
  for (const [status, body] of [
    [200, '{"errors":[{"message":"Cannot query field \\"x\\" on type \\"Query\\"."}]}'] as const,
    [200, '{"errors":[{"message":"not authorized","extensions":{"code":"FORBIDDEN"}}],"data":null}'] as const,
    [200, '{"data":{"order":null}}'] as const,
    [200, "garbage"] as const,
  ]) {
    const b = baselineVerdict(parseGraphqlResponse(status, body), ["order"]);
    assert.equal(b.established, false, body);
    assert.ok("reason" in b && b.reason.length > 0); // every failure carries an explicit reason
  }
  // All root fields missing → not established (wrong variables / stub endpoint).
  const stub = baselineVerdict(parseGraphqlResponse(200, '{"data":{"other":1}}'), ["order"]);
  assert.equal(stub.established, false);
});

test("fieldDiff: denied-for-other / extra-for-other / per-field errors", () => {
  const admin = parseGraphqlResponse(200, '{"data":{"user":{"id":1,"email":"a@b.c","salary":99}}}');
  const user = parseGraphqlResponse(200, '{"data":{"user":{"id":1,"email":"a@b.c","salary":null}},"errors":[{"message":"Forbidden","path":["salary"]}]}');
  const d = fieldDiff(admin, user);
  assert.deepEqual(d.deniedForOther, []); // "user" still resolved — the diff lives INSIDE the object (field-level, in errors)
  assert.deepEqual(d.errorFieldsForOther, ["salary"]);
  const deniedOp = parseGraphqlResponse(200, '{"data":null,"errors":[{"message":"forbidden","path":["user"]}]}');
  const d2 = fieldDiff(admin, deniedOp);
  assert.deepEqual(d2.deniedForOther, ["user"]); // whole root field gone → operation-level denial
});

test("graphqlErrorIsAuthz: explicit non-authz CODES override auth-looking message wording", () => {
  // A DB error that merely says "Access denied" is not enforcement.
  const dbErr = { message: "Access denied for user 'app'@'db'", code: "INTERNAL_SERVER_ERROR" };
  assert.equal(graphqlErrorIsAuthz(dbErr), false);
  assert.equal(
    parseGraphqlResponse(200, '{"errors":[{"message":"Access denied for user \'app\'@\'db\'","extensions":{"code":"INTERNAL_SERVER_ERROR"}}]}').authzDenied,
    false,
  );
  // Uncoded authz wording and coded authz both still count.
  assert.equal(graphqlErrorIsAuthz({ message: "Forbidden" }), true);
  assert.equal(graphqlErrorIsAuthz({ message: "x", code: "UNAUTHENTICATED" }), true);
  assert.equal(graphqlErrorIsAuthz({ message: "denied", code: "BAD_USER_INPUT" }), false);
});

test("fieldDiff: authz-denied fields separate from resolver/DB-failed fields", () => {
  const admin = parseGraphqlResponse(200, '{"data":{"user":{"id":1,"salary":99,"note":"x"}}}');
  const user = parseGraphqlResponse(200, JSON.stringify({
    data: { user: { id: 1, salary: null, note: null } },
    errors: [
      { message: "Forbidden", path: ["user", "salary"], extensions: { code: "FORBIDDEN" } },
      { message: "db timeout", path: ["user", "note"], extensions: { code: "INTERNAL_SERVER_ERROR" } },
    ],
  }));
  const d = fieldDiff(admin, user);
  assert.deepEqual(d.errorFieldsForOther, ["user.salary"]); // genuine authz denial
  assert.deepEqual(d.failedFieldsForOther, ["user.note"]); // resolver failure is NOT protection
});

test("fieldDiff: a root field absent because of a NON-authz error is FAILED, never 'denied'", () => {
  // Repro: baseline resolves {viewer, order}; the other role gets order:null + INTERNAL_SERVER_ERROR
  // whose message merely *says* "Access denied" — the absence must NOT count as restriction working.
  const baseline = parseGraphqlResponse(200, '{"data":{"viewer":{"id":"u1"},"order":{"id":"o1"}}}');
  const other = parseGraphqlResponse(
    200,
    JSON.stringify({
      data: { viewer: { id: "u1" }, order: null },
      errors: [{ message: "Access denied for user 'app'@'db'", path: ["order"], extensions: { code: "INTERNAL_SERVER_ERROR" } }],
    }),
  );
  const d = fieldDiff(baseline, other);
  assert.deepEqual(d.deniedForOther, []);
  assert.deepEqual(d.failedFieldsForOther, ["order"]);
  assert.deepEqual(d.errorFieldsForOther, []);
  // …while a genuine FORBIDDEN root still lands in deniedForOther via errorFields.
  const forbidden = parseGraphqlResponse(
    200,
    '{"data":{"viewer":{"id":"u1"},"order":null},"errors":[{"message":"Forbidden","path":["order"],"extensions":{"code":"FORBIDDEN"}}]}',
  );
  const d2 = fieldDiff(baseline, forbidden);
  assert.deepEqual(d2.errorFieldsForOther, ["order"]);
});

test("stableStateProjection removed — verify attribution reads a caller-named verifyPath, not a whole-body projection", () => {
  // The volatile-noise case is handled by reading ONLY verifyPath out of each verify response (tools.ts stateAt),
  // so a whole-response projection helper is unnecessary. This test guards the semantics via readJsonPath:
  const pre = { data: { note: { text: "hi", updatedAt: 1 }, reqId: "r1" } };
  const post = { data: { note: { text: "hi", updatedAt: 999 }, reqId: "r2" } };
  assert.deepEqual(readJsonPath(pre, "data.note.text").value, readJsonPath(post, "data.note.text").value);
});

test("mutationLooksDestructive: denylist vocabulary blocked, benign op allowed", () => {
  assert.equal(mutationLooksDestructive({ operationName: "DeleteUser", rootFields: ["deleteUser"] }), "DeleteUser");
  assert.equal(mutationLooksDestructive({ operationName: null, rootFields: ["transferFunds"] }), "transferFunds");
  assert.equal(mutationLooksDestructive({ operationName: "UpdateNote", rootFields: ["updateNote"] }), null);
});

test("redactedVariablePaths: persisted <redacted> placeholders found recursively", () => {
  assert.deepEqual(
    redactedVariablePaths({ id: "1", input: { secret: "<redacted>" }, arr: ["<redacted>"] }),
    ["variables.input.secret", "variables.arr.0"],
  );
  assert.deepEqual(redactedVariablePaths({ id: "1" }), []);
});

test("json paths: typed replace of ONE nested leaf; siblings and kinds preserved", () => {
  const body = { query: "query($i:F){o(i:$i){id}}", variables: { input: { ownerId: 7, tag: "x" }, ids: [1, 2] } };
  const leaf = readJsonPath(body, "variables.input.ownerId");
  assert.equal(leaf.found && leaf.value, 7);
  // typed: numeric leaf coerces "9" → 9 (a string "9" would be a type error against Int!, not evidence)
  assert.ok(writeJsonPath(body, "variables.input.ownerId", coerceJsonLike(leaf.value, "9")));
  assert.equal((body.variables.input as { ownerId: unknown }).ownerId, 9);
  assert.equal((body.variables.input as { tag: unknown }).tag, "x"); // unrelated leaf untouched
  assert.equal(body.query, "query($i:F){o(i:$i){id}}");
  // arrays + RFC6901 pointers + bare keys all resolve
  assert.equal(readJsonPath(body, "variables.ids.1").value, 2);
  assert.ok(writeJsonPath(body, "/variables/ids/0", 42));
  assert.equal(body.variables.ids[0], 42);
  // replace-only refuses missing paths; create:true adds nested leaves (mass-assignment)
  assert.equal(writeJsonPath(body, "variables.input.role", "admin"), false);
  assert.ok(writeJsonPath(body, "variables.input.extra.role", "admin", { create: true }));
  assert.equal(readJsonPath(body, "variables.input.extra.role").value, "admin");
  // prototype-chain paths are refused
  assert.equal(writeJsonPath(body, "variables.__proto__.x", 1, { create: true }), false);
  assert.equal(coerceJsonLike(true, "false"), false);
  assert.equal(coerceJsonLike("s", "5"), "5"); // string leaf stays a string
});

test("graphqlIdLeafPaths: finds id-bearing nested leaves only", () => {
  const leaves = graphqlIdLeafPaths({ input: { ownerId: "u2", qty: 3 }, id: "42", note: "hi", items: [{ sku: "a", orderId: 9 }] });
  const ptrs = leaves.map((l) => l.pointer).sort();
  assert.ok(ptrs.includes("variables.input.ownerId"));
  assert.ok(ptrs.includes("variables.id"));
  assert.ok(ptrs.includes("variables.items.0.orderId")); // through arrays
  assert.ok(!ptrs.includes("variables.input.qty") && !ptrs.includes("variables.note"));
});

test("graphqlIdParamLocs: one sweep entry per id leaf, request template carries the op, mutations flagged write", () => {
  const apis: ApiCall[] = [
    {
      method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
      graphql: {
        operationType: "query", operationName: "GetOrder", operationKey: "name:GetOrder", rootFields: ["order"],
        variablesShape: { id: "string" }, document: "query GetOrder($id: ID!){order(id:$id){id}}", variablesExample: { id: "1" },
      },
    },
    {
      method: "POST", urlTemplate: "/graphql", auth: "cookie", reqSchema: null, resSchema: null,
      graphql: {
        operationType: "mutation", operationName: "Move", operationKey: "name:Move", rootFields: ["move"],
        variablesShape: { input: "object" }, document: "mutation Move($input:I!){move(input:$input){ok}}", variablesExample: { input: { ownerId: "u1" } },
      },
    },
  ];
  const locs = graphqlIdParamLocs(apis, "https://app.test/");
  assert.equal(locs.length, 2);
  const ptrOf = (l: (typeof locs)[number]): string => (l.loc.via === "json-field" ? l.loc.pointer : "");
  const read = locs.find((l) => ptrOf(l) === "variables.id")!;
  assert.equal(read.write, false);
  assert.equal(read.req.url, "https://app.test/graphql");
  const sent = JSON.parse(read.req.body) as { query: string; operationName: string; variables: { id: string } };
  assert.equal(sent.operationName, "GetOrder");
  assert.equal(sent.variables.id, "1");
  const write = locs.find((l) => ptrOf(l) === "variables.input.ownerId")!;
  assert.equal(write.write, true); // mutation → idor-write classification
});

test("graphqlRequestBody: verbatim document + typed variables", () => {
  const b = JSON.parse(graphqlRequestBody({ document: "{x}", operationName: null }, { n: 2, s: "y" })) as Record<string, unknown>;
  assert.equal(b.query, "{x}");
  assert.equal(b.operationName, undefined); // null name omitted
  assert.equal((b.variables as { n: unknown }).n, 2);
});
