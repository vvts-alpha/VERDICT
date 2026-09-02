import { test } from "node:test";
import assert from "node:assert/strict";
import { nosqlBypassConfirms, nosqlErrorSignature, nosqlQueryUrl, NOSQL_OP_OBJECTS } from "./nosql.js";

test("nosqlBypassConfirms: control fails + operator positives succeed (marker) → confirmed", () => {
  const control = { status: 401, body: "Invalid email or password" };
  const pos = [
    { status: 200, body: '{"authentication":{"token":"eyJ..."}}' },
    { status: 200, body: '{"authentication":{"token":"eyJ..."}}' },
  ];
  assert.equal(nosqlBypassConfirms(control, pos, "authentication"), true);
});

test("nosqlBypassConfirms: control ALSO succeeds → not a bypass (endpoint accepts anything)", () => {
  const ok = { status: 200, body: '{"authentication":{"token":"x"}}' };
  assert.equal(nosqlBypassConfirms(ok, [ok, ok], "authentication"), false);
});

test("nosqlBypassConfirms: status-flip oracle when no marker, and <2 positives is never confirmed", () => {
  assert.equal(nosqlBypassConfirms({ status: 401, body: "no" }, [{ status: 200, body: "ok" }, { status: 200, body: "ok" }]), true);
  assert.equal(nosqlBypassConfirms({ status: 401, body: "no" }, [{ status: 200, body: "ok" }]), false);
});

test("nosqlErrorSignature detects Mongo/Mongoose errors, ignores benign bodies", () => {
  assert.ok(nosqlErrorSignature('{"error":"CastError: Cast to ObjectId failed"}'));
  assert.ok(nosqlErrorSignature("MongoServerError: unknown operator: $foo"));
  assert.equal(nosqlErrorSignature('{"products":[{"id":1}]}'), undefined);
});

test("nosqlQueryUrl builds field[$op]= and drops the plain key", () => {
  assert.equal(nosqlQueryUrl("https://t/api?user=admin&x=1", "user", "$ne", ""), "https://t/api?x=1&user%5B%24ne%5D=");
  assert.ok(NOSQL_OP_OBJECTS.some((o) => o.json === '{"$ne":null}'));
});
