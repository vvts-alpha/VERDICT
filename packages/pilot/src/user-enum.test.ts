import { strict as assert } from "node:assert";
import { test } from "node:test";
import { userEnumMarker, placeUserIdentity } from "./user-enum.js";

test("userEnumMarker: valid-account phrase (wrong password) vs user-not-found", () => {
  const invalid = { status: 401, body: '{"error":"user not found"}' };
  const valid = { status: 401, body: '{"error":"invalid password"}' };
  const hit = userEnumMarker(invalid, valid, valid, "alice", "nosuch");
  assert.ok(hit);
  assert.match(hit!.marker, /invalid password/i);
});

test("userEnumMarker: status flip (200 vs 404) uses status: marker", () => {
  const hit = userEnumMarker(
    { status: 404, body: "nope" },
    { status: 200, body: "ok" },
    { status: 200, body: "ok" },
    "alice",
    "nosuch",
  );
  assert.deepEqual(hit, { marker: "status:200", reason: "HTTP 200 for a valid user vs 404 for a non-existent user" });
});

test("userEnumMarker: username echo alone is NOT enumeration", () => {
  const hit = userEnumMarker(
    { status: 200, body: 'hello nosuch' },
    { status: 200, body: "hello alice" },
    { status: 200, body: "hello alice" },
    "alice",
    "nosuch",
  );
  assert.equal(hit, null);
});

test("userEnumMarker: identical generic errors are not a hit", () => {
  const body = '{"error":"invalid credentials"}';
  assert.equal(userEnumMarker({ status: 401, body }, { status: 401, body }, { status: 401, body }, "alice", "nosuch"), null);
});

test("userEnumMarker: JSON exists:true only for valid user", () => {
  const hit = userEnumMarker(
    { status: 200, body: '{"exists":false}' },
    { status: 200, body: '{"exists":true}' },
    { status: 200, body: '{"exists":true}' },
    "alice",
    "nobody",
  );
  assert.ok(hit);
  assert.ok(hit!.marker.includes("true") || hit!.marker.toLowerCase().includes("exists"));
});

test("userEnumMarker: marker must be stable across both valid replays", () => {
  const hit = userEnumMarker(
    { status: 200, body: '{"error":"user not found"}' },
    { status: 200, body: '{"error":"invalid password","csrf":"aaa"}' },
    { status: 200, body: '{"error":"invalid password","csrf":"bbb"}' },
    "alice",
    "nosuch",
  );
  assert.ok(hit);
  assert.match(hit!.marker, /invalid password/i);
  assert.ok(!/aaa|bbb/.test(hit!.marker));
});

test("placeUserIdentity: {{USER}} in body and query param", () => {
  const b = placeUserIdentity("https://app.test/login", "user={{USER}}&password=x", undefined, "alice");
  assert.equal(b?.body, "user=alice&password=x");
  const q = placeUserIdentity("https://app.test/login", null, "email", "alice");
  assert.ok(q?.url.includes("email=alice"));
  assert.equal(placeUserIdentity("https://app.test/login", null, undefined, "alice"), null);
});
