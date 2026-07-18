// ③ IDOR id-enumeration (fuzzing). When the model has NO known victim id (cross-tenant / needs another user's object),
// probe_idor walks neighbouring ids instead of dropping straight to verdict:suspected. These lock the id-walking heuristic:
// numeric & prefix+digits ids enumerate; opaque uuid/hash ids do NOT (→ the caller falls back to suspected).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { idNeighbors, nonexistentIdLike } from "./tools.js";

test("idNeighbors: a numeric id walks ±1/±2/±3 plus low/seed ids, excludes self, capped at 6", () => {
  const n = idNeighbors("1024");
  assert.ok(n.includes("1025"), "n+1");
  assert.ok(n.includes("1023"), "n-1");
  assert.ok(!n.includes("1024"), "excludes self");
  assert.ok(n.length <= 6, "capped");
});

test("idNeighbors: a low numeric id never goes negative and pulls in seed ids", () => {
  const n = idNeighbors("2");
  assert.ok(!n.some((x) => Number(x) < 0), "no negative ids");
  assert.ok(n.includes("1"), "neighbour/seed 1");
  assert.ok(n.includes("3"), "neighbour 3");
  assert.ok(!n.includes("2"), "excludes self");
});

test("idNeighbors: a prefix+digits id walks width-preserving (user-0007 → user-0008/user-0006)", () => {
  const n = idNeighbors("user-0007");
  assert.ok(n.includes("user-0008"), "n+1 zero-padded");
  assert.ok(n.includes("user-0006"), "n-1 zero-padded");
  assert.ok(!n.includes("user-0007"), "excludes self");
});

test("idNeighbors: an OPAQUE id (uuid / long hex) can't be enumerated → [] (caller falls back to suspected)", () => {
  assert.deepEqual(idNeighbors("550e8400-e29b-41d4-a716-446655440000"), []);
  assert.deepEqual(idNeighbors("deadbeefdeadbeef01"), []); // 16+ hex
  assert.deepEqual(idNeighbors("abcxyz"), []); // no trailing digits at all
});

test("nonexistentIdLike: a shape-matching non-existent control (so a catch-all 200 is detectable)", () => {
  assert.equal(nonexistentIdLike("42"), "2147483646"); // numeric → large absent value
  assert.equal(nonexistentIdLike("user-0007"), "user-9999"); // prefix + all-nines, width preserved
  assert.equal(nonexistentIdLike("550e8400-e29b-41d4-a716-446655440000"), "00000000-0000-0000-0000-000000000000");
});
