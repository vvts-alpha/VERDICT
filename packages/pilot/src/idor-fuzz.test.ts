// ③ IDOR id-enumeration (fuzzing). When the model has NO known victim id (cross-tenant / needs another user's object),
// probe_idor walks neighbouring ids instead of dropping straight to verdict:suspected. These lock the id-walking heuristic:
// numeric & prefix+digits ids enumerate; opaque uuid/hash ids do NOT (→ the caller falls back to suspected).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { idNeighbors, nonexistentIdLike, idBearingParamLocs, setFormField, replacePathSeg } from "./tools.js";
import type { Param } from "@veritas/core";

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

// ── probe_idor SWEEP: test EVERY id-bearing field on a screen (each in its own location), not just the one param the
//    model guessed. These lock the deterministic field-picking + placement so a wrong-param guess can't dump to suspected.

test("idBearingParamLocs: picks only id-bearing params, each mapped to its OWN location; dedups (loc,name)", () => {
  const params: Param[] = [
    { name: "event_id", in: "query", example: "785687", guessedType: "object_ref" },
    { name: "owner_id", in: "body", example: "826533", guessedType: "id" },
    { name: "title", in: "body", example: "My Event", guessedType: "free_text" }, // NOT id → excluded
    { name: "id", in: "path", example: "42", guessedType: "object_ref" },
    { name: "ref", in: "query", example: "550e8400-e29b-41d4-a716-446655440000", guessedType: "unknown" }, // id name → rule re-derives
    { name: "event_id", in: "query", example: "785687", guessedType: "object_ref" }, // dup (query,event_id) → dropped
    { name: "X-User-Id", in: "header", example: "826533", guessedType: "object_ref" },
  ];
  const locs = idBearingParamLocs(params);
  assert.deepEqual(
    locs.map((l) => `${l.name}:${l.loc.via}`),
    ["event_id:query", "owner_id:body-field", "id:path", "ref:query", "X-User-Id:header"],
  );
  assert.ok(!locs.some((l) => l.name === "title"), "a free_text field is not swept");
  // a path param carries its example (to locate the segment to swap); field params carry the name.
  assert.deepEqual(locs.find((l) => l.name === "id")?.loc, { via: "path", example: "42" });
});

test("idBearingParamLocs: a param with no example is skipped (nothing to seed / walk)", () => {
  assert.equal(idBearingParamLocs([{ name: "user_id", in: "query", example: "", guessedType: "object_ref" }]).length, 0);
});

test("setFormField: appends when absent, replaces when present, url-encodes", () => {
  assert.equal(setFormField(null, "id", "5"), "id=5");
  assert.equal(setFormField("a=1&b=2", "id", "5"), "a=1&b=2&id=5");
  assert.equal(setFormField("a=1&id=9&b=2", "id", "5"), "a=1&id=5&b=2"); // replace in place, order preserved
  assert.equal(setFormField("", "user id", "a b"), "user%20id=a%20b");
});

test("replacePathSeg: swaps the LAST matching segment, preserves the rest; null when the segment is absent", () => {
  assert.equal(replacePathSeg("https://x.test/api/event/785687", "785687", "785688"), "https://x.test/api/event/785688");
  assert.equal(replacePathSeg("https://x.test/785687/edit", "785687", "1"), "https://x.test/1/edit");
  assert.equal(replacePathSeg("https://x.test/api/event/785687?x=1", "999", "1"), null);
});
