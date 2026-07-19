// B: knownObjectIds mines object ids from ALREADY-captured response bodies (list endpoints, JSON id/email fields) — the
// richest source of another user's object id for cross-user IDOR, which the inventory-only scan missed.
// A: user-enumeration is marker-based so a same-LENGTH content flip (Meraki auth-routing oracle) can be confirmed.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { harvestBodyIds, MARKER_BASED_CATEGORIES } from "./tools.js";

const rec = (body: string): { response: { body: string } } => ({ response: { body } });

test("harvestBodyIds mines id / uuid / email tokens from captured response bodies", () => {
  const out = new Set<string>();
  harvestBodyIds(
    [
      rec('{"users":[{"userId":1023,"email":"alice@x.io"},{"userId":1024,"email":"bob@x.io"}]}'),
      rec('{"id":"550e8400-e29b-41d4-a716-446655440000","owner_id":"77"}'),
    ],
    out,
  );
  assert.ok(out.has("userId=1023"), "list-endpoint userId #1");
  assert.ok(out.has("userId=1024"), "list-endpoint userId #2 (another user's id)");
  assert.ok(out.has("email=alice@x.io"), "email as an identifier for BOLA");
  assert.ok(out.has("owner_id=77"));
  assert.ok([...out].some((v) => v.includes("550e8400-e29b-41d4-a716-446655440000")), "uuid harvested");
});

test("harvestBodyIds is bounded (skips huge bodies gracefully, caps total)", () => {
  const out = new Set<string>();
  const many = `{"rows":[${Array.from({ length: 200 }, (_, i) => `{"id":${i}}`).join(",")}]}`;
  harvestBodyIds([rec(many)], out);
  assert.ok(out.size <= 30, "capped at CAP_TOTAL");
});

test("MARKER_BASED_CATEGORIES includes user-enumeration — a same-length content flip confirms via the cited marker, not length", () => {
  assert.ok(MARKER_BASED_CATEGORIES.has("user-enumeration"));
});
