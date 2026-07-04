// The pure part of probe_scenario: extract a value from the earlier response (extractValue) and inject it into the later one (substVars).
// Regression test for the substrate that makes a multi-step workflow work (create a basket → inject its id into checkout).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { substVars, extractValue } from "./tools.js";

test("substVars replaces {{var}} placeholders (and blanks unknowns)", () => {
  assert.equal(substVars("/rest/basket/{{id}}/checkout", { id: "42" }), "/rest/basket/42/checkout");
  assert.equal(substVars('{"BasketId":{{bid}},"coupon":"{{c}}"}', { bid: "6", c: "X" }), '{"BasketId":6,"coupon":"X"}');
  assert.equal(substVars("/x/{{missing}}/y", {}), "/x//y"); // undefined → empty
  assert.equal(substVars("{{ spaced }}", { spaced: "ok" }), "ok"); // whitespace tolerated
});

test("extractValue reads a JSON path (object + array index)", () => {
  const body = JSON.stringify({ data: { id: 6, items: [{ id: 11 }, { id: 12 }] }, status: "ok" });
  assert.equal(extractValue(body, "data.id"), "6");
  assert.equal(extractValue(body, "data.items.1.id"), "12");
  assert.equal(extractValue(body, "status"), "ok");
});

test("extractValue falls back to a regex when JSON path misses or body is not JSON", () => {
  assert.equal(extractValue("set order_id=A39 done", "order_id=([A-Z0-9]+)"), "A39"); // first capture group
  assert.equal(extractValue('{"token":"abc.def.ghi"}', "missing.path"), null); // JSON but path missing → regex also misses → null
  assert.equal(extractValue("plain text 777", "\\d+"), "777"); // no capture group → whole match
});

test("extractValue returns null for absent values / invalid regex", () => {
  assert.equal(extractValue("{}", "a.b.c"), null);
  assert.equal(extractValue("nope", "([unclosed"), null);
});
