import { strict as assert } from "node:assert";
import { test } from "node:test";
import { disclosureHit } from "./disclosure.js";

test("disclosureHit: AWS key is secret-exposure (not ambient in control)", () => {
  // impact.ts: /\bAKIA[0-9A-Z]{16}\b/ ; PLACEHOLDERS include AKIAIOSFODNN7EXAMPLE
  const real = "AKIA" + "ABCDEFGHIJKLMNOP"; // 4+16
  const hit = disclosureHit(`creds ${real}`, "no secrets here");
  assert.equal(hit?.category, "secret-exposure");
  assert.ok(hit?.marker.includes("AKIA"));
});

test("disclosureHit: documentation placeholder AWS key is ignored", () => {
  assert.equal(disclosureHit("AKIAIOSFODNN7EXAMPLE in docs", ""), null);
});

test("disclosureHit: directory listing is info-disclosure", () => {
  const hit = disclosureHit("<html><title>Index of /backup</title>", "404 not found");
  assert.deepEqual(hit?.category, "info-disclosure");
  assert.equal(hit?.marker, "Index of");
});

test("disclosureHit: listing also in the control is ambient (not a hit)", () => {
  const listing = "<title>Index of /</title>";
  assert.equal(disclosureHit(listing, listing), null);
});

test("disclosureHit: Python traceback is info-disclosure", () => {
  const hit = disclosureHit("Traceback (most recent call last):\n  File \"app.py\"", "404");
  assert.equal(hit?.category, "info-disclosure");
  assert.equal(hit?.marker, "Traceback (most recent call last)");
});
