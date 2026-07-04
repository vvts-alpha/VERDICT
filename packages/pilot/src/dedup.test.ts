// Regression test for finding dedup. Verifies that the 21 raw findings from a real run (user-reported)
// collapse under the (class × endpoint × param) key down to only the distinct ones.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CATEGORIES, coarseClass, dedupKey, normEndpoint } from "./tools.js";

const base = "http://localhost:3000";

test("coarseClass folds wording variants of the same class", () => {
  for (const v of [
    "Reflected XSS",
    "Reflected XSS (CWE-79)",
    "Reflected Cross-Site Scripting (XSS)",
    "Reflected Cross-Site Scripting (CWE-79)",
  ]) {
    assert.equal(coarseClass(v), "xss-reflected", v);
  }
  assert.equal(coarseClass("Stored XSS (CWE-79)"), "xss-stored");
  assert.equal(coarseClass("Broken Access Control (IDOR)"), "idor");
  assert.equal(coarseClass("IDOR / BOLA (Broken Object Level Authorization)"), "idor");
  assert.equal(coarseClass("IDOR / Broken Object Level Authorization (write)"), "idor-write");
  assert.equal(coarseClass("Path Traversal / Arbitrary File Read (CWE-22)"), "path-traversal");
});

test("normEndpoint folds concrete ids and {id} templates together", () => {
  assert.equal(normEndpoint("/orders/o10", base), normEndpoint("/orders/{id}", base));
  assert.equal(normEndpoint(`${base}/orders/o10?x=1`, base), "/orders/{id}");
  assert.notEqual(normEndpoint("/orders/{id}", base), normEndpoint("/orders/{id}/receipt", base));
});

test("the 21 real raw findings dedupe to 8 distinct holes", () => {
  // [vulnClass, endpoint, param]  — real user-reported data, shaped as Claude would likely pass it
  const raw: Array<[string, string, string | undefined]> = [
    // ── Reflected XSS on /search?q= (13 wording variants) → 1 ──
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS (CWE-79)", "/search", "q"],
    ["Reflected Cross-Site Scripting (XSS)", "/search", "q"],
    ["Reflected XSS (CWE-79)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected Cross-Site Scripting (CWE-79)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected Cross-Site Scripting (XSS)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    // ── the distinct ones ──
    ["Path Traversal / Arbitrary File Read (CWE-22)", "/download", "file"],
    ["Broken Access Control (IDOR)", "/addresses/{id}", undefined], // addresses read
    ["IDOR / BOLA", "/orders/o10", undefined], // orders read (3 entries → 1)
    ["IDOR / BOLA (Broken Object Level Authorization)", "/orders/o11", undefined],
    ["Broken Access Control (IDOR/BOLA)", "/orders/{id}", undefined],
    ["IDOR / Broken Object Level Authorization (write)", "/addresses/12/edit", undefined], // write-IDOR
    ["IDOR / BOLA", "/orders/o10/receipt", undefined], // receipt
    ["Stored XSS (CWE-79)", "/support/new", "body"],
    ["Stored XSS (CWE-79)", "/support/tickets/42", "body"], // reply
  ];

  const keys = new Set(raw.map(([c, e, p]) => dedupKey(c, e, p, base)));
  assert.equal(raw.length, 22); // 13 XSS + 9 others as listed
  assert.equal(keys.size, 8, [...keys].sort().join("\n"));

  // all /search XSS collapse to 1 key
  const searchKeys = new Set(
    raw.filter(([, e]) => e === "/search").map(([c, e, p]) => dedupKey(c, e, p, base)),
  );
  assert.equal(searchKeys.size, 1);
});

test("canonical categories are idempotent and dedupe stably", () => {
  // record_finding passes the canonical category enum → coarseClass must be idempotent
  // (in particular xss-stored must not be mis-folded into xss-reflected).
  for (const c of CATEGORIES) {
    assert.equal(coarseClass(c), c, `coarseClass(${c}) should be idempotent`);
  }
  assert.notEqual(
    dedupKey("xss-stored", "/support/new", "body", base),
    dedupKey("xss-reflected", "/support/new", "body", base),
  );
  const holes: Array<[string, string, string | undefined]> = [
    ["xss-reflected", "/search", "q"],
    ["path-traversal", "/download", "file"],
    ["idor", "/addresses/{id}", undefined],
    ["idor", "/orders/o10", undefined],
    ["idor-write", "/addresses/12/edit", undefined],
    ["idor", "/orders/o10/receipt", undefined],
    ["xss-stored", "/support/new", "body"],
    ["xss-stored", "/support/tickets/42", "body"],
  ];
  assert.equal(new Set(holes.map(([c, e, p]) => dedupKey(c, e, p, base))).size, 8);
});
