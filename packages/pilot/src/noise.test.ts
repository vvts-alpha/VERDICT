// FP-robustness helpers for length-differential confirmation: normalizeVolatile (strip per-request tokens so same-content
// responses compare equal) and diffThreshold (a noise-aware floor so a delta below the page's own jitter is not trusted).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { normalizeVolatile, diffThreshold } from "./tools.js";

const nlen = (s: string): number => normalizeVolatile(s).length;

test("normalizeVolatile: two responses differing ONLY in __VIEWSTATE compare equal", () => {
  const a = '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="dDwtMTIzNDU2Nzg5MDs+long" />BODY';
  const b = '<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="ZZ" />BODY';
  assert.notEqual(a.length, b.length); // raw lengths differ (the FP source)
  assert.equal(nlen(a), nlen(b)); // normalized: identical
});

test("normalizeVolatile: CSP nonce / CSRF token / timestamp churn is stripped", () => {
  const a = 'nonce="AAAABBBBCCCC" csrf_token=abc123DEF456ghi 2026-07-11T10:18:14Z generated in 12ms';
  const b = 'nonce="ZZ" csrf_token=zzzzzzzzzzzz 2020-01-01T00:00:00Z generated in 9999ms';
  assert.equal(nlen(a), nlen(b));
});

test("normalizeVolatile: a REAL content difference (row count) still differs after normalization", () => {
  const trueRows = "<tr>row1</tr><tr>row2</tr><tr>row3</tr>"; // boolean TRUE → rows present
  const falseRows = "<tr>no results</tr>"; // boolean FALSE → empty
  assert.notEqual(nlen(trueRows), nlen(falseRows)); // the injection signal survives
});

test("diffThreshold: quiet page keeps the ±64 floor", () => {
  assert.equal(diffThreshold(0), 64);
  assert.equal(diffThreshold(30), 64); // 30*2 = 60 < 64 → floor
});

test("diffThreshold: a noisy page raises the bar above the noise (noise*2)", () => {
  assert.equal(diffThreshold(300), 600); // a 67-byte delta on a ±300 page would NOT clear this → not confirmed
  assert.equal(diffThreshold(100), 200);
});

test("diffThreshold: negative noise is treated by magnitude", () => {
  assert.equal(diffThreshold(-300), 600);
});
