// FP-robustness helpers for length-differential confirmation: normalizeVolatile (strip per-request tokens so same-content
// responses compare equal) and diffThreshold (a noise-aware floor so a delta below the page's own jitter is not trusted).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import {
  normalizeVolatile,
  diffThreshold,
  SQLI_BOOLEAN_PAIRS,
  looksLikeHtmlDocument,
  looksLikeStructuredBody,
  stripPayloadEcho,
  booleanLengthConfirmsSqli,
  sqliHtmlLengthOnlyFp,
} from "./tools.js";

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

test("SQLI_BOOLEAN_PAIRS: every TRUE/FALSE pair is the same length (matched quoting)", () => {
  for (const p of SQLI_BOOLEAN_PAIRS) {
    assert.equal(p.t.length, p.f.length, `${p.t} vs ${p.f}`);
  }
});

test("looksLikeHtmlDocument vs looksLikeStructuredBody", () => {
  assert.equal(looksLikeHtmlDocument("<!DOCTYPE html><html lang=en><body>search</body></html>"), true);
  assert.equal(looksLikeHtmlDocument("<html><head></head><body>x</body></html>"), true);
  assert.equal(looksLikeStructuredBody('{"n":1,"rows":[]}'), true);
  assert.equal(looksLikeStructuredBody('[{"id":1}]'), true);
  assert.equal(looksLikeStructuredBody('<?xml version="1.0"?><r/>'), true);
  assert.equal(looksLikeStructuredBody("<!DOCTYPE html><html><body>x</body></html>"), false);
  assert.equal(looksLikeHtmlDocument('{"ok":true}'), false);
});

test("stripPayloadEcho: search-box echo of the query is not a length oracle", () => {
  const t = "' OR '1'='1'-- -";
  const f = "' OR '1'='2'-- -";
  const wrap = (q: string) => `<h1>Search</h1><p>Results for ${q}</p>`;
  assert.equal(stripPayloadEcho(wrap(t), t).length, stripPayloadEcho(wrap(f), f).length);
});

test("booleanLengthConfirmsSqli: Drupal HTML length delta is NOT confirmation (Valero /search)", () => {
  const chrome = "<!DOCTYPE html><html lang=\"en\"><head><title>Search</title></head><body>" + "x".repeat(32000);
  const t = "' OR '1'='1'-- -";
  const f = "' OR '1'='2'-- -";
  const trueB = chrome + `<div>Results for ${t}</div></body></html>`;
  const falseB = chrome + `<div>Results for ${f}</div>` + "y".repeat(120) + "</body></html>";
  assert.equal(booleanLengthConfirmsSqli(trueB, falseB, t, f, 64), false);
});

test("booleanLengthConfirmsSqli: JSON extra rows ARE confirmation (Juice Shop search)", () => {
  const t = "' OR '1'='1'-- -";
  const f = "' OR '1'='2'-- -";
  const trueB = JSON.stringify({ n: 40, rows: Array.from({ length: 40 }, (_, i) => ({ id: i, name: "widget extra" })) });
  const falseB = JSON.stringify({ n: 0, rows: [] });
  assert.equal(booleanLengthConfirmsSqli(trueB, falseB, t, f, 64), true);
});

test("booleanLengthConfirmsSqli: refuses unmatched-length payloads (quoted FALSE vs bare TRUE)", () => {
  const jsonT = JSON.stringify({ n: 40, rows: Array.from({ length: 40 }, () => ({ x: "aaaaaaaa" })) });
  const jsonF = JSON.stringify({ n: 0, rows: [] });
  assert.equal(booleanLengthConfirmsSqli(jsonT, jsonF, " OR 1=1-- -", "' OR '1'='2'-- -", 64), false);
});

test("sqliHtmlLengthOnlyFp: HTML length-only is the Valero FP; JSON / SQL error / time-proof are not", () => {
  const html = (n: number) => `<!DOCTYPE html><html><body>${"z".repeat(n)}</body></html>`;
  assert.equal(sqliHtmlLengthOnlyFp(html(32468), [html(32348), html(32348)]), true);
  const jsonT = '{"n":40,"rows":[' + '"a"'.repeat(80) + "]}";
  const jsonF = '{"n":0,"rows":[]}';
  assert.equal(sqliHtmlLengthOnlyFp(jsonF, [jsonT, jsonT]), false);
  assert.equal(sqliHtmlLengthOnlyFp(html(100), ["You have an error in your SQL syntax", "You have an error in your SQL syntax"]), false);
  assert.equal(sqliHtmlLengthOnlyFp("baseline 3ms — no injection, fast response.", [
    "TIME-BASED BLIND SQLi CONFIRMED — payload=SLEEP(5)",
    "TIME-BASED BLIND SQLi CONFIRMED — payload=SLEEP(5)",
  ]), false);
});
