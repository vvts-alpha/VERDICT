// Regression tests for false-negative bugs found by the FP-oracle bug hunt (2026-09-02): confirmation/FP-filter
// heuristics that were wrongly KILLING real findings. Each test fails on the pre-fix code.
import { test } from "node:test";
import assert from "node:assert/strict";
import { looksBlocked, reflectionIsLive, sqliHtmlLengthOnlyFp, booleanLengthConfirmsSqli, protectedContentLeaked } from "./tools.js";

// #1 looksBlocked — a normal 200 page that merely references a CDN/WAF vendor is NOT a block page.
test("looksBlocked: a 200 app page referencing Akamai/Incapsula is NOT blocked; a non-2xx challenge is", () => {
  assert.equal(looksBlocked({ status: 200, body: '<link rel="preconnect" href="https://assets.akamaized.net"><h1>Dashboard</h1>' }), false);
  assert.equal(looksBlocked({ status: 200, body: '<script src="/_Incapsula_Resource?SWJIYLWA=x"></script><h1>Home</h1>' }), false);
  assert.equal(looksBlocked({ status: 403, body: "<html>Incapsula ... _Incapsula_Resource challenge</html>" }), true);
  assert.equal(looksBlocked({ status: 503, body: "" }), true);
  assert.equal(looksBlocked({ status: 200, body: "Just a moment... challenges.cloudflare.com" }), true); // unconditional challenge marker
});

// #8 reflectionIsLive — a custom element <title-bar> must not make a following reflection look inert.
test("reflectionIsLive: <title-bar> custom element does not shadow a LIVE reflection after it", () => {
  const body = "<title-bar>Dashboard</title-bar><div><svg onload=alert('t123')></div>";
  assert.equal(reflectionIsLive(body, "<svg onload=alert('t123')"), true);
  // a genuine <title> container is still inert
  assert.equal(reflectionIsLive("<title><svg onload=alert(1)></title>", "<svg onload=alert(1)>"), false);
  assert.equal(reflectionIsLive("<script>var x='<svg onload=alert(1)>'</script>", "<svg onload=alert(1)>"), false);
});

// #9 sqliHtmlLengthOnlyFp — an HTML-bodied auth-bypass (401 -> 200 status flip) is a real SQLi, not an HTML-length FP.
test("sqliHtmlLengthOnlyFp: an HTML auth-bypass with a 401->200 status flip is kept", () => {
  assert.equal(sqliHtmlLengthOnlyFp("<html>Invalid credentials</html>", ["<html>Welcome, admin</html>", "<html>Welcome, admin</html>"], 401, [200, 200]), false);
  // JSON positives are kept even without statuses; a pure HTML length-only case (no status info) is still refused
  assert.equal(sqliHtmlLengthOnlyFp("Invalid", ['{"token":"x"}', '{"token":"x"}']), false);
  assert.equal(sqliHtmlLengthOnlyFp("<html>a</html>", ["<html>a b c d e</html>", "<html>a b c d e</html>"]), true);
});

// #12 booleanLengthConfirmsSqli — an equal-length JSON content flip ({"ok":1} vs {"ok":0}) confirms.
test("booleanLengthConfirmsSqli: same-length JSON content flip confirms; identical bodies do not", () => {
  assert.equal(booleanLengthConfirmsSqli('{"ok":1}', '{"ok":0}', "' OR '1'='1'-- -", "' OR '1'='2'-- -", 0), true);
  assert.equal(booleanLengthConfirmsSqli('{"ok":1}', '{"ok":1}', "' OR '1'='1'-- -", "' OR '1'='2'-- -", 0), false);
});

// #7 protectedContentLeaked — a genuine SMALLER subset leak (unauth shows a few of the protected records) is detected.
test("protectedContentLeaked: an unauth SUBSET of the authed content is detected", () => {
  const rec = (i: number) => `{"id":${i},"email":"user${i}@corp.example","phone":"555-01${String(i).padStart(2, "0")}"}`;
  const unauth = `[${rec(1)},${rec(2)}]`;
  const auth = `[${Array.from({ length: 20 }, (_, i) => rec(i + 1)).join(",")}]`;
  assert.equal(protectedContentLeaked(unauth, auth), true);
  assert.equal(protectedContentLeaked(unauth, "totally unrelated public marketing content ".repeat(6)), false);
});
