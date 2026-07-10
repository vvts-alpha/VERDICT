// WAF / bot-challenge false-positive guard. The namejet.com run manufactured 5 "confirmed SQLi" from Cloudflare 403
// "Just a moment..." challenge pages — the boolean length delta was challenge-page variance, not injection. looksBlocked
// detects the block, and checkEvidenceDiscipline refuses a length-only differential on non-2xx (WAF/error) responses.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { looksBlocked, checkEvidenceDiscipline } from "./tools.js";

test("looksBlocked: Cloudflare cf-mitigated challenge is blocked", () => {
  assert.equal(looksBlocked({ status: 403, headers: { "cf-mitigated": "challenge" }, body: "<title>Just a moment...</title>" }), true);
});

test("looksBlocked: 'Just a moment' body (no header) is blocked", () => {
  assert.equal(looksBlocked({ status: 403, body: "<html><title>Just a moment...</title>challenges.cloudflare.com</html>" }), true);
});

test("looksBlocked: 429 / 503 are blocked (rate-limit / unavailable)", () => {
  assert.equal(looksBlocked({ status: 429, body: "" }), true);
  assert.equal(looksBlocked({ status: 503, body: "" }), true);
});

test("looksBlocked: a real 200 app page is NOT blocked", () => {
  assert.equal(looksBlocked({ status: 200, body: "<html><body>Search results for foo</body></html>" }), false);
});

test("looksBlocked: an app's own 403 (real Forbidden content) is NOT a WAF challenge", () => {
  assert.equal(looksBlocked({ status: 403, body: "<h1>Forbidden</h1><p>You do not have access to this order.</p>" }), false);
});

test("checkEvidenceDiscipline: REJECTS a length-only differential on 403 WAF pages (the namejet FP)", () => {
  // TRUE replays 5982/5982 vs FALSE control 6049 — but ALL status 403 (Cloudflare challenge). Must be refused.
  const v = checkEvidenceDiscipline({ status: 403, bodyLen: 6049 }, [
    { status: 403, bodyLen: 5982 },
    { status: 403, bodyLen: 5982 },
  ]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /not a 2xx app response|block page|WAF/i);
});

test("checkEvidenceDiscipline: still CONFIRMS a genuine 2xx boolean differential", () => {
  const v = checkEvidenceDiscipline({ status: 200, bodyLen: 4000 }, [
    { status: 200, bodyLen: 5982 },
    { status: 200, bodyLen: 5982 },
  ]);
  assert.equal(v.ok, true);
});

test("checkEvidenceDiscipline: a status-based differential (200 vs 500) is still allowed", () => {
  // error-based signal: positives 500 (SQL error), control 200 — different status, not a WAF-length artifact.
  const v = checkEvidenceDiscipline({ status: 200, bodyLen: 4000 }, [
    { status: 500, bodyLen: 900 },
    { status: 500, bodyLen: 900 },
  ]);
  assert.equal(v.ok, true);
});
