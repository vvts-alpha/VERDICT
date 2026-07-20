// record_finding evidence-discipline structural check: ok only when the negative control is distinguishable from the positives and the positives are stable with each other.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { checkEvidenceDiscipline, checkLogicEvidence } from "./tools.js";

const r = (status: number, bodyLen: number) => ({ status, bodyLen });
const lr = (status: number, hasMarker: boolean) => ({ status, hasMarker });

test("ok: control fails (different status) + 2 stable positives", () => {
  assert.equal(checkEvidenceDiscipline(r(404, 12), [r(200, 800), r(200, 810)]).ok, true);
});

test("ok: differential by body length alone (same status)", () => {
  // IDOR-like: invalid id → 200/empty shell, valid adjacent id → 200/victim data
  assert.equal(checkEvidenceDiscipline(r(200, 40), [r(200, 900), r(200, 880)]).ok, true);
});

test("reject: fewer than 2 positive replays", () => {
  const v = checkEvidenceDiscipline(r(404, 0), [r(200, 800)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, />=2 positive/);
});

test("reject: positives disagree (unstable / flaky)", () => {
  const v = checkEvidenceDiscipline(r(404, 0), [r(200, 800), r(500, 30)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /unstable|disagree/);
});

test("reject: control indistinguishable from positives (catch-all)", () => {
  const v = checkEvidenceDiscipline(r(200, 805), [r(200, 800), r(200, 810)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /catch-all|indistinguishable/);
});

// ── business-logic marker-based gate ──
test("logic ok: marker accepted in 2 stable positives, absent in baseline", () => {
  // e.g. price=1 goes through and the order confirmation shows "total":1 (absent in the legitimate-price baseline)
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(200, true)]).ok, true);
});

test("logic reject: marker also in the legit baseline (not discriminating)", () => {
  const v = checkLogicEvidence(lr(200, true), [lr(200, true), lr(200, true)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /baseline/);
});

test("logic reject: a manipulated replay lacks the marker (not accepted)", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(200, false)]).ok, false);
});

test("logic reject: a manipulated replay was rejected (>=400)", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(403, true)]).ok, false);
});

test("logic reject: fewer than 2 positives", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true)]).ok, false);
});

// B6: reflected XSS confirms on a 4xx error page too (a payload reflected into a custom 403/404 still executes). The
// status<400 "accepted" gate is right for business-logic but wrong for reflection classes — requireSuccess:false skips it.
test("checkLogicEvidence: requireSuccess:false confirms a marker on a 4xx page (status doesn't gate reflection)", () => {
  const ctrl = { status: 200, hasMarker: false };
  const pos403 = [{ status: 403, hasMarker: true }, { status: 403, hasMarker: true }];
  assert.equal(checkLogicEvidence(ctrl, pos403).ok, false); // default (business-logic): status>=400 rejected
  assert.equal(checkLogicEvidence(ctrl, pos403, { requireSuccess: false }).ok, true); // XSS: error-page reflection still executes
});
