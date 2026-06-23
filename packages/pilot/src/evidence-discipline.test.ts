// record_finding の証拠規律 構造チェック: ネガコンが positive と区別でき、positive 同士が安定な時だけ ok。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { checkEvidenceDiscipline, checkLogicEvidence } from "./tools.js";

const r = (status: number, bodyLen: number) => ({ status, bodyLen });
const lr = (status: number, hasMarker: boolean) => ({ status, hasMarker });

test("ok: control fails (different status) + 2 stable positives", () => {
  assert.equal(checkEvidenceDiscipline(r(404, 12), [r(200, 800), r(200, 810)]).ok, true);
});

test("ok: differential by body length alone (same status)", () => {
  // IDOR 風: 無効 id は 200/空シェル、有効隣接 id は 200/被害者データ
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
  // 例: price=1 が通り、注文確認に "total":1 が出る(baseline=正規価格には出ない)
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
