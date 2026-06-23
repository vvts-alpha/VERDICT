// record_finding の証拠規律 構造チェック: ネガコンが positive と区別でき、positive 同士が安定な時だけ ok。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { checkEvidenceDiscipline } from "./tools.js";

const r = (status: number, bodyLen: number) => ({ status, bodyLen });

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
