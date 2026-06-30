// screen_done カバレッジ・ゲート: 「1個見つけて打ち切り」を構造的に封じる。
// 計画した攻撃クラスを coverage で全部説明し、tested-clean を主張するなら最低1回 probe していること。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { plannedClassesFor, checkScreenCoverage } from "./tools.js";

test("plannedClassesFor parses the classes=[...] prefix and canonicalizes", () => {
  assert.deepEqual(
    plannedClassesFor("classes=[IDOR/BOLA,SQL-injection,stored-XSS] 1. test ... 2. ...").sort(),
    ["idor", "sqli", "xss-stored"].sort(),
  );
  // info-disclosure / headers / 自由文の other は網羅強制の対象外
  assert.deepEqual(plannedClassesFor("classes=[info-disclosure,headers] ..."), []);
  assert.deepEqual(plannedClassesFor("(no recorded plan — use judgement)"), []);
  assert.deepEqual(plannedClassesFor(undefined), []);
});

test("gate: a plan class with no coverage entry is rejected (the core 'find-one-move-on' fix)", () => {
  const planned = ["idor", "sqli", "xss-stored"];
  // SQLi だけ見つけて即 done → 残り idor/xss-stored が未説明 → 差し戻し
  const g = checkScreenCoverage(planned, [{ class: "sqli", result: "found" }], 5);
  assert.equal(g.ok, false);
  if (!g.ok) {
    assert.match(g.reason, /idor/);
    assert.match(g.reason, /xss-stored/);
  }
});

test("gate: every planned class accounted for → passes", () => {
  const planned = ["idor", "sqli"];
  const g = checkScreenCoverage(
    planned,
    [
      { class: "sqli", result: "found" },
      { class: "idor", result: "tested-clean" },
    ],
    7,
  );
  assert.equal(g.ok, true);
});

test("gate: claims tested but fired zero probes → rejected (anti self-report)", () => {
  const planned = ["idor"];
  const g = checkScreenCoverage(planned, [{ class: "idor", result: "tested-clean" }], 0);
  assert.equal(g.ok, false);
  if (!g.ok) assert.match(g.reason, /no probe/i);
});

test("gate: a 'suspected' coverage result accounts for the class AND counts as actually-tested", () => {
  const planned = ["idor", "ssti"];
  // 'suspected' は planned を満たし、claimsTested 側にも数える(=最低1 probe を要求する)。
  const ok = checkScreenCoverage(planned, [{ class: "idor", result: "suspected" }, { class: "ssti", result: "tested-clean" }], 4);
  assert.equal(ok.ok, true);
  const noProbe = checkScreenCoverage(["idor"], [{ class: "idor", result: "suspected" }], 0);
  assert.equal(noProbe.ok, false); // suspected を主張するなら probe を撃っているはず
  if (!noProbe.ok) assert.match(noProbe.reason, /no probe/i);
});

test("gate: not-applicable counts as accounted (escape hatch), and no-plan screens pass freely", () => {
  // 全部 not-applicable は probe 0 でも閉じれる(該当しない画面の正当な締め)
  assert.deepEqual(checkScreenCoverage(["csrf"], [{ class: "csrf", result: "not-applicable" }], 0), { ok: true });
  // プランにクラスが無い画面はゲート対象外
  assert.deepEqual(checkScreenCoverage([], [], 0), { ok: true });
});
