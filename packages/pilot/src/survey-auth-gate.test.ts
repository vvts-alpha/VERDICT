// survey_done の認証ゲート: ロールがあるのに認証セッションが立っていなければ survey を閉じさせない。
// これが無いと、モデルが未認証フロンティアを空にしただけで survey_done を呼べてしまい、
// post-login サーフェスが丸ごと未マップになって画面数が静かに半減する(60→32 の実バグ)。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { surveyAuthGate } from "./tools.js";

test("gate: roles configured but no active session → refused (the 60→32 anonymous-survey bug)", () => {
  // attended で primary の currentRole は立つが cookie/bearer は空 = 実体は匿名 → authActive=false
  assert.equal(surveyAuthGate(3, false).ok, false);
  assert.equal(surveyAuthGate(1, false).ok, false);
});

test("gate: roles configured and a session is active → passes", () => {
  // login() が cookie か Bearer を載せた後
  assert.equal(surveyAuthGate(3, true).ok, true);
});

test("gate: no roles configured (auth-less target) → passes regardless", () => {
  assert.equal(surveyAuthGate(0, false).ok, true);
  assert.equal(surveyAuthGate(0, true).ok, true);
});
