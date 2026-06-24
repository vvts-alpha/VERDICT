// probe_scenario の純粋部分: 前段レスポンスから値を抽出(extractValue)し、後段に差し込む(substVars)。
// 多段 workflow(カゴ作成 → その id を checkout に差し込み)が成立する土台の回帰テスト。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { substVars, extractValue } from "./tools.js";

test("substVars replaces {{var}} placeholders (and blanks unknowns)", () => {
  assert.equal(substVars("/rest/basket/{{id}}/checkout", { id: "42" }), "/rest/basket/42/checkout");
  assert.equal(substVars('{"BasketId":{{bid}},"coupon":"{{c}}"}', { bid: "6", c: "X" }), '{"BasketId":6,"coupon":"X"}');
  assert.equal(substVars("/x/{{missing}}/y", {}), "/x//y"); // 未定義は空
  assert.equal(substVars("{{ spaced }}", { spaced: "ok" }), "ok"); // 空白許容
});

test("extractValue reads a JSON path (object + array index)", () => {
  const body = JSON.stringify({ data: { id: 6, items: [{ id: 11 }, { id: 12 }] }, status: "ok" });
  assert.equal(extractValue(body, "data.id"), "6");
  assert.equal(extractValue(body, "data.items.1.id"), "12");
  assert.equal(extractValue(body, "status"), "ok");
});

test("extractValue falls back to a regex when JSON path misses or body is not JSON", () => {
  assert.equal(extractValue("set order_id=A39 done", "order_id=([A-Z0-9]+)"), "A39"); // 第1キャプチャ
  assert.equal(extractValue('{"token":"abc.def.ghi"}', "missing.path"), null); // JSON だがパス無し → regex も無し → null
  assert.equal(extractValue("plain text 777", "\\d+"), "777"); // キャプチャ無し → マッチ全体
});

test("extractValue returns null for absent values / invalid regex", () => {
  assert.equal(extractValue("{}", "a.b.c"), null);
  assert.equal(extractValue("nope", "([unclosed"), null);
});
