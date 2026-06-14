// トークン計上: done ツールで stage を早期 break すると result(cumulative usage)を読めない。
// その場合でも assistant 各ターンの積算で計上されること(0 のままにならないこと)を固定する。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { usageTokens, stageTokenDelta } from "./run.js";

test("usageTokens は input+output+cache を合算", () => {
  assert.equal(usageTokens(undefined), 0);
  assert.equal(usageTokens({ input_tokens: 10, output_tokens: 5 }), 15);
  assert.equal(
    usageTokens({ input_tokens: 100, output_tokens: 20, cache_read_input_tokens: 300, cache_creation_input_tokens: 40 }),
    460,
  );
});

test("result を読めた stage は cumulative を採用", () => {
  assert.equal(stageTokenDelta(1200, 5000, true), 5000);
});

test("done ツールで早期 break(result 無し)でも assistant 積算で計上 — ここが 0 だったバグ", () => {
  assert.equal(stageTokenDelta(4200, 0, false), 4200);
  assert.notEqual(stageTokenDelta(4200, 0, false), 0);
});

test("result が assistant 積算より小さくても取りこぼさない(max)", () => {
  assert.equal(stageTokenDelta(4200, 100, true), 4200);
});
