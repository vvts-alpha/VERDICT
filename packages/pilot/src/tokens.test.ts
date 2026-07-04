// Token accounting: when a done tool breaks a stage early, we can't read result (cumulative usage).
// Pin that even then it is accounted from the per-turn assistant accumulation (it must not stay 0).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { usageTokens, stageTokenDelta } from "./run.js";

test("usageTokens counts fresh input + output + cache-creation, EXCLUDING re-read cache", () => {
  assert.equal(usageTokens(undefined), 0);
  assert.equal(usageTokens({ input_tokens: 10, output_tokens: 5 }), 15);
  // cache_creation (newly cached tokens) counts; cache_read_input_tokens does NOT — it is the cached prefix re-read
  // on every turn, so summing it inflates ~10x. 100 + 20 + 40 = 160 (the 300 cache_read is excluded).
  assert.equal(
    usageTokens({ input_tokens: 100, output_tokens: 20, cache_read_input_tokens: 300, cache_creation_input_tokens: 40 }),
    160,
  );
  // a huge re-read cache must not dominate the count (this was the ~38M-vs-5M inflation)
  assert.equal(usageTokens({ input_tokens: 5, output_tokens: 5, cache_read_input_tokens: 1_000_000 }), 10);
});

test("a stage that could read result adopts cumulative", () => {
  assert.equal(stageTokenDelta(1200, 5000, true), 5000);
});

test("even on early break by a done tool (no result), accounted via assistant accumulation — this was the 0 bug", () => {
  assert.equal(stageTokenDelta(4200, 0, false), 4200);
  assert.notEqual(stageTokenDelta(4200, 0, false), 0);
});

test("don't drop when result is smaller than the assistant accumulation (max)", () => {
  assert.equal(stageTokenDelta(4200, 100, true), 4200);
});
