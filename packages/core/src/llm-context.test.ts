import { test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CONTEXT_TOKENS, modelContextWindows, parseContextTokens } from "./llm-context.js";

test("context settings accept explicit capacities and reject malformed limits", () => {
  for (const value of [undefined, null, ""]) assert.equal(parseContextTokens(value), undefined);
  for (const value of [128_000, "256000", " 1000000 "]) assert.equal(parseContextTokens(value), Number(value));
  for (const value of [0, -1, 8191, 256000.5, NaN, Infinity, "256k", " ", "bad", true, {}, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => parseContextTokens(value), /Max context/);
  }
});

test("model context limits follow tiers, share Deep when Light uses the same model, and default to 256k", () => {
  assert.deepEqual(modelContextWindows({}), { deep: DEFAULT_CONTEXT_TOKENS, light: DEFAULT_CONTEXT_TOKENS });
  const env = { VERDICT_LLM_MODEL: "deep", VERDICT_LLM_CONTEXT_TOKENS: "128000" };
  assert.deepEqual(modelContextWindows(env), { deep: 128000, light: 128000 });
  assert.deepEqual(modelContextWindows({ ...env, VERDICT_LLM_FAST_MODEL: "deep" }), { deep: 128000, light: 128000 });
  assert.deepEqual(modelContextWindows({ ...env, VERDICT_LLM_FAST_MODEL: "light" }), { deep: 128000, light: 256000 });
  assert.deepEqual(modelContextWindows({ ...env, VERDICT_LLM_FAST_MODEL: "light", VERDICT_LLM_FAST_CONTEXT_TOKENS: "1000000" }), { deep: 128000, light: 1000000 });
  assert.throws(() => modelContextWindows({ ...env, VERDICT_LLM_FAST_CONTEXT_TOKENS: "broken" }), /Max context/);
});
