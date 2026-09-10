import { test } from "node:test";
import assert from "node:assert/strict";
import { modelConnectionEnv } from "./model-providers.js";

test("desktop model capacities reach scan children as independent Deep and Light limits", () => {
    const env = modelConnectionEnv({ provider: "other", deepModel: "deep", lightModel: "light", deepContextTokens: 1_000_000, lightContextTokens: 256_000 });
    assert.equal(env.VERDICT_LLM_CONTEXT_TOKENS, "1000000");
    assert.equal(env.VERDICT_LLM_FAST_CONTEXT_TOKENS, "256000");
    const cleared = modelConnectionEnv({ provider: "other", deepModel: "deep" });
    assert.equal(cleared.VERDICT_LLM_CONTEXT_TOKENS, undefined);
    assert.equal(cleared.VERDICT_LLM_FAST_CONTEXT_TOKENS, undefined);
    assert.throws(() => modelConnectionEnv({ provider: "other", deepContextTokens: 0 }), /Max context/);
});

test("Claude settings leave context management to the SDK", () => {
    const env = modelConnectionEnv({ provider: "claude-cli", deepContextTokens: 128000, lightContextTokens: 256000 });
    assert.equal(env.VERDICT_LLM_CONTEXT_TOKENS, undefined);
    assert.equal(env.VERDICT_LLM_FAST_CONTEXT_TOKENS, undefined);
});
