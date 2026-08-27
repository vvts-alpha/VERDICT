import { test } from "node:test";
import assert from "node:assert/strict";

import { resolveLlmConfig, makeLlmClient, OpenAiClient, ClaudeCliClient, chatCompletionsUrl, type FetchLike } from "./index.js";

// ---- resolveLlmConfig -------------------------------------------------------

test("default provider is claude-cli; the site's Claude default fills the model (byte-identical)", () => {
    const cfg = resolveLlmConfig({}, { claudeDefaultModel: "claude-sonnet-5" });
    assert.deepEqual(cfg, { provider: "claude-cli", model: "claude-sonnet-5" });
});

test("claude-cli with no default and empty env leaves model unset (ClaudeCliClient's own default applies)", () => {
    assert.deepEqual(resolveLlmConfig({}, {}), { provider: "claude-cli" });
});

test("explicit model (--model / manifest) wins over VERDICT_LLM_MODEL and the Claude default", () => {
    const cfg = resolveLlmConfig({ VERDICT_LLM_MODEL: "from-env" }, { explicitModel: "from-flag", claudeDefaultModel: "claude-sonnet-5" });
    assert.equal(cfg.model, "from-flag");
});

test("openai provider is read from env with base URL, key, and model", () => {
    const cfg = resolveLlmConfig({
        VERDICT_LLM_PROVIDER: "openai",
        VERDICT_LLM_BASE_URL: "https://api.openai.com/v1",
        VERDICT_LLM_API_KEY: "sk-test",
        VERDICT_LLM_MODEL: "gpt-4o",
    });
    assert.deepEqual(cfg, { provider: "openai", model: "gpt-4o", baseURL: "https://api.openai.com/v1", apiKey: "sk-test" });
});

test("openai NEVER inherits the Claude default model (fails loud instead of posting a Claude id)", () => {
    const cfg = resolveLlmConfig({ VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://x/v1" }, { claudeDefaultModel: "claude-sonnet-5" });
    assert.equal(cfg.model, undefined);
});

test("openai api key falls back to OPENAI_API_KEY", () => {
    const cfg = resolveLlmConfig({ VERDICT_LLM_PROVIDER: "openai", VERDICT_LLM_BASE_URL: "http://x/v1", OPENAI_API_KEY: "sk-oai" });
    assert.equal(cfg.apiKey, "sk-oai");
});

// ---- makeLlmClient ----------------------------------------------------------

test("makeLlmClient returns ClaudeCliClient for the default provider, OpenAiClient for openai", () => {
    assert.ok(makeLlmClient({ provider: "claude-cli", model: "claude-sonnet-5" }) instanceof ClaudeCliClient);
    assert.ok(makeLlmClient({ provider: "openai", baseURL: "http://x/v1", model: "gpt-4o" }) instanceof OpenAiClient);
});

test("makeLlmClient throws a clear error for openai without a base URL or without a model", () => {
    assert.throws(() => makeLlmClient({ provider: "openai", model: "gpt-4o" }), /requires a base URL/);
    assert.throws(() => makeLlmClient({ provider: "openai", baseURL: "http://x/v1" }), /requires a model/);
});

// ---- chatCompletionsUrl -----------------------------------------------------

test("chatCompletionsUrl appends the path, tolerating a trailing slash or an already-suffixed URL", () => {
    assert.equal(chatCompletionsUrl("https://api.openai.com/v1"), "https://api.openai.com/v1/chat/completions");
    assert.equal(chatCompletionsUrl("https://api.openai.com/v1/"), "https://api.openai.com/v1/chat/completions");
    assert.equal(chatCompletionsUrl("http://x/v1/chat/completions"), "http://x/v1/chat/completions");
});

// ---- OpenAiClient.complete (fake fetch, no network) -------------------------

/** A fake fetch that records the last call and returns a canned chat-completions response. */
function fakeFetch(resp: { status?: number; json?: unknown; body?: string }): { fetchImpl: FetchLike; last: () => { url: string; init: RequestInit } | undefined } {
    let captured: { url: string; init: RequestInit } | undefined;
    const fetchImpl: FetchLike = async (url, init) => {
        captured = { url, init };
        const status = resp.status ?? 200;
        const text = resp.body ?? JSON.stringify(resp.json ?? {});
        return new Response(text, { status, headers: { "content-type": "application/json" } });
    };
    return { fetchImpl, last: () => captured };
}

test("OpenAiClient posts model + system/user messages to /chat/completions with Bearer auth and returns {text, model}", async () => {
    const fake = fakeFetch({ json: { model: "gpt-4o", choices: [{ message: { role: "assistant", content: "hello" } }] } });
    const client = new OpenAiClient({ baseURL: "https://api.openai.com/v1", apiKey: "sk-test", defaultModel: "gpt-4o", fetchImpl: fake.fetchImpl });
    const res = await client.complete({ prompt: "hi there", system: "be terse" });

    assert.deepEqual(res, { text: "hello", model: "gpt-4o" });
    const call = fake.last();
    assert.ok(call);
    assert.equal(call.url, "https://api.openai.com/v1/chat/completions");
    assert.equal(call.init.method, "POST");
    const headers = call.init.headers as Record<string, string>;
    assert.equal(headers.authorization, "Bearer sk-test");
    const sent = JSON.parse(String(call.init.body)) as { model: string; messages: Array<{ role: string; content: string }> };
    assert.equal(sent.model, "gpt-4o");
    assert.deepEqual(sent.messages, [
        { role: "system", content: "be terse" },
        { role: "user", content: "hi there" },
    ]);
});

test("OpenAiClient omits the system message when none is given, and a per-request model overrides the default", async () => {
    const fake = fakeFetch({ json: { choices: [{ message: { content: "{}" } }] } });
    const client = new OpenAiClient({ baseURL: "http://local/v1", defaultModel: "default-m", fetchImpl: fake.fetchImpl });
    const res = await client.complete({ prompt: "p", model: "override-m" });

    // no api key -> no authorization header
    const headers = fake.last()!.init.headers as Record<string, string>;
    assert.equal(headers.authorization, undefined);
    const sent = JSON.parse(String(fake.last()!.init.body)) as { model: string; messages: Array<{ role: string }> };
    assert.equal(sent.model, "override-m");
    assert.deepEqual(sent.messages.map((m) => m.role), ["user"]);
    // response had no top-level model -> echoes the request model
    assert.equal(res.model, "override-m");
});

test("OpenAiClient throws on a non-2xx response, surfacing the status", async () => {
    const fake = fakeFetch({ status: 401, body: "unauthorized" });
    const client = new OpenAiClient({ baseURL: "http://x/v1", defaultModel: "m", fetchImpl: fake.fetchImpl });
    await assert.rejects(client.complete({ prompt: "p" }), /HTTP 401/);
});

test("OpenAiClient throws when the response has no message content", async () => {
    const fake = fakeFetch({ json: { choices: [] } });
    const client = new OpenAiClient({ baseURL: "http://x/v1", defaultModel: "m", fetchImpl: fake.fetchImpl });
    await assert.rejects(client.complete({ prompt: "p" }), /no choices\[0\]\.message\.content/);
});

test("OpenAiClient throws when no model is resolvable", async () => {
    const client = new OpenAiClient({ baseURL: "http://x/v1", fetchImpl: fakeFetch({ json: {} }).fetchImpl });
    await assert.rejects(client.complete({ prompt: "p" }), /no model/);
});
