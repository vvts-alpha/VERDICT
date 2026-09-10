// @veritas/llm — one-shot LLM client abstraction + provider selection (claude-cli default / OpenAI-compatible) + JSON extraction.

export type { LlmClient, LlmRequest, LlmResponse } from "./types.js";
export { extractJson } from "./json.js";
export { ClaudeCliClient } from "./claude-cli.js";
export type { ClaudeCliOptions } from "./claude-cli.js";
export { OpenAiClient, chatCompletionsUrl } from "./openai-client.js";
export type { OpenAiClientOptions, FetchLike } from "./openai-client.js";
export { makeLlmClient, resolveLlmConfig, createLlmClient } from "./factory.js";
export type { LlmProvider, LlmProviderConfig, LlmConfigOverrides } from "./factory.js";
export { FakeLlmClient } from "./fake.js";
export type { FakeResponder } from "./fake.js";
export { createProviderHeaders } from "./provider-headers.js";
