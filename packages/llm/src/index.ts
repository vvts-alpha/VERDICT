// @veritas/llm — Claude クライアント抽象(サブスク認証 CLI)+ JSON 抽出ユーティリティ。

export type { LlmClient, LlmRequest, LlmResponse } from "./types.js";
export { extractJson } from "./json.js";
export { ClaudeCliClient } from "./claude-cli.js";
export type { ClaudeCliOptions } from "./claude-cli.js";
export { FakeLlmClient } from "./fake.js";
export type { FakeResponder } from "./fake.js";
