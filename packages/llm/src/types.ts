// Abstraction over the Claude client. Concrete implementations: ClaudeCliClient (subscription auth) / FakeLlmClient (tests).

export interface LlmRequest {
  prompt: string;
  system?: string;
  model?: string;
  /** ms. Unspecified falls back to the client default */
  timeoutMs?: number;
}

export interface LlmResponse {
  text: string;
  model: string;
  /** Actual provider-reported usage when available. */
  tokensUsed?: number;
  /** Provider-reported input (prompt-side) tokens — includes cache reads/writes on Claude. */
  inputTokens?: number;
  /** Provider-reported output (completion-side) tokens. */
  outputTokens?: number;
  /** Prompt-side tokens served from the provider's prompt cache — Claude cache_read_input_tokens,
   *  DeepSeek prompt_cache_hit_tokens, OpenAI prompt_tokens_details.cached_tokens. */
  cacheReadTokens?: number;
  /** Prompt-side tokens written INTO the provider cache (Claude cache_creation_input_tokens). */
  cacheCreationTokens?: number;
}

export interface LlmClient {
  complete(req: LlmRequest): Promise<LlmResponse>;
}
