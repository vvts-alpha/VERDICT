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
}

export interface LlmClient {
  complete(req: LlmRequest): Promise<LlmResponse>;
}
