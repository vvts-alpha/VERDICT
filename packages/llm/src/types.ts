// Claude クライアントの抽象。実体は ClaudeCliClient(サブスク認証)/ FakeLlmClient(テスト)。

export interface LlmRequest {
  prompt: string;
  system?: string;
  model?: string;
  /** ms。未指定はクライアント既定 */
  timeoutMs?: number;
}

export interface LlmResponse {
  text: string;
  model: string;
}

export interface LlmClient {
  complete(req: LlmRequest): Promise<LlmResponse>;
}
