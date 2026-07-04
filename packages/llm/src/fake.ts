// Deterministic client for tests. Responds with a fixed string / function / array (consumed in order, last one repeated).

import type { LlmClient, LlmRequest, LlmResponse } from "./types.js";

export type FakeResponder = string | ((req: LlmRequest) => string);

export class FakeLlmClient implements LlmClient {
  /** Requests received so far (for assertions) */
  readonly calls: LlmRequest[] = [];
  private readonly scripted: FakeResponder[];
  private readonly fallback: FakeResponder;

  constructor(responder: FakeResponder | FakeResponder[]) {
    if (Array.isArray(responder)) {
      this.scripted = [...responder];
      this.fallback = responder[responder.length - 1] ?? "{}";
    } else {
      this.scripted = [];
      this.fallback = responder;
    }
  }

  async complete(req: LlmRequest): Promise<LlmResponse> {
    this.calls.push(req);
    const responder = this.scripted.length > 0 ? this.scripted.shift()! : this.fallback;
    const text = typeof responder === "function" ? responder(req) : responder;
    return { text, model: req.model ?? "fake-model" };
  }
}
