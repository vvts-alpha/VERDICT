/** One backend call the chat UI fired during a turn (RAG retrieval / tool call / completion). */
export interface ApiObservation {
  method: string;
  url: string;
  status?: number;
}

/** The assistant's reply to one sent turn, plus the backend calls it triggered. */
export interface ChatReply {
  text: string;
  apis?: ApiObservation[];
}

/**
 * The one low-level primitive the oracle composes over. A real implementation drives the deployed
 * assistant's composer via Playwright (later slice); FakeChatAdapter drives a scripted responder for
 * offline tests. `newConversation()` MUST yield a fresh, isolated context — see docs
 * §Two make-or-break risks: conversation isolation.
 */
export interface ChatAdapter {
  /** Reset to a fresh, isolated conversation (memory-off). Called before the control and before each replay. */
  newConversation(): Promise<void>;
  /** Send one user turn; resolves once the reply has settled. */
  send(prompt: string): Promise<ChatReply>;
}
