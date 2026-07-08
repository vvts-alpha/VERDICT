import type { ChatAdapter, ChatReply } from "./adapter.js";

export interface FakeChatContext {
  /** 0-based conversation index; increments on every newConversation(). */
  conversation: number;
  /** 0-based turn index within the current conversation. */
  turn: number;
}

export type FakeResponder = (prompt: string, ctx: FakeChatContext) => string;

/** Scriptable in-memory ChatAdapter for offline tests — never touches a browser or the network. */
export class FakeChatAdapter implements ChatAdapter {
  private conversation = -1;
  private turn = 0;
  readonly calls: Array<{ conversation: number; prompt: string; reply: string }> = [];

  constructor(private readonly responder: FakeResponder) {}

  async newConversation(): Promise<boolean> {
    this.conversation += 1;
    this.turn = 0;
    return true;
  }

  async send(prompt: string): Promise<ChatReply> {
    if (this.conversation < 0) await this.newConversation();
    const ctx: FakeChatContext = { conversation: this.conversation, turn: this.turn };
    const text = this.responder(prompt, ctx);
    this.turn += 1;
    this.calls.push({ conversation: this.conversation, prompt, reply: text });
    return { text };
  }
}
