import type { ApiCall, ChatDriver } from "./driver.js";

export interface FakeChatDriverOptions {
  /** Produce the assistant reply for a sent prompt in a given (0-based) conversation. */
  responder: (prompt: string, conversation: number) => string;
  composerSelector?: string;
  /** If set, clickFirst() submits when this selector is among the candidates (else Enter submits). */
  sendSelector?: string;
  /** If set, clickFirst() starts a fresh conversation when this selector is among the candidates. */
  newChatSelector?: string;
  fileInputSelector?: string;
  /**
   * Fractions of the new turn segment revealed on successive transcriptText() calls after submit (models
   * streaming). Monotonic growth never lets settle() settle early; a REPEATED value models a mid-stream STALL
   * that a too-small stableChecks would settle on prematurely (truncating the reply). Default: [0.34,0.67,1].
   */
  revealSchedule?: number[];
  apisFor?: (prompt: string, conversation: number) => ApiCall[];
}

/**
 * Scriptable in-memory ChatDriver for offline tests — models composer-fill, submit, streaming settle (incl.
 * mid-stream stalls), delta, an APPENDING API buffer, no-submit file staging, and conversation reset, all
 * without a browser or the network.
 */
export class FakeChatDriver implements ChatDriver {
  private base = ""; // transcript committed before the current turn
  private segment: string | null = null; // the current turn's new segment, revealed progressively
  private revealIdx = 0;
  private conversation = 0;
  private pendingPrompt: string | null = null;
  private buffer: ApiCall[] = [];
  readonly filled: string[] = [];
  readonly uploads: Array<{ selector: string; filename: string; base64: string }> = [];
  readonly visits: string[] = [];

  constructor(private readonly opts: FakeChatDriverOptions) {}

  private get composerSel(): string {
    return this.opts.composerSelector ?? "textarea";
  }
  private get schedule(): number[] {
    return this.opts.revealSchedule ?? [0.34, 0.67, 1];
  }

  async fill(selector: string, value: string): Promise<boolean> {
    if (selector !== this.composerSel) return false;
    this.pendingPrompt = value;
    this.filled.push(value);
    return true;
  }

  async clickFirst(selectors: string[]): Promise<boolean> {
    if (this.opts.sendSelector && selectors.includes(this.opts.sendSelector)) {
      this.submit();
      return true;
    }
    if (this.opts.newChatSelector && selectors.includes(this.opts.newChatSelector)) {
      this.resetConversation();
      return true;
    }
    return false;
  }

  async pressEnter(_selector: string): Promise<void> {
    this.submit();
  }

  async transcriptText(): Promise<string> {
    if (this.segment === null) return this.base;
    const sched = this.schedule;
    const frac = sched[Math.min(this.revealIdx, sched.length - 1)] ?? 1;
    this.revealIdx += 1;
    if (frac >= 1) {
      this.base = this.base + this.segment; // fully revealed → commit
      this.segment = null;
      return this.base;
    }
    const cut = Math.floor(this.segment.length * frac);
    return this.base + this.segment.slice(0, cut);
  }

  drainApiCalls(): ApiCall[] {
    const out = this.buffer.slice();
    this.buffer = [];
    return out;
  }

  /** Inject a stale/background API call (as if one fired between turns) — for testing the pre-turn drain. */
  enqueueApi(call: ApiCall): void {
    this.buffer.push(call);
  }

  /** Stage only — no submit, so the transcript does NOT advance (matches a real setInputFiles-only primitive). */
  async stageFile(selector: string, filename: string, base64: string): Promise<{ ok: boolean; note: string }> {
    this.uploads.push({ selector, filename, base64 });
    const target = this.opts.fileInputSelector ?? "input[type='file']";
    if (selector !== target) return { ok: false, note: `no file input at ${selector}` };
    return { ok: true, note: `staged ${filename}` };
  }

  async visit(url: string): Promise<unknown> {
    this.visits.push(url);
    this.resetConversation();
    return { url };
  }

  private submit(): void {
    if (this.pendingPrompt === null) return;
    const reply = this.opts.responder(this.pendingPrompt, this.conversation);
    this.segment = `\nuser: ${this.pendingPrompt}\nassistant: ${reply}`;
    this.revealIdx = 0;
    this.buffer.push(...(this.opts.apisFor?.(this.pendingPrompt, this.conversation) ?? []));
    this.pendingPrompt = null;
  }

  private resetConversation(): void {
    this.conversation += 1;
    this.base = "";
    this.segment = null;
    this.revealIdx = 0;
    this.pendingPrompt = null;
  }
}
