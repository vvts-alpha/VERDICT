import type { ApiObservation, ChatAdapter, ChatReply } from "./adapter.js";
import type { ApiCall, ChatDriver } from "./driver.js";

const DEFAULT_COMPOSER = [
  "textarea",
  "[contenteditable='true']",
  "[contenteditable]",
  "[role='textbox']",
  "input[type='text']",
];
const DEFAULT_SEND = ["button[type='submit']", "button[aria-label*='send' i]", "[data-testid*='send' i]"];
const DEFAULT_NEWCHAT = ["[data-testid*='new-chat' i]", "button[aria-label*='new chat' i]"];

const realSleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function toApiObservation(a: ApiCall): ApiObservation {
  return { method: a.method, url: a.url, status: a.status };
}

/** Strip the longest common prefix — leaves the newly-appended transcript (user echo + assistant turn). */
export function extractDelta(before: string, after: string): string {
  let i = 0;
  const n = Math.min(before.length, after.length);
  while (i < n && before[i] === after[i]) i++;
  return after.slice(i);
}

export interface AttachFile {
  name: string;
  /** UTF-8 text content, or provide `base64` for binary. */
  content?: string;
  base64?: string;
  contentType?: string;
}

/** A ChatAdapter that also attaches a file — the P1 file-upload seedMode primitive. */
export interface AttachingChatAdapter extends ChatAdapter {
  attach(file: AttachFile): Promise<void>;
}

export interface BrowserChatAdapterOptions {
  /** Chat UI URL — newConversation() navigates here when no new-chat control is found. */
  chatUrl?: string;
  composerSelectors?: string[];
  sendSelectors?: string[];
  newChatSelectors?: string[];
  fileInputSelector?: string;
  /** Settle polling. */
  pollMs?: number;
  maxPolls?: number;
  stableChecks?: number;
  /** Injectable delay so tests can run without real timers. */
  sleep?: (ms: number) => Promise<void>;
}

/**
 * Drives a deployed assistant's chat UI through a ChatDriver: discovers the composer, sends a turn, waits for
 * the streaming reply to SETTLE, and returns only the new assistant turn (delta) + the backend calls it fired.
 * `newConversation()` performs a UI-level reset (new-chat control or navigation) and THROWS if it cannot,
 * rather than silently running the oracle's control + replays inside one shared conversation. A truly fresh
 * session/profile (memory-off, for the server-side-isolation invariant) is a wiring-layer concern.
 */
export class BrowserChatAdapter implements AttachingChatAdapter {
  private readonly chatUrl?: string;
  private readonly composerSelectors: string[];
  private readonly sendSelectors: string[];
  private readonly newChatSelectors: string[];
  private readonly fileInputSelector: string;
  private readonly pollMs: number;
  private readonly maxPolls: number;
  private readonly stableChecks: number;
  private readonly sleep: (ms: number) => Promise<void>;

  constructor(
    private readonly driver: ChatDriver,
    opts: BrowserChatAdapterOptions = {},
  ) {
    this.chatUrl = opts.chatUrl;
    this.composerSelectors = opts.composerSelectors ?? DEFAULT_COMPOSER;
    this.sendSelectors = opts.sendSelectors ?? DEFAULT_SEND;
    this.newChatSelectors = opts.newChatSelectors ?? DEFAULT_NEWCHAT;
    this.fileInputSelector = opts.fileInputSelector ?? "input[type='file']";
    this.pollMs = opts.pollMs ?? 250;
    this.maxPolls = opts.maxPolls ?? 40;
    this.stableChecks = opts.stableChecks ?? 3;
    this.sleep = opts.sleep ?? realSleep;
  }

  async newConversation(): Promise<void> {
    if (this.newChatSelectors.length > 0 && (await this.driver.clickFirst(this.newChatSelectors))) return;
    if (this.chatUrl) {
      await this.driver.visit(this.chatUrl);
      return;
    }
    // Fail loud: silently doing nothing would let the oracle run its control + replays in ONE conversation,
    // where intra-conversation carryover fakes ">=2 stable positives" and yields a false 'confirmed'.
    throw new Error(
      "chat-adapter: cannot start a fresh conversation — no new-chat control matched and no chatUrl configured; conversation isolation cannot be guaranteed",
    );
  }

  async send(prompt: string): Promise<ChatReply> {
    const before = await this.driver.transcriptText();
    this.driver.drainApiCalls(); // clear the buffer so we capture only this turn's calls
    const composer = await this.fillComposer(prompt);
    if (!composer) {
      throw new Error(`chat-adapter: no composer matched ${JSON.stringify(this.composerSelectors)}`);
    }
    if (!(await this.driver.clickFirst(this.sendSelectors))) {
      await this.driver.pressEnter(composer);
    }
    const after = await this.settle(before);
    const apis = this.driver.drainApiCalls().map(toApiObservation);
    return { text: extractDelta(before, after), apis };
  }

  /** Stage a file WITHOUT submitting; a subsequent send() submits file + benign prompt together (P1 seedMode). */
  async attach(file: AttachFile): Promise<void> {
    const base64 = file.base64 ?? Buffer.from(file.content ?? "", "utf8").toString("base64");
    const res = await this.driver.stageFile(this.fileInputSelector, file.name, base64, file.contentType);
    if (!res.ok) throw new Error(`chat-adapter: attach failed — ${res.note}`);
  }

  /** Try each composer candidate; return the first that accepts the fill. */
  private async fillComposer(value: string): Promise<string | null> {
    for (const sel of this.composerSelectors) {
      if (await this.driver.fill(sel, value)) return sel;
    }
    return null;
  }

  /** Poll the transcript until it changes from `before` and then holds stable for `stableChecks` polls. */
  private async settle(before: string): Promise<string> {
    let prev = before;
    let stable = 0;
    let current = before;
    for (let i = 0; i < this.maxPolls; i++) {
      await this.sleep(this.pollMs);
      current = await this.driver.transcriptText();
      if (current !== before && current === prev) {
        if (++stable >= this.stableChecks) return current;
      } else {
        stable = 0;
        prev = current;
      }
    }
    return current;
  }
}
