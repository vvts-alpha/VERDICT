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
const DEFAULT_NEWCHAT = [
  "[data-testid*='new-chat' i]",
  "button[aria-label*='new chat' i]",
  "button[aria-label*='new conversation' i]",
  "button[title*='new' i]",
];

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
  /** Chat UI URL — newConversation() navigates here (reload) only when reloads are allowed. */
  chatUrl?: string;
  composerSelectors?: string[];
  sendSelectors?: string[];
  newChatSelectors?: string[];
  fileInputSelector?: string;
  /** Pins the transcript/reply container for settle + delta (override when the driver's default misfires). */
  transcriptSelector?: string;
  /** Frame to scope every op to (iframe URL); "" = top document. Usually set by calibrate(). */
  frameSelector?: string;
  /** When true, newConversation() never reloads the page (attended widget — a reload would destroy the
   *  operator-opened widget + calibration); it resets only via a new-chat control, else throws. */
  noReload?: boolean;
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
 * Every op is scoped to `frameSelector` (set by calibrate() so an iframe-embedded widget is reachable).
 * `newConversation()` resets via a new-chat control; it reloads the page only when reloads are allowed and
 * throws rather than silently sharing one conversation (which would break the oracle's isolation).
 */
export class BrowserChatAdapter implements AttachingChatAdapter {
  private readonly chatUrl?: string;
  private readonly composerSelectors: string[];
  private readonly sendSelectors: string[];
  private readonly newChatSelectors: string[];
  private readonly fileInputSelector: string;
  private readonly transcriptSelector?: string;
  private frameSelector: string;
  private readonly noReload: boolean;
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
    this.transcriptSelector = opts.transcriptSelector;
    this.frameSelector = opts.frameSelector ?? "";
    this.noReload = opts.noReload ?? false;
    this.pollMs = opts.pollMs ?? 250;
    this.maxPolls = opts.maxPolls ?? 40;
    this.stableChecks = opts.stableChecks ?? 3;
    this.sleep = opts.sleep ?? realSleep;
  }

  /**
   * Attended calibration: after the operator has typed the marker into the RIGHT box and sent it, find which
   * frame it landed in and pin every subsequent op to that frame. Returns the frame ("" = top document) or
   * null if the marker wasn't found (probes then target the top document — likely the wrong input).
   */
  async calibrate(marker: string): Promise<string | null> {
    const hit = await this.driver.findMarker(marker);
    if (!hit) return null;
    this.frameSelector = hit.frame;
    return hit.frame;
  }

  async newConversation(): Promise<void> {
    if (this.newChatSelectors.length > 0 && (await this.driver.clickFrame(this.frameSelector, this.newChatSelectors))) {
      return;
    }
    if (this.chatUrl && !this.noReload) {
      await this.driver.visit(this.chatUrl);
      return;
    }
    // Fail loud rather than reload a manually-opened widget (destroys it) or share one conversation (breaks
    // the oracle's per-replay isolation — a canary lingering in history would fake stable positives).
    throw new Error(
      "chat-adapter: cannot start a fresh conversation — no new-chat control matched" +
        (this.noReload
          ? " and page reload is disabled (attended widget). Provide a new-chat selector."
          : " and no chatUrl configured") +
        "; conversation isolation cannot be guaranteed.",
    );
  }

  async send(prompt: string): Promise<ChatReply> {
    const before = await this.driver.transcriptTextFrame(this.frameSelector, this.transcriptSelector);
    this.driver.drainApiCalls(); // clear the buffer so we capture only this turn's calls
    const composer = await this.fillComposer(prompt);
    if (!composer) {
      throw new Error(`chat-adapter: no composer matched ${JSON.stringify(this.composerSelectors)}`);
    }
    if (!(await this.driver.clickFrame(this.frameSelector, this.sendSelectors))) {
      await this.driver.pressEnterFrame(this.frameSelector, composer);
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

  /** Try each composer candidate (within the calibrated frame); return the first that accepts the fill. */
  private async fillComposer(value: string): Promise<string | null> {
    for (const sel of this.composerSelectors) {
      if (await this.driver.fillFrame(this.frameSelector, sel, value)) return sel;
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
      current = await this.driver.transcriptTextFrame(this.frameSelector, this.transcriptSelector);
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
