/** One backend call observed during a turn — a structural subset of crawler's CapturedExchange. */
export interface ApiCall {
  method: string;
  url: string;
  status: number;
  resourceType?: string;
}

/**
 * The browser primitives the chat-adapter composes over. Most map directly onto crawler's PlaywrightDriver
 * (fill / clickFirst / pressEnter / drainApiCalls / visit), but two require small **additive** primitives on
 * the real driver (added when it is wired in, slice 3) because the existing methods have the wrong semantics
 * for a chat UI:
 *   - `transcriptText()` — the crawler's `snapshot().visibleText` is whole-page AND capped (~4000 chars), which
 *     truncates long replies (they append at the bottom) and would make settle/delta silently return empty.
 *     Chat needs the UNCAPPED transcript / assistant-reply container text.
 *   - `stageFile()` — the crawler's `uploadFile()` always clicks a button after setInputFiles, which on a chat
 *     UI submits the file as a turn; the file-upload seedMode needs to STAGE the file without submitting.
 * FakeChatDriver implements all of these for offline tests.
 */
export interface ChatDriver {
  /** Fill `value` into the element matched by `selector` (pierces open shadow DOM). Returns success. */
  fill(selector: string, value: string): Promise<boolean>;
  /** Click the first `selectors` entry that resolves. Returns success (never throws on no-match). */
  clickFirst(selectors: string[]): Promise<boolean>;
  /** Press Enter on the element matched by `selector`. */
  pressEnter(selector: string): Promise<void>;
  /** UNCAPPED text of the conversation transcript / assistant-reply container (NOT whole-page visibleText).
   *  An optional selector pins the container (operator override) when the default priority list misfires. */
  transcriptText(selector?: string): Promise<string>;
  /** Take + clear the intercepted API-call buffer since the last drain. */
  drainApiCalls(): ApiCall[];
  /** Stage a file into a file input WITHOUT submitting (setInputFiles only — the composer submits later). */
  stageFile(
    selector: string,
    filename: string,
    base64: string,
    contentType?: string,
  ): Promise<{ ok: boolean; note: string }>;
  /** Navigate to a URL (newConversation fallback). */
  visit(url: string): Promise<unknown>;
}
