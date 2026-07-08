/** One backend call observed during a turn — a structural subset of crawler's CapturedExchange. */
export interface ApiCall {
  method: string;
  url: string;
  status: number;
  resourceType?: string;
}

/**
 * The browser primitives the chat-adapter composes over. All page ops are FRAME-SCOPED: the first argument is
 * the target frame's URL, or "" for the top document. This lets the adapter drive an assistant embedded in an
 * iframe widget (located by attended calibration via findMarker) without touching the crawler's existing
 * top-level driver methods — PlaywrightDriver's *Frame methods delegate to the unchanged fill/clickFirst/
 * pressEnter/transcriptText when the frame is "". transcriptText is UNCAPPED (not whole-page visibleText);
 * stageFile stages a file WITHOUT the submit-click uploadFile performs.
 */
export interface ChatDriver {
  /** Fill `value` into `selector` within `frame` ("" = top document). Returns success. */
  fillFrame(frame: string, selector: string, value: string): Promise<boolean>;
  /** Click the first `selectors` entry that resolves within `frame`. Returns success. */
  clickFrame(frame: string, selectors: string[]): Promise<boolean>;
  /** Press Enter on `selector` within `frame`. */
  pressEnterFrame(frame: string, selector: string): Promise<void>;
  /** UNCAPPED transcript / reply-container text within `frame` ("" = top document). */
  transcriptTextFrame(frame: string, selector?: string): Promise<string>;
  /** Take + clear the intercepted API-call buffer since the last drain. */
  drainApiCalls(): ApiCall[];
  /** Stage a file into a file input WITHOUT submitting (setInputFiles only — the composer submits later). */
  stageFile(
    selector: string,
    filename: string,
    base64: string,
    contentType?: string,
  ): Promise<{ ok: boolean; note: string }>;
  /** Navigate to a URL (newConversation fallback when reloads are allowed). */
  visit(url: string): Promise<unknown>;
  /** Locate which frame a calibration marker landed in ("" = top document), or null if not found. */
  findMarker(marker: string): Promise<{ frame: string } | null>;
}
