// @veritas/crawler — Phase1: crawl + intercept + dedup + rule labeling → screen_inventory.json.

// Orchestrator
export { crawl } from "./crawl.js";
export type { CrawlHooks } from "./crawl.js";

// Observation contract / config
export type {
  CapturedExchange,
  CrawlConfig,
  CrawlResult,
  CrawlStats,
  CrawlStopReason,
  Driver,
  FormFieldObservation,
  FormObservation,
  Observation,
} from "./types.js";

// URL normalization / scope
export {
  classifyPathSegment,
  extractQueryParams,
  hostMatches,
  isInScope,
  normalizePath,
  resolveLink,
} from "./url.js";
export type { PathParam, QueryParam, SegmentKind } from "./url.js";

// JSON shape inference
export { inferJsonShape, inferJsonShapeFromValue } from "./json.js";

// API inference / static extraction
export { apiKey, extractApiRefs, inferApiCall, isApiExchange } from "./api.js";

// DOM skeleton hash
export { hashDomSkeleton } from "./dom.js";

// Rule labeling
export { classifyScreenType, deriveLabels, describeScreen, guessParamType } from "./labeler.js";

// Inventory build / dedup
export { buildScreenFromObservation, InventoryBuilder } from "./inventory.js";
export type { BuiltScreen } from "./inventory.js";

export { parseOpenApiToScreens, validateOpenApiDocument, apiCallToBuiltScreen } from "./openapi-ingest.js";

// screen_inventory.json I/O
export { buildInventory, readScreenInventory, writeScreenInventory } from "./io.js";
export type { ScreenInventory } from "./io.js";

// LLM labeling (M2)
export {
  applyLabel,
  buildLabelPrompt,
  labelInventory,
  labelScreen,
  parseScreenLabel,
  LABEL_SYSTEM_PROMPT,
} from "./label.js";
export type {
  LabelInventoryHooks,
  LabelInventoryResult,
  LabelOptions,
  ParseResult,
  ScreenLabel,
} from "./label.js";

// Auth handoff (stuck detection §6.3)
export { detectStuck } from "./auth.js";
export type { StuckSignal } from "./auth.js";

// LLM-assisted login (auto-discovers the login screen/fields from just credentials)
export { smartLogin, heuristicFields } from "./smart-login.js";
export type { LoginDriver, LoginCreds, SmartLoginResult, SmartLoginOptions } from "./smart-login.js";

// Active exploration (§7.2 / §9) — drive the browser to surface fired APIs/state
export { exploreScreen, planExplore } from "./explore.js";
export type { ExploreDriver, ExploreResult, ExplorePlan } from "./explore.js";

// Drivers
export { FakeDriver } from "./drivers/fake.js";
export type { FakeSite } from "./drivers/fake.js";
export { PlaywrightDriver } from "./drivers/playwright.js";
export type { PlaywrightDriverOptions, AutoLoginOptions, CookieInfo } from "./drivers/playwright.js";

// HTML → PDF (report PDF output; reuses playwright-core, no new dependency)
export { htmlToPdf, detectSystemChromium, resolvePlaywrightLaunch } from "./pdf.js";
export type { HtmlToPdfOptions, PlaywrightLaunchChoice } from "./pdf.js";
