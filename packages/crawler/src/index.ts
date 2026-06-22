// @veritas/crawler — Phase1: クロール + 傍受 + dedup + ルールラベリング → screen_inventory.json。

// オーケストレータ
export { crawl } from "./crawl.js";
export type { CrawlHooks } from "./crawl.js";

// 観測契約 / 設定
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

// URL 正規化 / スコープ
export {
  classifyPathSegment,
  extractQueryParams,
  hostMatches,
  isInScope,
  normalizePath,
  resolveLink,
} from "./url.js";
export type { PathParam, QueryParam, SegmentKind } from "./url.js";

// JSON 形状推定
export { inferJsonShape, inferJsonShapeFromValue } from "./json.js";

// API 推定 / 静的抽出
export { apiKey, extractApiRefs, inferApiCall, isApiExchange } from "./api.js";

// DOM 骨格 hash
export { hashDomSkeleton } from "./dom.js";

// ルールラベリング
export { classifyScreenType, deriveLabels, describeScreen, guessParamType } from "./labeler.js";

// インベントリ構築 / dedup
export { buildScreenFromObservation, InventoryBuilder } from "./inventory.js";
export type { BuiltScreen } from "./inventory.js";

// screen_inventory.json 入出力
export { buildInventory, readScreenInventory, writeScreenInventory } from "./io.js";
export type { ScreenInventory } from "./io.js";

// LLM ラベリング(M2)
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

// 認証ハンドオフ(詰まり検出 §6.3)
export { detectStuck } from "./auth.js";
export type { StuckSignal } from "./auth.js";

// LLM 補助ログイン(資格情報だけでログイン画面/項目を自動発見)
export { smartLogin, heuristicFields } from "./smart-login.js";
export type { LoginDriver, LoginCreds, SmartLoginResult, SmartLoginOptions } from "./smart-login.js";

// 能動探索(§7.2 / §9)— ブラウザを操作して発火 API/状態を引き出す
export { exploreScreen, planExplore } from "./explore.js";
export type { ExploreDriver, ExploreResult, ExplorePlan } from "./explore.js";

// ドライバ
export { FakeDriver } from "./drivers/fake.js";
export type { FakeSite } from "./drivers/fake.js";
export { PlaywrightDriver } from "./drivers/playwright.js";
export type { PlaywrightDriverOptions, AutoLoginOptions, CookieInfo } from "./drivers/playwright.js";

// HTML → PDF(レポート PDF 出力。playwright-core 再利用・新規依存なし)
export { htmlToPdf } from "./pdf.js";
export type { HtmlToPdfOptions } from "./pdf.js";
