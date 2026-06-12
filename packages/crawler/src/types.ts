// crawler 内部の観測契約。driver(Playwright/Fake)が満たし、pure パイプラインが消費する。

import type { AuthState, Screen, ScopePolicy } from "@veritas/core";

/** ナビゲーション中に傍受した 1 リクエスト/レスポンス対(DESIGN §6.2)。 */
export interface CapturedExchange {
  method: string;
  url: string;
  /** "xhr" | "fetch" | "document" | "script" | ... */
  resourceType: string;
  /** 認証ヘッダの「存在」のみ(値は保存しない。DESIGN §6.2) */
  hasAuthorizationHeader: boolean;
  hasCookieHeader: boolean;
  requestBody: string | null;
  status: number;
  /** JSON 形状推定用のレスポンス本文サンプル(切り詰め可) */
  responseBodySample: string | null;
  responseContentType: string | null;
}

export interface FormFieldObservation {
  name: string;
  /** input type / "textarea" / "select" */
  type: string;
}

export interface FormObservation {
  action: string | null;
  method: string;
  fields: FormFieldObservation[];
}

/** driver.visit() が 1 画面について返す観測。 */
export interface Observation {
  requestedUrl: string;
  /** リダイレクト後の最終 URL */
  finalUrl: string;
  status: number;
  title: string;
  /** タグ構造のみの正規化文字列(テキスト/属性値除去)。pipeline が hash 化(§6.4) */
  domSkeleton: string;
  /** ラベリング/説明用の可視テキスト要約 */
  visibleText: string;
  forms: FormObservation[];
  /** ページ内リンク(href 文字列。pipeline が絶対 URL 化) */
  links: string[];
  /** SPA 仮想ルート(pushState/hashchange、絶対 URL 化済み。§6.4) */
  virtualRoutes: string[];
  /** このナビゲーション中に傍受した XHR/fetch(§6.2) */
  apiCalls: CapturedExchange[];
  /** インラインスクリプト本文(API 静的抽出用 §6.2)。 */
  scripts?: string[];
}

/** クロール driver の抽象。実体は Playwright(本番)/ Fake(テスト)。 */
export interface Driver {
  visit(url: string): Promise<Observation>;
  close(): Promise<void>;
}

export type CrawlStopReason =
  | "frontier_empty"
  | "budget_requests"
  | "budget_screens"
  | "no_new_screens"
  | "wall_clock"
  | "paused";

export interface CrawlConfig {
  startUrl: string;
  scope: ScopePolicy;
  followLinks: boolean;
  maxDepth: number;
  /** このパスで採取した画面の authState(認証済み再クロールは "post-login")。既定 "unauth" */
  authState?: AuthState;
  /** クロール予算(DESIGN §6.7) */
  maxRequests?: number;
  maxScreens?: number;
  /** 新規 dedup_key が N 連続ゼロで停止(§6.7) */
  maxConsecutiveNoNew?: number;
  maxWallClockMs?: number;
}

export interface CrawlStats {
  visited: number;
  screens: number;
  apis: number;
  /** 認証ハンドオフを起票した数(§6.3) */
  handoffs: number;
  stopReason: CrawlStopReason;
  elapsedMs: number;
}

export interface CrawlResult {
  startUrl: string;
  screens: Screen[];
  stats: CrawlStats;
}
