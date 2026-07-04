// crawler-internal observation contract. Satisfied by the driver (Playwright/Fake), consumed by the pure pipeline.

import type { AuthState, Screen, ScopePolicy } from "@veritas/core";

/** One request/response pair intercepted during navigation (DESIGN §6.2). */
export interface CapturedExchange {
  method: string;
  url: string;
  /** "xhr" | "fetch" | "document" | "script" | ... */
  resourceType: string;
  /** Only the "presence" of the auth header (the value is never stored; DESIGN §6.2) */
  hasAuthorizationHeader: boolean;
  hasCookieHeader: boolean;
  requestBody: string | null;
  status: number;
  /** Response body sample for JSON shape inference (may be truncated) */
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

/** The observation driver.visit() returns for one screen. */
export interface Observation {
  requestedUrl: string;
  /** Final URL after redirects */
  finalUrl: string;
  status: number;
  title: string;
  /** Normalized string of tag structure only (text/attribute values stripped). The pipeline hashes it (§6.4) */
  domSkeleton: string;
  /** Visible-text summary for labeling/description */
  visibleText: string;
  forms: FormObservation[];
  /** In-page links (href strings; the pipeline makes them absolute) */
  links: string[];
  /** SPA virtual routes (pushState/hashchange, already absolute; §6.4) */
  virtualRoutes: string[];
  /** XHR/fetch intercepted during this navigation (§6.2) */
  apiCalls: CapturedExchange[];
  /** Inline script bodies (for static API extraction §6.2). */
  scripts?: string[];
}

/** Abstraction over the crawl driver. Concrete impls: Playwright (production) / Fake (tests). */
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
  /** authState for screens captured on this pass ("post-login" for an authenticated re-crawl). Default "unauth" */
  authState?: AuthState;
  /** Crawl budget (DESIGN §6.7) */
  maxRequests?: number;
  maxScreens?: number;
  /** Stop after N consecutive screens with zero new dedup_key (§6.7) */
  maxConsecutiveNoNew?: number;
  maxWallClockMs?: number;
}

export interface CrawlStats {
  visited: number;
  screens: number;
  apis: number;
  /** Number of auth handoffs raised (§6.3) */
  handoffs: number;
  stopReason: CrawlStopReason;
  elapsedMs: number;
}

export interface CrawlResult {
  startUrl: string;
  screens: Screen[];
  stats: CrawlStats;
}
