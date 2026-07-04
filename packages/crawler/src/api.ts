// DESIGN §6.2 — intercepted exchange → ApiCall inference (method, url_template, auth mask, req/res schema).

import type { ApiCall } from "@veritas/core";
import type { CapturedExchange } from "./types.js";
import { normalizePath } from "./url.js";
import { inferJsonShape } from "./json.js";

function detectAuth(ex: CapturedExchange): ApiCall["auth"] {
  if (ex.hasAuthorizationHeader) return "bearer";
  if (ex.hasCookieHeader) return "cookie";
  return "none";
}

/** Treat only XHR/fetch as internal APIs (excludes document/script/images etc.). */
export function isApiExchange(ex: CapturedExchange): boolean {
  const rt = ex.resourceType.toLowerCase();
  return rt === "xhr" || rt === "fetch";
}

export function inferApiCall(ex: CapturedExchange): ApiCall {
  let urlTemplate = ex.url;
  try {
    urlTemplate = normalizePath(new URL(ex.url).pathname).template;
  } catch {
    // keep the raw URL if it can't be parsed
  }
  const isJsonResp = ex.responseContentType?.includes("json") ?? false;
  return {
    method: ex.method.toUpperCase(),
    urlTemplate,
    auth: detectAuth(ex),
    reqSchema: inferJsonShape(ex.requestBody),
    resSchema: isJsonResp ? inferJsonShape(ex.responseBodySample) : null,
  };
}

export function apiKey(a: ApiCall): string {
  return `${a.method} ${a.urlTemplate}`;
}

interface ScriptPattern {
  re: RegExp;
  urlGroup: number;
  methodGroup?: number;
  method?: string;
}

const SCRIPT_PATTERNS: ScriptPattern[] = [
  { re: /\bfetch\s*\(\s*['"`]([^'"`]+)['"`]/g, urlGroup: 1, method: "GET" },
  { re: /\baxios\s*\.\s*(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi, urlGroup: 2, methodGroup: 1 },
  { re: /\.open\s*\(\s*['"`](GET|POST|PUT|DELETE|PATCH)['"`]\s*,\s*['"`]([^'"`]+)['"`]/gi, urlGroup: 2, methodGroup: 1 },
  { re: /['"`](\/(?:api|graphql|rest|v\d+)\/[^'"`\s?#]*)/g, urlGroup: 1, method: "GET" },
];

const ASSET_RE = /\.(js|mjs|css|png|jpe?g|svg|gif|webp|woff2?|ttf|ico|map|json)$/i;

/**
 * DESIGN §6.2 — statically extract API references from a page's JS (catches APIs that passive crawling never fires).
 * Normalizes fetch/axios/XHR/`/api` literals into ApiCalls. auth is unknown, so "none".
 */
export function extractApiRefs(scripts: string[], baseUrl: string): ApiCall[] {
  const found = new Map<string, ApiCall>();
  for (const text of scripts) {
    for (const pattern of SCRIPT_PATTERNS) {
      pattern.re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = pattern.re.exec(text)) !== null) {
        const rawUrl = m[pattern.urlGroup];
        if (!rawUrl) continue;
        const method = (pattern.methodGroup ? m[pattern.methodGroup] : pattern.method ?? "GET")?.toUpperCase() ?? "GET";
        let urlTemplate: string;
        try {
          urlTemplate = normalizePath(new URL(rawUrl, baseUrl).pathname).template;
        } catch {
          continue;
        }
        if (ASSET_RE.test(urlTemplate)) continue;
        const api: ApiCall = { method, urlTemplate, auth: "none", reqSchema: null, resSchema: null };
        found.set(apiKey(api), api);
      }
    }
  }
  return [...found.values()];
}
