// Contract type — one first-party JavaScript bundle the agent statically analyzed (endpoints / secrets mined from it).
// Shared like Screen/Finding/Asset: the WebUI reads it (types-only), so it lives in @veritas/core.

export interface JsSecret {
  /** the secret class, e.g. "secret" | "source-leak" (from the impact oracle) */
  kind: string;
  /** short, already-redacted locator (never the full secret value) */
  detail: string;
}

export interface JsAsset {
  /** the bundle URL — natural dedup key */
  url: string;
  bytes: number;
  /** endpoint URL-templates statically extracted from the bundle (fetch/axios/XHR/`/api` literals) */
  endpointsFound: string[];
  secretsFound: JsSecret[];
  /** a source map is reachable (//# sourceMappingURL, or <url>.map returns 200) — exposes original source */
  sourceMap: boolean;
  /** ISO-8601 */
  analyzedAt: string;
}
