// Contract type — one first-party JavaScript bundle the agent statically analyzed (endpoints / secrets mined from it).
// Shared like Screen/Finding/Asset: the WebUI reads it (types-only), so it lives in @veritas/core.

export interface JsSecret {
  /** the secret class, e.g. "secret" | "source-leak" (from the impact oracle) */
  kind: string;
  /** short, already-redacted locator (never the full secret value) */
  detail: string;
}

/** A dangerous DOM sink found in a bundle by static analysis (a DOM-XSS *candidate*, not a confirmed finding —
 *  confirmation is runtime, via probe_dom_xss executing a payload in a real browser). */
export interface JsSink {
  /** the sink, e.g. "innerHTML" | "eval" | "document.write" | "location.href" | "insertAdjacentHTML" */
  sink: string;
  /** the taint SOURCE that can reach it, if identified (e.g. "location.hash" | "postMessage" | "window.name");
   *  omitted = the sink is present but no user-controllable source was proven near it. */
  source?: string;
  /** a short, redacted code slice around the sink so the operator can eyeball it */
  snippet: string;
  /** how likely this is a real DOM-XSS: "high" (a source reaches the sink unsanitized) | "medium" | "low" */
  confidence: "high" | "medium" | "low";
  /** one line: why it is (or isn't quite) a candidate */
  rationale: string;
  /** a URL path/hash that would trigger it if inferable (e.g. "#/search?q={{XSS}}") — feeds probe_dom_xss */
  routeHint?: string;
  /** true = judged by the LLM refinement pass; false = regex-only (no LLM was available) */
  ai: boolean;
}

export interface JsAsset {
  /** the bundle URL — natural dedup key */
  url: string;
  bytes: number;
  /** endpoint URL-templates statically extracted from the bundle (fetch/axios/XHR/`/api` literals) */
  endpointsFound: string[];
  secretsFound: JsSecret[];
  /** dangerous DOM sinks found by static analysis (DOM-XSS candidates → confirmed at runtime by probe_dom_xss).
   *  Optional so older records / the deterministic path stay valid. */
  sinksFound?: JsSink[];
  /** a source map is reachable (//# sourceMappingURL, or <url>.map returns 200) — exposes original source */
  sourceMap: boolean;
  /** ISO-8601 */
  analyzedAt: string;
}
