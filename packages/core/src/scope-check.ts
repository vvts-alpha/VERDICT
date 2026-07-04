// DESIGN §4.2 — minimal scope check (pure). Every crawl transition and scan request passes through it.
// The full decision (ALLOW/CAUTION/APPROVAL/DENY) will eventually be a PolicyEngine, but the in/out-of-scope
// host/path decision is centralized here and shared by crawler / scanner.

import type { ScopePolicy } from "./types/index.js";

/** Whether the host matches an allow pattern (exact match or `*.suffix`). Ports are ignored
 *  (host="app.example.com:3000" still matches `*.example.com` / `app.example.com`). */
export function hostMatches(host: string, patterns: string[]): boolean {
  const hostname = host.replace(/:\d+$/, ""); // hostname without the port
  return patterns.some((p) => {
    if (p === "*") return true; // "unrestricted" mode wildcard (matches every host)
    if (p === host || p === hostname) return true;
    if (p.startsWith("*.")) {
      const apex = p.slice(2); // "example.com"
      const suffix = p.slice(1); // ".example.com"
      return hostname === apex || hostname.endsWith(suffix);
    }
    return false;
  });
}

/** Same origin (in-scope hosts) + path prefix. out-of-scope takes precedence. */
export function isInScope(rawUrl: string, scope: ScopePolicy): boolean {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    return false;
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  if (hostMatches(u.host, scope.outOfScopeHosts)) return false;
  if (!hostMatches(u.host, scope.inScopeHosts)) return false;
  const path = u.pathname;
  if (scope.outOfScopePathPrefixes.some((p) => path.startsWith(p))) return false;
  if (
    scope.inScopePathPrefixes.length > 0 &&
    !scope.inScopePathPrefixes.some((p) => path.startsWith(p))
  ) {
    return false;
  }
  return true;
}

/**
 * Parse an operator-supplied target URL, requiring an explicit http(s) scheme. A schemeless target is rejected
 * with an actionable message instead of the two silent failure modes it otherwise causes downstream:
 *   - "example.com"      → `new URL()` throws an opaque TypeError, crashing scope derivation before the run starts.
 *   - "juice.shop:3000"  → `new URL()` misparses "juice.shop:" as the scheme (host=""), yielding a silently empty scope.
 * Used by deriveScopeFromUrls and the server's /api/run gate so a bad --url / WebUI target fails fast and clearly.
 */
export function parseTargetUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`invalid target URL "${raw}": include a scheme, e.g. https://${raw}`);
  }
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`invalid target URL "${raw}": must start with http:// or https://`);
  }
  return u;
}
