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
  // Paths: a trailing `*` is a wildcard marker (`/*` = every path). A catch-all allow ("/", "/*", "*") means
  // "no narrowing" — derived scopes set it implicitly — so blocks still apply under it. A non-catch-all
  // allow-prefix wins over a block, so the operator can carve exceptions (block /admin/*, allow /admin/public).
  const path = u.pathname;
  const pathMatch = (prefix: string): boolean =>
    path.startsWith(prefix.endsWith("*") ? prefix.slice(0, -1) : prefix);
  const isCatchAll = (prefix: string): boolean => {
    const n = prefix.endsWith("*") ? prefix.slice(0, -1) : prefix;
    return n === "" || n === "/" || n === "*";
  };
  const explicit = scope.inScopePathPrefixes.filter((p) => !isCatchAll(p));
  if (explicit.some(pathMatch)) return true;
  if (scope.outOfScopePathPrefixes.some(pathMatch)) return false;
  return scope.inScopePathPrefixes.length === 0 || scope.inScopePathPrefixes.some(isCatchAll);
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
