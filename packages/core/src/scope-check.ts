// DESIGN §4.2 — 最小スコープ判定(純粋)。crawl の遷移と scan の各リクエストが通る。
// 判定本体(ALLOW/CAUTION/APPROVAL/DENY)は将来 PolicyEngine が担うが、in/out-of-scope の
// ホスト・パス判定はここに集約し crawler / scanner で共有する。

import type { ScopePolicy } from "./types/index.js";

/** ホストが許可パターンに合致(完全一致 or `*.suffix`)。ポートは無視して判定する
 *  (host="app.example.com:3000" でも `*.example.com` / `app.example.com` に一致させる)。 */
export function hostMatches(host: string, patterns: string[]): boolean {
  const hostname = host.replace(/:\d+$/, ""); // ポートを除いたホスト名
  return patterns.some((p) => {
    if (p === "*") return true; // "unrestricted" モードのワイルドカード(全ホスト一致)
    if (p === host || p === hostname) return true;
    if (p.startsWith("*.")) {
      const apex = p.slice(2); // "example.com"
      const suffix = p.slice(1); // ".example.com"
      return hostname === apex || hostname.endsWith(suffix);
    }
    return false;
  });
}

/** 同一オリジン(in-scope hosts)+ パス接頭辞。out-of-scope を優先。 */
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
