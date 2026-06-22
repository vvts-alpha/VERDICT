// DESIGN §4.2 — 最小スコープ判定(純粋)。crawl の遷移と scan の各リクエストが通る。
// 判定本体(ALLOW/CAUTION/APPROVAL/DENY)は将来 PolicyEngine が担うが、in/out-of-scope の
// ホスト・パス判定はここに集約し crawler / scanner で共有する。

import type { ScopePolicy } from "./types/index.js";

/** ホストが許可パターンに合致(完全一致 or `*.suffix`)。 */
export function hostMatches(host: string, patterns: string[]): boolean {
  return patterns.some((p) => {
    if (p === "*") return true; // "unrestricted" モードのワイルドカード(全ホスト一致)
    if (p === host) return true;
    if (p.startsWith("*.")) return host === p.slice(2) || host.endsWith(p.slice(1));
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
