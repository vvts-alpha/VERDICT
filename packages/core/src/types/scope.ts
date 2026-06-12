// DESIGN §4.2 / §4.5 — PolicyEngine(スコープゲート)が読む構造化スコープ。
//
// M0 では型のみ定義する。判定ロジック(PolicyEngine)は後続マイルストン。

export type PolicyDecision =
  | "ALLOW"
  | "ALLOW_WITH_CAUTION"
  | "REQUIRES_APPROVAL"
  | "DENY";

export interface RateLimit {
  requestsPerMinute: number;
  maxConcurrent: number;
}

export interface ScopePolicy {
  /** in-scope ホスト(完全一致 or グロブ。M0 は完全一致想定) */
  inScopeHosts: string[];
  outOfScopeHosts: string[];
  /** in-scope とみなすパス接頭辞(例 "/") */
  inScopePathPrefixes: string[];
  outOfScopePathPrefixes: string[];
  /** REQUIRES_APPROVAL に倒すパス接頭辞(機微領域) */
  approvalPathPrefixes: string[];
  /** REQUIRES_APPROVAL に倒すメソッド(破壊的: DELETE/PUT/PATCH 等) */
  approvalMethods: string[];
  /** デフォルト保守的レート(WAF 教訓。DESIGN §2.2/§4.5) */
  rate: RateLimit;
}
