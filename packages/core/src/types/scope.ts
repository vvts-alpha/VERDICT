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

/**
 * スコープ広さ(in-scope ホスト許可集合の作り方)。シード URL からの導出モード。
 * - "same-origin": シードと同一ホスト(exact)のみ。最も厳格。別サブドメイン(api.*)は弾く。
 * - "etld": シードの登録可能ドメイン配下(`*.example.com`)。同一プログラムの API サブドメインを含む。
 * - "unrestricted": ホスト制限なし(`*`)。authorized-targets 原則に反するので明示オプトイン向け。
 */
export type ScopeMode = "same-origin" | "etld" | "unrestricted";

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
