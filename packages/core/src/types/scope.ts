// DESIGN §4.2 / §4.5 — the structured scope the PolicyEngine (scope gate) reads.
//
// M0 defines types only. The decision logic (PolicyEngine) is a later milestone.

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
 * Scope breadth (how the in-scope host allow-set is built). The derivation mode from seed URLs.
 * - "same-origin": only the same host as the seed (exact). Strictest; rejects other subdomains (api.*).
 * - "etld": under the seed's registrable domain (`*.example.com`). Includes the program's API subdomains.
 * - "unrestricted": no host restriction (`*`). Violates the authorized-targets principle, so it's an explicit opt-in.
 */
export type ScopeMode = "same-origin" | "etld" | "unrestricted";

export interface ScopePolicy {
  /** in-scope hosts (exact match or glob; M0 assumes exact match) */
  inScopeHosts: string[];
  outOfScopeHosts: string[];
  /** Path prefixes considered in-scope (e.g. "/") */
  inScopePathPrefixes: string[];
  outOfScopePathPrefixes: string[];
  /** Path prefixes that force REQUIRES_APPROVAL (sensitive areas) */
  approvalPathPrefixes: string[];
  /** Methods that force REQUIRES_APPROVAL (destructive: DELETE/PUT/PATCH etc.) */
  approvalMethods: string[];
  /** Conservative default rate (WAF lesson. DESIGN §2.2/§4.5) */
  rate: RateLimit;
}
