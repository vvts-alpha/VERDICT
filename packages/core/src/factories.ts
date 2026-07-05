// Pure helpers that build the initial state. The real PolicyEngine/BudgetGuard are later milestones.

import type { BudgetState } from "./types/budget.js";
import type { ScopeMode, ScopePolicy } from "./types/scope.js";
import { registrableDomain } from "./etld.js";
import { parseTargetUrl } from "./scope-check.js";

/** A realistic desktop-Chrome User-Agent shared by the browser driver AND the raw-HTTP client, so a target/WAF sees a
 *  consistent, non-"HeadlessChrome" / non-"scanner" UA across the whole assessment (the x-verdict header identifies our
 *  traffic separately). Single source of truth — avoids drift between the browser and raw-HTTP paths. Override per-request. */
export const DEFAULT_BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36";

/** The wildcard "unrestricted" mode puts in inScopeHosts (hostMatches treats it as matching all). */
const UNRESTRICTED_HOST = "*";

/** A sortable, human-friendly id usable for runs/<assessment_id>/ */
export function newAssessmentId(now: Date = new Date()): string {
  const t = now.getTime().toString(36);
  const r = Math.random().toString(36).slice(2, 8);
  return `a-${t}-${r}`;
}

/** Conservative default budget, keyed on wall-clock/request count (DESIGN §13: cost is flat under the Max subscription). */
export function defaultBudget(now: Date = new Date()): BudgetState {
  return {
    limits: {
      maxTokens: 5_000_000,
      maxWallClockMs: 60 * 60 * 1000, // 1h
      maxTotalRequests: 5_000,
      maxRequestsPerTarget: 2_000,
    },
    startedAt: now.toISOString(),
    tokensUsed: 0,
    totalRequests: 0,
    requestsPerTarget: {},
  };
}

/**
 * Derive the default scope from a set of seed URLs + a mode (DESIGN §4.2/§5).
 * - "same-origin": same host as each seed (exact, port included)
 * - "etld":        under each seed's registrable domain (`*.example.com`); includes the program's API subdomains
 * - "unrestricted": no host restriction (`*`)
 * Path prefix is always "/" (host-granularity gate). Not narrowing by the URL's path is the existing behavior.
 */
export function deriveScopeFromUrls(rawUrls: string[], mode: ScopeMode = "same-origin"): ScopePolicy {
  const hosts = new Set<string>();
  for (const raw of rawUrls) {
    const u = parseTargetUrl(raw); // reject schemeless/non-http(s) with a clear error (vs an opaque throw or a silently empty scope)
    if (mode === "unrestricted") hosts.add(UNRESTRICTED_HOST);
    else if (mode === "etld") {
      const reg = registrableDomain(u.hostname);
      // IP / localhost etc. (no notion of subdomains): don't add `*.`; fall back to the exact host (port included).
      hosts.add(reg.includes(".") && !/^[0-9.]+$/.test(reg) ? `*.${reg}` : u.host);
    } else hosts.add(u.host);
  }
  return {
    inScopeHosts: [...hosts],
    outOfScopeHosts: [],
    inScopePathPrefixes: ["/"],
    outOfScopePathPrefixes: [],
    approvalPathPrefixes: [],
    approvalMethods: ["DELETE", "PUT", "PATCH"], // destructive → REQUIRES_APPROVAL (DESIGN §4.5)
    rate: { requestsPerMinute: 30, maxConcurrent: 2 }, // WAF lesson: stay conservative (DESIGN §2.2)
  };
}

/**
 * Derive the default scope from a single URL: same origin + under the entry point (DESIGN §4.2/§5).
 * A thin backward-compatible wrapper (= deriveScopeFromUrls([url], "same-origin")).
 */
export function deriveScopeFromSingleUrl(rawUrl: string): ScopePolicy {
  return deriveScopeFromUrls([rawUrl], "same-origin");
}
