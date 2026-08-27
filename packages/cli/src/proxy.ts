// Upstream-proxy resolution for a run. Kept in its own module (side-effect-free) so it is unit-testable
// without importing main.ts (which runs the CLI on import). See resolveUpstreamProxy for the precedence + invariant.

/** An optional-value flag as returned by extractOptValueFlag: whether it was given, and its optional inline value. */
export interface OptValueFlag {
    present: boolean;
    value?: string;
}

/**
 * Resolve the single upstream proxy for a run (routes BOTH the browser and the raw-http client through it).
 *
 * Precedence — first non-empty wins:
 *   1. `--proxy <url>`                    (general)
 *   2. bare `--proxy`  -> env VERDICT_PROXY, then BURP_PROXY
 *   3. `--burp-proxy <url>`               (compat alias)
 *   4. bare `--burp-proxy`  -> env BURP_PROXY
 *   5. manifest `proxy` field             (explicit operator config)
 *
 * Opt-in invariant: a bare env var ALONE never activates the proxy. With no proxy flag and no manifest
 * `proxy`, the result is `undefined` regardless of VERDICT_PROXY/BURP_PROXY being set — so none of the
 * downstream proxy code runs and behaviour is byte-identical to proxy-off. Env vars only supply the
 * *address* for a bare flag; the flag (or the manifest field) is what turns the proxy on.
 */
export function resolveUpstreamProxy(input: {
    proxyFlag: OptValueFlag;
    burpFlag: OptValueFlag;
    manifestProxy?: string;
    env?: Record<string, string | undefined>;
}): string | undefined {
    const env = input.env ?? {};
    const fromFlag = input.proxyFlag.present
        ? (input.proxyFlag.value ?? env.VERDICT_PROXY ?? env.BURP_PROXY)
        : input.burpFlag.present
          ? (input.burpFlag.value ?? env.BURP_PROXY)
          : undefined;
    return fromFlag ?? input.manifestProxy;
}

/** A proxy flag was given but nothing resolved (no inline value, no env, no manifest proxy) → warn and continue without a proxy. */
export function proxyFlagGivenButEmpty(proxyFlag: OptValueFlag, burpFlag: OptValueFlag, resolved: string | undefined): boolean {
    return (proxyFlag.present || burpFlag.present) && !resolved;
}
