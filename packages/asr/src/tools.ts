// ASR external-tool discovery adapters (S2/S3). Each adapter has HARDCODED argv (the operator never supplies raw
// flags), interpolates only the normalized apex + operator file paths (wordlist/resolvers), parses structured output
// (JSONL) with a garbage → [] parser, and degrades to [] when the binary is missing. subfinder is PASSIVE (aggregates
// OSINT feeds, no brute); dnsx brute is ACTIVE (resolves <word>.<apex> against a resolver pool) → opt-in only.

import type { RunTool } from "./run-tool.js";
import type { HostCandidate } from "./sources.js";

/** Parse a `-json` JSONL stream ({"host":"api.example.com",...} per line) → hostnames. Garbage → [] (never throw). Shared by subfinder + dnsx. */
export function parseHostJsonl(text: string): string[] {
    const out = new Set<string>();
    for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t[0] !== "{") continue;
        try {
            const o = JSON.parse(t) as { host?: unknown };
            if (o && typeof o.host === "string" && o.host.trim()) out.add(o.host.trim().toLowerCase().replace(/\.$/, ""));
        } catch {
            /* skip non-JSON line */
        }
    }
    return [...out];
}

/** subfinder + dnsx both emit `-json` JSONL keyed on `.host`; kept as a named alias for the subfinder call site + its test. */
export const parseSubfinderJson = parseHostJsonl;

export interface ToolDiscoverResult {
    candidates: HostCandidate[];
    /** the tool binary isn't installed — the caller logs a one-liner and continues (or falls back). */
    missing: boolean;
}

/**
 * subfinder passive adapter: `subfinder -d <apex> -all -silent -json`. `-all` aggregates dozens of passive feeds (it
 * does NOT brute-force), so it's the single biggest breadth win over crt.sh-alone. Missing binary → { candidates: [],
 * missing: true }. Provenance tag is "import" (the reserved external-tool slot; no core change).
 */
export async function subfinderDiscover(runTool: RunTool, apex: string, opts?: { timeoutMs?: number }): Promise<ToolDiscoverResult> {
    const r = await runTool("subfinder", ["-d", apex, "-all", "-silent", "-json"], { timeoutMs: opts?.timeoutMs ?? 120_000 });
    if (r.missing) return { candidates: [], missing: true };
    return { candidates: parseHostJsonl(r.stdout).map((host) => ({ host, source: "import" as const })), missing: false };
}

export interface BruteOptions {
    /** Wordlist file path (required for a meaningful brute; cmdAsr materializes the bundled default when none given). */
    wordlist?: string;
    /** Trusted-resolver file path; omitted → dnsx uses its own default resolvers. */
    resolvers?: string;
    timeoutMs?: number;
}

/**
 * dnsx ACTIVE brute adapter: `dnsx -d <apex> -w <wordlist> [-r <resolvers>] -a -silent -json`. It resolves
 * `<word>.<apex>` against the resolver pool — this is the ONLY source that sends resolution packets, so it is opt-in
 * (`--brute`) at the CLI. Missing binary → { candidates: [], missing: true } so the caller can fall back to nativeBrute.
 * Provenance tag is "active" (lowest merge priority — crt.sh/import/subfinder win as primary source when a host overlaps).
 */
export async function dnsxBrute(runTool: RunTool, apex: string, opts?: BruteOptions): Promise<ToolDiscoverResult> {
    const args = ["-d", apex, ...(opts?.wordlist ? ["-w", opts.wordlist] : []), ...(opts?.resolvers ? ["-r", opts.resolvers] : []), "-a", "-silent", "-json"];
    const r = await runTool("dnsx", args, { timeoutMs: opts?.timeoutMs ?? 300_000 });
    if (r.missing) return { candidates: [], missing: true };
    return { candidates: parseHostJsonl(r.stdout).map((host) => ({ host, source: "active" as const })), missing: false };
}
