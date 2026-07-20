// ASR external-tool discovery adapters (S2+). Each adapter has HARDCODED argv (the operator never supplies raw flags),
// interpolates only the normalized apex + operator file paths, parses structured output (JSONL) with a garbage → []
// parser, and degrades to [] when the binary is missing. subfinder is PASSIVE (it aggregates OSINT feeds, no brute).

import type { RunTool } from "./run-tool.js";
import type { HostCandidate } from "./sources.js";

/** Parse subfinder `-json` JSONL ({"host":"api.example.com",...} per line) → hostnames. Garbage → [] (never throw). */
export function parseSubfinderJson(text: string): string[] {
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

export interface ToolDiscoverResult {
    candidates: HostCandidate[];
    /** the tool binary isn't installed — the caller logs a one-liner and continues */
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
    return { candidates: parseSubfinderJson(r.stdout).map((host) => ({ host, source: "import" as const })), missing: false };
}
