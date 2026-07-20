// ASR ① DISCOVER — provenance-tagged host candidates from multiple sources (crt.sh / import / active brute), merged.
// The union AssetSource already reserves "import"/"active", so provenance needs no core change. mergeCandidates keeps a
// passive-authoritative priority (crt.sh > import > active > seed) for the primary origin, and unions liveness hints.

import type { AssetSource } from "@veritas/core";

/** Pre-filled liveness / fingerprint hints an offline import (httpx.json) can carry — lets --import-trust-liveness skip re-probing. */
export interface HostHint {
    alive?: boolean;
    scheme?: string;
    status?: number;
    title?: string;
    tech?: string[];
    server?: string;
}

/** One discovered host with its provenance (and optional import hints). */
export interface HostCandidate {
    host: string;
    source: AssetSource;
    hint?: HostHint;
}

/** Passive-authoritative first: the primary `source` of a host found by several sources is the highest-priority one. */
const SOURCE_PRIORITY: AssetSource[] = ["crt.sh", "import", "active", "seed"];
const rank = (s: AssetSource): number => {
    const i = SOURCE_PRIORITY.indexOf(s);
    return i < 0 ? SOURCE_PRIORITY.length : i;
};

/**
 * Merge candidate lists: dedupe by host, keep the highest-priority source as the primary origin, and union hints
 * (the first source that supplied a field wins — crt.sh carries no hint, so an import's liveness hint is retained even
 * when crt.sh is the primary origin). Sorted by host. Pure.
 */
export function mergeCandidates(...lists: HostCandidate[][]): HostCandidate[] {
    const byHost = new Map<string, HostCandidate>();
    for (const list of lists) {
        for (const c of list) {
            const prev = byHost.get(c.host);
            if (!prev) {
                byHost.set(c.host, { host: c.host, source: c.source, ...(c.hint ? { hint: { ...c.hint } } : {}) });
                continue;
            }
            const source = rank(c.source) < rank(prev.source) ? c.source : prev.source;
            const hint = prev.hint || c.hint ? { ...(c.hint ?? {}), ...(prev.hint ?? {}) } : undefined; // prev wins per field
            byHost.set(c.host, { host: c.host, source, ...(hint ? { hint } : {}) });
        }
    }
    return [...byHost.values()].sort((a, b) => (a.host < b.host ? -1 : a.host > b.host ? 1 : 0));
}

/**
 * Probe-budget priority for a candidate host (LOWER = probe first). Under `--max-hosts`, a flood of auto-generated
 * ephemeral hosts (deep chains + random-hex leftmost labels — e.g. `1jwqo068-cloudhub-eu-west-1.qa.hydra.example.com`
 * pulled from CT logs) would otherwise starve the budget of high-value named hosts (`portal.example.com`). This orders
 * named/shallow hosts ahead of deep/random ones so the cap keeps the interesting surface. Pure heuristic; it only
 * affects ordering *under* the cap — it never drops a candidate, and dictionary labels (dev/qa/api) are never penalized.
 */
export function probePriority(host: string): number {
    const labels = host.split(".");
    const left = labels[0] ?? "";
    let p = 0;
    p += Math.max(0, labels.length - 3) * 12; // subdomain depth beyond apex+1 (apex = 2 labels; one named label = 3)
    if (left.length >= 8 && /\d/.test(left) && /[a-z]/i.test(left)) p += 8; // random-looking leftmost (mixes digits + letters)
    if (left.length > 20) p += 8; // very long leftmost label
    return p;
}

/** Order candidates for the probe budget: named/shallow first (probePriority), then alphabetical. Stable + pure. */
export function orderCandidatesForProbe(candidates: HostCandidate[]): HostCandidate[] {
    return [...candidates].sort((a, b) => probePriority(a.host) - probePriority(b.host) || a.host.localeCompare(b.host));
}
