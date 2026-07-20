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
