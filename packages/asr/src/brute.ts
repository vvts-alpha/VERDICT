// ASR S3 — the native DNS-brute fallback (when dnsx is absent). A pure-TS wordlist brute over an injected `resolve4`
// (node:dns in the CLI, a fake in tests), with a concurrency cap. Keeps `--brute` working with ZERO external deps
// (T3MP3ST's built-in-fallback pattern). It is ACTIVE (it sends resolution packets) — only reached under `--brute`.
//
// Honesty (matches asr's parser discipline): a host is emitted ONLY when resolve4 returns ≥1 address. NXDOMAIN /
// SERVFAIL / timeout → dropped, never a fabricated host. Each word is sanitized so a hostile wordlist line can't
// smuggle anything into the queried name.

import type { HostCandidate } from "./sources.js";

/** Resolve a hostname to A records; resolves to [] (or rejects) when the host does not exist. Same shape as probe.ts's Resolver. */
export type Resolve4 = (host: string) => Promise<string[]>;

export interface NativeBruteOptions {
    /** Max concurrent resolutions (default 10). */
    concurrency?: number;
    signal?: AbortSignal;
}

/** A DNS label: lowercase alnum + hyphen/underscore (a leading/trailing hyphen is still a valid query, so allow it). */
const LABEL_RE = /^[a-z0-9_-]+$/;

/**
 * nativeBrute — resolve `<word>.<apex>` for each wordlist entry over the injected resolver, bounded concurrency,
 * dropping non-resolving names. Returns deduped, host-sorted `source:"active"` candidates.
 */
export async function nativeBrute(resolve4: Resolve4, apex: string, words: string[], opts?: NativeBruteOptions): Promise<HostCandidate[]> {
    const labels = [...new Set(words.map((w) => w.trim().toLowerCase()).filter((w) => w.length > 0 && LABEL_RE.test(w)))];
    const found: HostCandidate[] = [];
    let idx = 0;
    const worker = async (): Promise<void> => {
        for (;;) {
            if (opts?.signal?.aborted) break;
            const w = labels[idx++]; // idx++ is synchronous between awaits → no race on the single JS thread
            if (w === undefined) break;
            const host = `${w}.${apex}`;
            try {
                const addrs = await resolve4(host);
                if (addrs.length > 0) found.push({ host, source: "active" });
            } catch {
                /* NXDOMAIN / SERVFAIL / timeout → dropped (never fabricate a host) */
            }
        }
    };
    const n = Math.max(1, Math.min(opts?.concurrency ?? 10, labels.length || 1));
    await Promise.all(Array.from({ length: n }, () => worker()));
    found.sort((a, b) => a.host.localeCompare(b.host));
    return found;
}
