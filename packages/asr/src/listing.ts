// ASR — open directory-listing enumeration. When a host serves an autoindex ("Index of /"), fetch it, parse the
// entries, and recurse into subdirectories (depth- and count-bounded) to produce a listing tree. Read-only GETs,
// scope-gated + rate-limited by the caller's HTTP client; opt-in via `asr --paths`. Pure parse + injectable http.

import type { ListingEntry } from "@veritas/core";

import type { HttpProbe } from "./probe.js";

/** Heuristic: does this response body look like an Apache/nginx/Python autoindex? */
export function isDirectoryListing(body: string): boolean {
    return (
        /<title>\s*Index of\b/i.test(body) ||
        /<h1>\s*Index of\b/i.test(body) ||
        /Directory listing for\b/i.test(body) || // Python http.server
        (/<a\s+href="[^"]*\/">/i.test(body) && /parent directory/i.test(body))
    );
}

/** Parse the direct-child entries (files + dirs) from an autoindex page. Skips parent/sort/protocol links. */
export function parseListing(body: string, basePath: string): ListingEntry[] {
    const base = basePath.endsWith("/") ? basePath : `${basePath}/`;
    const out: ListingEntry[] = [];
    const seen = new Set<string>();
    const re = /<a\s+href="([^"]+)"/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(body)) !== null) {
        const href = (m[1] ?? "").trim();
        if (!href || href.startsWith("?") || href.startsWith("#")) continue; // sort / anchor links
        if (/^[a-z][a-z0-9+.-]*:/i.test(href)) continue; // protocol-qualified (http:, mailto:, …)
        let rel = href;
        if (href.startsWith("/")) {
            if (!href.startsWith(base)) continue; // parent or other directory — skip
            rel = href.slice(base.length);
        }
        const isDir = rel.endsWith("/");
        const nameRaw = rel.replace(/\/$/, "");
        if (!nameRaw || nameRaw.includes("/") || nameRaw === ".." || nameRaw === ".") continue; // direct children only
        if (seen.has(rel)) continue;
        seen.add(rel);
        out.push({ name: decodeURIComponent(nameRaw), type: isDir ? "dir" : "file", path: base + rel });
    }
    return out;
}

export interface ListingOptions {
    /** How deep to recurse into subdirectories. Default 2. */
    maxDepth?: number;
    /** Total entries to enumerate across the whole tree (runaway guard). Default 100. */
    maxEntries?: number;
}

/**
 * Enumerate an open directory listing starting at `origin + startPath`, recursing into subdirs. `http` rejects on a
 * transport error (that subtree is skipped). Returns [] if the start URL isn't a 200 autoindex.
 */
export async function enumerateListing(origin: string, startPath: string, http: HttpProbe, opts: ListingOptions = {}): Promise<ListingEntry[]> {
    const maxDepth = opts.maxDepth ?? 2;
    const maxEntries = opts.maxEntries ?? 100;
    let count = 0;

    const walk = async (path: string, depth: number): Promise<ListingEntry[]> => {
        let body: string;
        let status: number;
        try {
            const res = await http(origin + path);
            body = res.body;
            status = res.status;
        } catch {
            return [];
        }
        if (status !== 200 || !isDirectoryListing(body)) return [];
        const entries = parseListing(body, path);
        const kept: ListingEntry[] = [];
        for (const e of entries) {
            if (count >= maxEntries) break;
            count += 1;
            if (e.type === "dir" && depth + 1 < maxDepth) {
                e.children = await walk(e.path.endsWith("/") ? e.path : `${e.path}/`, depth + 1);
            }
            kept.push(e);
        }
        return kept;
    };

    return walk(startPath, 0);
}
