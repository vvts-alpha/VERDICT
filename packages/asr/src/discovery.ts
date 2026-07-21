// ASR ① DISCOVER — passive subdomain discovery from Certificate Transparency logs (crt.sh), over HTTPS, zero-dep.
//
// crt.sh is an external OSINT lookup: it queries public CT log data *about* the authorized apex domain, not the
// target hosts themselves — so it is passive by nature and does not touch the target. Everything that later *probes*
// a discovered host (dns/liveness/screenshot) goes through the scope gate + conservative rate limiting (P0-b+).
//
// The parse is pure and offline-testable; the fetch is a thin wrapper with an injectable `httpGet` so tests never
// hit the network (VERDICT test discipline: no real network/LLM in node:test).

import { get as httpsGet } from "node:https";

/** The apex + carve-outs a discovery run is scoped to. `domain` may be given as a wildcard ("*.example.com"). */
export interface DiscoveryScope {
    /** Registrable domain / apex the wildcard covers, e.g. "example.com" (a leading "*." is tolerated and stripped). */
    domain: string;
    /** Hostnames (or parent hosts) to exclude — bug-bounty carve-outs. A host and all its subdomains are dropped. */
    outOfScope?: string[];
}

/** A crt.sh JSON row — only the fields we read. `name_value` can be multi-line and can carry "*." wildcard entries. */
export interface CrtShRow {
    name_value?: string;
    common_name?: string;
}

/** An injectable HTTP GET returning the response body as text (tests pass a fake; runtime uses `fetchHttpGet`). */
export type HttpGet = (url: string) => Promise<string>;

/** Normalize an apex/domain: lowercase, drop a trailing dot and a leading "*.". */
function normalizeDomain(d: string): string {
    return d.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
}

/** Normalize one candidate name into a bare hostname, or null if it isn't a usable hostname. */
function normalizeHost(s: string): string | null {
    let h = s.trim().toLowerCase().replace(/\.$/, "");
    if (h.startsWith("*.")) h = h.slice(2); // a wildcard cert entry -> the bare parent host
    if (!h || h.includes("*") || h.includes(" ") || h.includes("@")) return null;
    if (!/^[a-z0-9.-]+$/.test(h)) return null;
    if (!h.includes(".")) return null;
    return h;
}

/** True if `host` is carved out — it equals a denied host, or is a subdomain of one. */
function isDenied(host: string, denies: string[]): boolean {
    return denies.some((d) => host === d || host.endsWith("." + d));
}

/** The crt.sh query URL for a domain's subdomains ("%.example.com" = the CT wildcard search). */
export function crtShUrl(domain: string): string {
    return `https://crt.sh/?q=${encodeURIComponent("%." + normalizeDomain(domain))}&output=json`;
}

/**
 * The single, safety-critical scope filter EVERY discovery source funnels through (crt.sh, import, subfinder, brute):
 * normalize each candidate, admit only the apex itself or a subdomain of it, drop carve-outs, dedupe, sort. Pure.
 * (The probe loop's `isInScope` remains the defense-in-depth backstop, so even a bug here can't put a host on the wire.)
 */
export function filterInScope(rawHosts: string[], scope: DiscoveryScope): string[] {
    const apex = normalizeDomain(scope.domain);
    const suffix = "." + apex;
    const denies = (scope.outOfScope ?? []).map(normalizeDomain).filter((d) => d.length > 0);
    const out = new Set<string>();
    for (const raw of rawHosts) {
        const h = normalizeHost(raw);
        if (!h) continue;
        if (h !== apex && !h.endsWith(suffix)) continue; // under the apex only
        if (isDenied(h, denies)) continue; // carve-outs
        out.add(h);
    }
    return [...out].sort();
}

/**
 * Parse crt.sh rows into a sorted, deduped list of in-scope hostnames under the apex. Pure.
 * Keeps the apex itself and any subdomain of it; strips "*." wildcard entries; drops foreign domains, carve-outs,
 * and anything that isn't a syntactically valid hostname.
 */
export function parseCrtSh(rows: CrtShRow[], scope: DiscoveryScope): string[] {
    const names = rows.flatMap((row) => `${row.name_value ?? ""}\n${row.common_name ?? ""}`.split("\n"));
    return filterInScope(names, scope);
}

/** Retry policy for the (frequently-overloaded) crt.sh endpoint. */
export interface DiscoveryOptions {
    /** How many times to try the fetch (crt.sh 502/503/timeouts are common). Default 3. */
    attempts?: number;
    /** Base backoff between attempts, multiplied by the attempt index. Default 4000ms. */
    backoffMs?: number;
}

/**
 * Fetch + parse subdomains for a domain from crt.sh. `httpGet` is injectable.
 * A **transport/HTTP error** (crt.sh 502/503/timeout) is retried with linear backoff; a **valid response that
 * isn't JSON** (an HTML rate-limit page served as 200) yields [] without retry (retrying won't help). If every
 * attempt errors, the last error is thrown — the caller (cmdAsr) logs it and continues with zero hosts.
 */
/** Retry only a transient crt.sh error (5xx = server up but erroring, or a timeout). A CONNECTION failure ("fetch
 *  failed" / ECONNREFUSED / DNS) won't recover in a few seconds of backoff — fail fast instead of burning ~12s. */
function isRetryableCrtErr(e: unknown): boolean {
    if (!(e instanceof Error)) return false;
    if (e.name === "TimeoutError" || e.name === "AbortError") return true; // crt.sh was just slow — a retry may catch it
    return /\b5\d\d\b|HTTP 5/i.test(e.message); // 5xx transient
}

export async function discoverCrtSh(scope: DiscoveryScope, httpGet: HttpGet, opts: DiscoveryOptions = {}): Promise<string[]> {
    const attempts = Math.max(1, opts.attempts ?? 3);
    const backoffMs = opts.backoffMs ?? 4000;
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
        try {
            const body = await httpGet(crtShUrl(scope.domain));
            try {
                const parsed = JSON.parse(body) as unknown;
                return parseCrtSh(Array.isArray(parsed) ? (parsed as CrtShRow[]) : [], scope);
            } catch {
                return []; // a valid HTTP response but not JSON (rate-limit HTML) — don't retry
            }
        } catch (e) {
            lastErr = e;
            if (!isRetryableCrtErr(e)) break; // unreachable (connection failure) → fail fast; retrying won't help
            if (i < attempts - 1) await new Promise((r) => setTimeout(r, backoffMs * (i + 1)));
        }
    }
    throw lastErr;
}

/**
 * Default runtime `httpGet`, forcing IPv4 (`family: 4`). crt.sh is dual-stack (A + AAAA); on a host with a dead IPv6
 * egress — common under WSL / containers — Node's global `fetch` grabs the AAAA and black-holes (surfacing as
 * "fetch failed" / ETIMEDOUT) without falling back to the reachable A record: Happy-Eyeballs still opens the v6 socket
 * regardless of `--dns-result-order=ipv4first`, so ordering alone doesn't help. `node:https` with `family: 4` resolves
 * A-only and connects over v4 — zero extra dep, no global Happy-Eyeballs disable. 10s timeout so an unreachable crt.sh
 * can't hang; a 5xx or a timeout is surfaced as a *retryable* error (see `isRetryableCrtErr` / `discoverCrtSh`).
 */
export const fetchHttpGet: HttpGet = (url) =>
    new Promise<string>((resolve, reject) => {
        const req = httpsGet(url, { family: 4, headers: { "user-agent": "verdict-asr" }, timeout: 10_000 }, (res) => {
            const status = res.statusCode ?? 0;
            if (status < 200 || status >= 300) {
                res.resume(); // drain the body so the socket is released
                reject(new Error(`crt.sh returned HTTP ${status}`));
                return;
            }
            let body = "";
            res.setEncoding("utf8");
            res.on("data", (chunk) => (body += chunk));
            res.on("end", () => resolve(body));
            res.on("error", reject);
        });
        req.on("error", reject);
        req.on("timeout", () => {
            const e = new Error("crt.sh request timed out");
            e.name = "TimeoutError"; // preserve discoverCrtSh's retry-on-timeout (isRetryableCrtErr checks the name)
            req.destroy(e);
        });
    });
