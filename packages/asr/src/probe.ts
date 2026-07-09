// ASR ② PROBE — resolve a candidate host and check HTTP liveness. Pure over injected deps (a DNS resolver + an
// HTTP GET), so it is offline-testable; the CLI wires node:dns + scanner's FetchHttpClient in (scope-gated, rated).

/** The liveness result for one candidate host. */
export interface HostProbe {
    host: string;
    /** Resolved IP addresses ([] = did not resolve → never probed over the wire). */
    addresses: string[];
    /** CNAME chain targets (for subdomain-takeover detection); [] if none / no resolver. */
    cnames: string[];
    /** True once the host answered with any HTTP status (even 401/403/5xx = it's live). */
    alive: boolean;
    scheme: "https" | "http" | null;
    status: number | null;
    title: string | null;
    /** The `Server:` response header — a light tech signal for P0 (fuller fingerprinting is P1). */
    server: string | null;
    /** A prefix of the response body (for takeover fingerprinting); "" if not fetched. */
    bodySample: string;
}

/** Resolve a hostname to IP addresses; resolves to [] when the host does not exist. */
export type Resolver = (host: string) => Promise<string[]>;

/** Resolve a host's CNAME chain targets; resolves to [] when there is no CNAME. */
export type CnameResolver = (host: string) => Promise<string[]>;

/** A minimal HTTP response shape (a subset of scanner's HttpResponse). */
export interface ProbeResponse {
    status: number;
    headers: Record<string, string>;
    body: string;
    finalUrl: string;
}

/** Perform a GET; **rejects** on a transport error (connection refused / timeout / TLS failure). */
export type HttpProbe = (url: string) => Promise<ProbeResponse>;

const TITLE_RE = /<title[^>]*>([\s\S]*?)<\/title>/i;

/** Look up a header case-insensitively (fetch/undici lowercase keys, but don't rely on it). */
function header(headers: Record<string, string>, name: string): string | null {
    const lower = name.toLowerCase();
    for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === lower) return headers[k] ?? null;
    }
    return null;
}

/** Extract a trimmed, length-capped <title>, or null. */
export function extractTitle(body: string): string | null {
    const m = TITLE_RE.exec(body);
    if (!m || m[1] === undefined) return null;
    const t = m[1].replace(/\s+/g, " ").trim();
    return t.length > 0 ? t.slice(0, 200) : null;
}

/**
 * Resolve a host, then probe HTTPS then HTTP for liveness. Any HTTP status counts as alive (401/403/5xx still prove
 * the host is up). A host that doesn't resolve, or resolves but answers on neither scheme, comes back `alive: false`.
 */
export async function probeHost(host: string, resolver: Resolver, http: HttpProbe, cnameResolver?: CnameResolver): Promise<HostProbe> {
    const [addresses, cnames] = await Promise.all([
        resolver(host).catch(() => []),
        cnameResolver ? cnameResolver(host).catch(() => []) : Promise.resolve<string[]>([]),
    ]);
    // Even with no A record, keep the CNAME chain — a dangling CNAME is a takeover signal.
    const dead: HostProbe = { host, addresses, cnames, alive: false, scheme: null, status: null, title: null, server: null, bodySample: "" };
    if (addresses.length === 0) return dead; // NXDOMAIN → nothing to probe over the wire
    for (const scheme of ["https", "http"] as const) {
        try {
            const res = await http(`${scheme}://${host}/`);
            return {
                host,
                addresses,
                cnames,
                alive: true,
                scheme,
                status: res.status,
                title: extractTitle(res.body),
                server: header(res.headers, "server"),
                bodySample: res.body.slice(0, 8192),
            };
        } catch {
            // transport error on this scheme — fall through and try the next
        }
    }
    return dead; // resolved but neither scheme responded
}
