// ASR ③ SURFACE (P1) — light, curated path probing on a *live* host. A small set of high-signal GETs (exposed
// source/secret/config, API specs, info-disclosure). Each path has a **content-signature predicate** so a catch-all
// 200 / SPA soft-404 does NOT count (same evidence discipline as the scanner). Read-only; opt-in via `asr --paths`.
//
// The pure `probeSurface` takes an injected HTTP GET, so it is offline-testable; the CLI wires the scope-gated,
// rate-limited FetchHttpClient in and only calls it on hosts that are already alive + in scope.

import type { AssetPathHit } from "@veritas/core";

import type { HttpProbe } from "./probe.js";

interface Signals {
    status: number;
    body: string;
    ctype: string;
}

interface CuratedPath {
    path: string;
    /** Return a short note when the response is a genuine hit (signature match); undefined = not interesting. */
    hit: (s: Signals) => string | undefined;
    /** A genuine hit hard-escalates the host to critical (exposed source/secret/config). */
    escalate?: boolean;
}

const looksHtml = (b: string, ctype: string): boolean =>
    ctype.includes("text/html") || /<html|<!doctype html/i.test(b.slice(0, 256));

/** The curated set. Small on purpose — breadth is discovery's job, depth is `pilot`'s. */
export const CURATED_PATHS: CuratedPath[] = [
    { path: "/.git/HEAD", escalate: true, hit: (s) => (s.status === 200 && /^(ref:\s|[0-9a-f]{40})/m.test(s.body.trim()) ? "readable .git (HEAD)" : undefined) },
    { path: "/.git/config", escalate: true, hit: (s) => (s.status === 200 && /\[core\]/.test(s.body) ? "readable .git/config" : undefined) },
    { path: "/.env", escalate: true, hit: (s) => (s.status === 200 && !looksHtml(s.body, s.ctype) && /^[A-Z][A-Z0-9_]*=.+/m.test(s.body) ? "exposed .env" : undefined) },
    { path: "/actuator", hit: (s) => (s.status === 200 && /"_links"\s*:/.test(s.body) ? "Spring Actuator index" : undefined) },
    { path: "/actuator/env", escalate: true, hit: (s) => (s.status === 200 && /"propertySources"|"activeProfiles"/.test(s.body) ? "Actuator /env (config)" : undefined) },
    { path: "/actuator/heapdump", escalate: true, hit: (s) => (s.status === 200 && (s.ctype.includes("octet-stream") || s.body.length > 100_000) ? "Actuator heapdump" : undefined) },
    { path: "/server-status", hit: (s) => (s.status === 200 && /Apache Server Status/i.test(s.body) ? "mod_status exposed" : undefined) },
    { path: "/phpinfo.php", hit: (s) => (s.status === 200 && /phpinfo\(\)|<title>PHP [0-9]/i.test(s.body) ? "phpinfo()" : undefined) },
    { path: "/swagger.json", hit: (s) => (s.status === 200 && /"swagger"\s*:|"openapi"\s*:/.test(s.body) ? "OpenAPI/Swagger spec" : undefined) },
    { path: "/openapi.json", hit: (s) => (s.status === 200 && /"openapi"\s*:/.test(s.body) ? "OpenAPI spec" : undefined) },
    { path: "/v2/api-docs", hit: (s) => (s.status === 200 && /"swagger"\s*:|"paths"\s*:/.test(s.body) ? "Swagger api-docs" : undefined) },
    { path: "/graphql", hit: (s) => (s.status < 500 && /"__schema"|must provide query|graphql|"errors"\s*:/i.test(s.body) ? "GraphQL endpoint" : undefined) },
    { path: "/.well-known/security.txt", hit: (s) => (s.status === 200 && /contact\s*:/i.test(s.body) ? "security.txt" : undefined) },
    { path: "/robots.txt", hit: (s) => (s.status === 200 && !looksHtml(s.body, s.ctype) && /(dis)?allow\s*:/i.test(s.body) ? "robots.txt" : undefined) },
];

function contentType(headers: Record<string, string>): string {
    for (const k of Object.keys(headers)) {
        if (k.toLowerCase() === "content-type") return (headers[k] ?? "").toLowerCase();
    }
    return "";
}

/** Probe the curated paths on `scheme://host`; returns only the genuine hits. `http` rejects on transport error. */
export async function probeSurface(
    host: string,
    scheme: string,
    http: HttpProbe,
    paths: CuratedPath[] = CURATED_PATHS,
): Promise<AssetPathHit[]> {
    const base = `${scheme}://${host}`;
    const hits: AssetPathHit[] = [];
    for (const p of paths) {
        try {
            const res = await http(base + p.path);
            const note = p.hit({ status: res.status, body: res.body, ctype: contentType(res.headers) });
            if (note !== undefined) hits.push({ path: p.path, status: res.status, note, escalate: p.escalate === true });
        } catch {
            // path not reachable on this host — skip
        }
    }
    return hits;
}
