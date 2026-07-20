// ASR ① DISCOVER — offline import of external recon output (recon.sh). Ingests httpx JSONL (rich: liveness/title/tech
// hints) or a bare hosts list. Pure parsers (offline, garbage → [] — never throw, never fabricate a host); importRecon
// is the thin fs wrapper. Scope filtering is NOT done here — the caller funnels the merged set through filterInScope.

import { readFileSync, statSync, readdirSync } from "node:fs";
import { join } from "node:path";
import type { HostCandidate } from "./sources.js";

/** Normalize a raw host-ish token (a bare host, host:port, or a URL) to a bare hostname, or null if unusable. */
function bareHost(raw: string): string | null {
    let h = raw.trim().toLowerCase();
    if (!h || h.startsWith("#")) return null;
    if (h.includes("://")) {
        try {
            h = new URL(h).hostname;
        } catch {
            return null;
        }
    }
    h = (h.split("/")[0] ?? "").split(":")[0]?.replace(/\.$/, "") ?? "";
    if (!h || h.includes("*") || !h.includes(".") || !/^[a-z0-9.-]+$/.test(h)) return null;
    return h;
}

/** Parse httpx JSONL (one JSON object per line): url/host/status_code/title/tech/webserver → candidates with hints. */
export function parseHttpxJsonl(text: string): HostCandidate[] {
    const out: HostCandidate[] = [];
    for (const line of text.split(/\r?\n/)) {
        const t = line.trim();
        if (!t || t[0] !== "{") continue; // skip blanks / non-JSON lines (never throw)
        let o: Record<string, unknown>;
        try {
            const parsed = JSON.parse(t);
            if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) continue;
            o = parsed as Record<string, unknown>;
        } catch {
            continue;
        }
        let host = typeof o["host"] === "string" ? (o["host"] as string) : "";
        let scheme: string | undefined;
        if (typeof o["url"] === "string") {
            try {
                const u = new URL(o["url"] as string);
                if (!host) host = u.hostname;
                scheme = u.protocol.replace(":", "");
            } catch {
                /* ignore a bad url */
            }
        }
        if (!host && typeof o["input"] === "string") host = o["input"] as string;
        const h = bareHost(host);
        if (!h) continue;
        const status = typeof o["status_code"] === "number" ? (o["status_code"] as number) : undefined;
        const title = typeof o["title"] === "string" ? (o["title"] as string) : undefined;
        const server = typeof o["webserver"] === "string" ? (o["webserver"] as string) : undefined;
        const tech = Array.isArray(o["tech"]) ? (o["tech"] as unknown[]).filter((x): x is string => typeof x === "string") : undefined;
        const alive = status != null ? status > 0 && status < 400 : undefined;
        const hint: HostCandidate["hint"] = {
            ...(alive != null ? { alive } : {}),
            ...(scheme ? { scheme } : {}),
            ...(status != null ? { status } : {}),
            ...(title ? { title } : {}),
            ...(tech && tech.length ? { tech } : {}),
            ...(server ? { server } : {}),
        };
        out.push({ host: h, source: "import", ...(Object.keys(hint).length ? { hint } : {}) });
    }
    return out;
}

/** Parse a bare hosts list (one host/host:port/URL per line, '#' comments allowed) → candidates (no liveness hint). */
export function parseHostsList(text: string): HostCandidate[] {
    const out: HostCandidate[] = [];
    for (const line of text.split(/\r?\n/)) {
        const h = bareHost(line);
        if (h) out.push({ host: h, source: "import" });
    }
    return out;
}

/** Read + parse ONE file, auto-detecting httpx JSONL (first non-empty line is a JSON object) vs a plain hosts list. */
export function importReconFile(path: string): HostCandidate[] {
    let text: string;
    try {
        text = readFileSync(path, "utf8");
    } catch {
        return []; // unreadable → degrade to empty (never throw)
    }
    const firstLine = text.split(/\r?\n/).find((l) => l.trim().length > 0) ?? "";
    return firstLine.trim()[0] === "{" ? parseHttpxJsonl(text) : parseHostsList(text);
}

/** Import external recon from a file OR a directory (reads its *.json/*.jsonl/*.txt). Missing path → [] (degrade). */
export function importRecon(path: string): HostCandidate[] {
    try {
        if (statSync(path).isDirectory()) {
            const out: HostCandidate[] = [];
            for (const f of readdirSync(path)) if (/\.(jsonl?|txt)$/i.test(f)) out.push(...importReconFile(join(path, f)));
            return out;
        }
    } catch {
        return []; // missing path → degrade to empty
    }
    return importReconFile(path);
}
