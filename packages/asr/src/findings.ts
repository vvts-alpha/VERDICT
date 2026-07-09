// ASR — recon-stage findings catalog. Derive the issues flaggable from the recon state alone (no exploitation) from
// an asset's collected signals: subdomain takeover, exposed source/secret, open directory listing, default install
// page, version disclosure, plaintext HTTP. Pure; extends as more signals (TLS, headers, CORS) get captured.

import type { Asset, AssetFinding, FindingSeverity, ListingEntry } from "@veritas/core";

function countEntries(entries: ListingEntry[]): number {
    let n = 0;
    for (const e of entries) {
        n += 1;
        if (e.children) n += countEntries(e.children);
    }
    return n;
}

function pathSeverity(note: string, escalate: boolean): FindingSeverity {
    if (escalate) return "critical";
    if (/actuator/i.test(note)) return "high";
    if (/swagger|openapi|api-docs|graphql/i.test(note)) return "medium";
    return "info";
}

const DEFAULT_PAGE_RE = /welcome to nginx|apache2 (ubuntu|debian) default|iis windows|test page for the apache|it works|welcome to caddy/i;

/** Derive the recon-stage findings for one asset from its collected signals. Recon only — no exploitation. */
export function reconFindings(asset: Asset): AssetFinding[] {
    const out: AssetFinding[] = [];
    if (asset.takeover) {
        const t = asset.takeover;
        out.push({
            category: "subdomain-takeover",
            severity: t.vulnerable ? (t.confidence === "likely" ? "critical" : "high") : "medium",
            title: `Possible subdomain takeover — ${t.service}`,
            detail: `${t.confidence}${t.cname ? ` · CNAME → ${t.cname}` : ""}. ${t.note}`,
        });
    }
    for (const h of asset.notablePaths ?? []) {
        out.push({
            category: h.escalate ? "exposed-source-secret" : "exposed-path",
            severity: pathSeverity(h.note, h.escalate === true),
            title: h.note,
            detail: `${h.path} → ${h.status}`,
        });
    }
    if (asset.listing?.length) {
        out.push({ category: "directory-listing", severity: "high", title: "Open directory listing", detail: `${countEntries(asset.listing)} entries enumerated (autoindex).` });
    }
    const title = asset.title ?? "";
    if (DEFAULT_PAGE_RE.test(title)) {
        out.push({ category: "default-install-page", severity: "low", title: "Default install page", detail: title });
    }
    const server = asset.tech.join(" ").trim();
    if (server.length > 0 && /\d/.test(server)) {
        out.push({ category: "version-disclosure", severity: "info", title: "Server version disclosed", detail: server });
    }
    if (asset.alive && asset.scheme === "http") {
        out.push({ category: "plaintext-http", severity: "low", title: "Served over plaintext HTTP", detail: "Live on http:// (no TLS)." });
    }
    return out;
}

const RANK: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** The highest severity among an asset's findings (for a summary badge), or null. */
export function topSeverity(findings: AssetFinding[]): FindingSeverity | null {
    let top: FindingSeverity | null = null;
    for (const f of findings) if (top === null || RANK[f.severity] > RANK[top]) top = f.severity;
    return top;
}
