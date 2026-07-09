// ASR ④ SCORE (P0.5) — deterministic attack-target rubric. Rules only, no LLM; every component is visible so the
// operator can audit *why* a host ranks where it does (evidence-not-vibes). Works off the signals P0 collects
// (host-name tokens, HTTP status, title, Server header, scheme). Fuller path-based exposure + breadth land in P1;
// the AI triage layer (band adjust + attack angle) is P1 too — this is the reproducible backbone under it.
//
// Reachability gates everything: an unreachable host is not an attack target, so dead/no-DNS hosts score 0. That is
// what sinks the internal-only surface (the wellsfargo run: 28/40 hosts had no public DNS → all 0) automatically.

import type { Asset, AssetBand, AssetScore } from "@veritas/core";

// High-value host/title tokens — admin panels, internal tooling, auth/gateway, remote access.
const HIGH_VALUE = [
    "admin", "adminconsole", "webadmin", "manage", "console", "jenkins", "grafana", "kibana", "gitlab", "jira",
    "confluence", "phpmyadmin", "adminer", "sso", "vpn", "portal", "gateway", "api", "auth", "login", "oauth",
    "keycloak", "vault", "consul", "rabbitmq", "k8s", "kubernetes", "dashboard", "internal", "corp", "remote",
    "citrix", "owa", "exchange", "webmail", "cpanel", "router", "firewall", "jenkins", "nexus", "artifactory",
];
// Non-production markers — an externally-reachable one is a classic weak point (and a triage/scope flag).
const NONPROD = ["test", "uat", "dev", "staging", "stage", "sit", "qa", "preprod", "sandbox", "demo", "tmp"];
// Legacy / continuity markers.
const LEGACY = ["dr", "bcp", "backup", "legacy", "old", "deprecated", "archive"];
// Title fragments that signal a sensitive app.
const SENSITIVE_TITLE = [
    "login", "sign in", "log in", "admin", "dashboard", "jenkins", "grafana", "phpmyadmin", "kibana", "gitlab",
    "jira", "portal", "webmail", "control panel",
];
// Titles that reveal an unfinished/default install (a misconfig signal).
const DEFAULT_PAGE = [
    "welcome to nginx", "apache2 ubuntu default", "apache2 debian default", "iis windows", "test page for the apache",
    "it works", "welcome to caddy",
];
// Version-/tech-disclosing or dev-grade Server banners.
const RISKY_SERVER = [
    /apache\/(1\.|2\.[012])/i, /nginx\/1\.([0-9]|1[0-3])\b/i, /microsoft-iis\/[567]/i, /jetty/i, /tomcat|coyote/i,
    /werkzeug|gunicorn|flask/i, /php\//i, /openresty/i,
];

function tokensOf(host: string): Set<string> {
    return new Set(host.toLowerCase().split(/[.\-_]/).filter((t) => t.length > 0));
}
function hasAny(tokens: Set<string>, set: string[]): boolean {
    return set.some((t) => tokens.has(t));
}
function bandOf(total: number): AssetBand {
    return total >= 70 ? "critical" : total >= 50 ? "high" : total >= 30 ? "medium" : "low";
}

/**
 * Score one asset as an attack target (0–100 across five visible components) + a band. Auto-escalate signals
 * (only "directory listing" is detectable from P0 data; the /.git//.env/actuator set arrives with P1 path probing)
 * hard-set the band to critical regardless of the sum.
 */
export function scoreAsset(asset: Asset): AssetScore {
    const components: Record<string, number> = { sensitivity: 0, exposure: 0, weakness: 0, breadth: 0, anomaly: 0 };
    const autoEscalate: string[] = [];

    // A subdomain takeover is critical regardless of liveness — a dangling CNAME IS the vulnerability.
    if (asset.takeover?.vulnerable) {
        return {
            total: 100,
            band: "critical",
            components: { ...components, sensitivity: 40, exposure: 30 },
            autoEscalate: [`subdomain takeover: ${asset.takeover.service} (${asset.takeover.confidence})`],
        };
    }

    // Not reachable / out of scope → not an attack target.
    if (!asset.alive || asset.inScope === false || asset.thirdPartyHosted) {
        return { total: 0, band: "low", components, autoEscalate };
    }

    const tokens = tokensOf(asset.host);
    const title = (asset.title ?? "").toLowerCase();
    const server = asset.tech.join(" ").toLowerCase();
    const status = asset.status ?? 0;
    const nonprod = hasAny(tokens, NONPROD);

    // sensitivity (0–40)
    let sens = 0;
    if (hasAny(tokens, HIGH_VALUE)) sens += 22;
    if (SENSITIVE_TITLE.some((k) => title.includes(k))) sens += 12;
    if (status === 401 || status === 403) sens += 6; // gated but real app surface
    components.sensitivity = Math.min(40, sens);

    // exposure (0–30) — what's actually reachable/served, incl. P1 curated-path hits
    let exp = 0;
    if (title.includes("index of /")) {
        exp += 24;
        autoEscalate.push("directory listing (Index of /)");
    }
    if (status >= 200 && status < 300) exp += 10; // serves content unauthenticated
    if (nonprod && status !== 0) exp += 10; // externally-reachable non-production
    if (asset.scheme === "http") exp += 4; // plaintext reachable
    for (const h of asset.notablePaths ?? []) {
        if (h.escalate) {
            autoEscalate.push(`${h.note} (${h.path})`); // exposed source/secret/config → critical
            exp += 15;
        } else {
            exp += 6; // an info-disclosure / API-spec / mgmt path
        }
    }
    components.exposure = Math.min(30, exp);

    // weakness (0–20) — tech disclosure / default page / plaintext / server error
    let weak = 0;
    if (DEFAULT_PAGE.some((d) => title.includes(d))) weak += 12;
    if (RISKY_SERVER.some((re) => re.test(server))) weak += 8;
    else if (/\d/.test(server) && server.trim().length > 0) weak += 4; // any version-bearing banner
    if (asset.scheme === "http") weak += 3;
    if (status >= 500) weak += 4; // a surfaced server error
    components.weakness = Math.min(20, weak);

    // breadth (0–5) — endpoint/spec sources discovered by P1 surface probing (robots/sitemap/swagger/graphql…)
    const breadthSources = (asset.notablePaths ?? []).filter((h) =>
        /robots|sitemap|swagger|openapi|api-docs|graphql/i.test(h.path),
    );
    components.breadth = Math.min(5, breadthSources.length * 2);

    // anomaly (0–5) — non-prod / legacy-backup naming
    let anom = 0;
    if (nonprod) anom += 3;
    if (hasAny(tokens, LEGACY)) anom += 3;
    components.anomaly = Math.min(5, anom);

    const total = Math.min(
        100,
        components.sensitivity + components.exposure + components.weakness + components.breadth + components.anomaly,
    );
    return { total, band: autoEscalate.length > 0 ? "critical" : bandOf(total), components, autoEscalate };
}
