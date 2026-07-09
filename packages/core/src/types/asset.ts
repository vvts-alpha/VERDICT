// ASR contract type — one discovered attack-surface asset (a host) and the run's asset inventory.
//
// This is a shared contract type (the WebUI reads it, types-only), so it lives in core like Screen/Finding.
// P0 populates the discovery + liveness subset; `score` (P0.5 deterministic rubric) and `ai` (P1 triage) are
// optional and filled by later slices — see docs/ASR.md.

export type AssetSource = "crt.sh" | "import" | "active" | "seed";

export type AssetBand = "critical" | "high" | "medium" | "low";

/** The deterministic attack-target score (P0.5) — visible components, never an opaque number. */
export interface AssetScore {
    total: number;
    band: AssetBand;
    /** Per-component sub-scores (sensitivity/exposure/weakness/breadth/anomaly), shown in the UI. */
    components: Record<string, number>;
    /** Signals that hard-escalate the band regardless of the sum (e.g. "readable /.git/HEAD"). */
    autoEscalate: string[];
}

/** The AI triage layer (P1) — a lead/prioritization, never a finding. */
export interface AssetTriage {
    category: string;
    band: AssetBand;
    rationale: string;
    /** Suggested first attack angle / pilot hypothesis. */
    angle: string;
}

/** One curated-path hit from P1 surface probing (a content-signature match, not a soft-404). */
export interface AssetPathHit {
    path: string;
    status: number;
    /** Short description of what the signature matched (e.g. "readable .git (HEAD)"). */
    note: string;
    /** True if this hit hard-escalates the host to critical (exposed source/secret/config). */
    escalate?: boolean;
}

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

/** One issue flagged from the recon state alone (no exploitation) — takeover, exposed source, listing, TLS, … */
export interface AssetFinding {
    /** Machine slug, e.g. "subdomain-takeover" | "exposed-source-secret" | "directory-listing". */
    category: string;
    severity: FindingSeverity;
    title: string;
    /** What it is + the next step (how to verify / turn into a report). */
    detail: string;
}

/** A subdomain-takeover signal: a dangling CNAME to an unclaimed third-party service. */
export interface AssetTakeover {
    /** The third-party service (e.g. "GitHub Pages", "AWS/S3"). */
    service: string;
    /** Whether this service is generally takeover-able (per can-i-take-over-xyz); some are edge-cases. */
    vulnerable: boolean;
    /** "likely" = fingerprint + matching CNAME; "potential" = fingerprint only, or a dangling CNAME. */
    confidence: "likely" | "potential";
    /** The CNAME target the subdomain points at, if resolved. */
    cname?: string;
    /** How to claim it (the takeover step). */
    note: string;
}

/** One entry in an enumerated directory listing (an open autoindex). Dirs may carry recursively-enumerated children. */
export interface ListingEntry {
    name: string;
    type: "dir" | "file";
    /** Absolute path on the host, e.g. "/backup/db.sql". */
    path: string;
    children?: ListingEntry[];
}

export interface Asset {
    /** Fully-qualified hostname. */
    host: string;
    source: AssetSource;
    /** Resolved IP addresses ([] = did not resolve). */
    resolved: string[];
    alive: boolean;
    scheme: string | null;
    status: number | null;
    title: string | null;
    /** Light tech signals (P0: the Server header; P1: fuller fingerprint). */
    tech: string[];
    /** Relative path under runs/<id>/artifacts/, e.g. "hosts/<host>.png"; null if not captured. */
    screenshot: string | null;
    inScope: boolean;
    /** A subdomain CNAME'd to a third-party SaaS — flagged and not probed (bug-bounty carve-out class). */
    thirdPartyHosted?: boolean;
    /** Curated high-signal paths found by P1 surface probing (`--paths`). */
    notablePaths?: AssetPathHit[];
    /** An enumerated open directory listing (root autoindex), if found (`--paths`). */
    listing?: ListingEntry[];
    /** A subdomain-takeover signal (dangling CNAME to an unclaimed third-party service). */
    takeover?: AssetTakeover;
    /** Recon-stage findings derived from the signals above (takeover, exposed paths, listing, …). */
    findings?: AssetFinding[];
    // — later slices —
    score?: AssetScore; // P0.5
    ai?: AssetTriage; // P1
    /** The assessmentId this asset was promoted into once piloted (P3). */
    promoted?: string | null;
}

/** The ASR run's asset inventory — the Phase-0 contract artifact (runs/<id>/asset_inventory.json). */
export interface AssetInventory {
    version: 1;
    generatedAt: string;
    /** The apex the run was scoped to, e.g. "example.com". */
    apex: string;
    assets: Asset[];
}
