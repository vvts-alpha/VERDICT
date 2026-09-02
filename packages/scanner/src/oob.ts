// Provider-pluggable OOB (out-of-band) confirmation. Blind SSRF/XXE/SQLi/CMDi are confirmed when the
// TARGET server calls back to a unique host we issued — not from a reflected response.
//
// Implementations: Burp Collaborator (Audit REST) and Interactsh (free / self-host). probe_oob talks
// only to this interface. Off by default; public Interactsh is opt-in third-party egress (like cve_lookup).

export interface OobInteraction {
    /** correlation key matching the id of the issued payload. */
    id: string;
    /** "DNS" | "HTTP" | "SMTP" | … */
    type: string;
    /** epoch ms. */
    time: number;
    /** IP of the target (the callback source). */
    clientIp?: string;
}

export interface OobPayload {
    /** Full hostname to inject at {{OOB}} (no scheme). */
    host: string;
    /** Correlation key for subsequent poll({ id }). */
    id: string;
}

export interface OobPollOpts {
    since?: number;
    id?: string;
}

export interface OobProvider {
    readonly kind: "burp" | "interactsh" | "fake";
    payload(): Promise<OobPayload>;
    poll(opts?: OobPollOpts): Promise<OobInteraction[]>;
    close?(): Promise<void>;
}

/** In-memory OOB for tests. No network. */
export class FakeOobProvider implements OobProvider {
    readonly kind = "fake" as const;
    host: string;
    id: string;
    hits: OobInteraction[];

    constructor(opts: { host?: string; id?: string; hits?: OobInteraction[] } = {}) {
        this.host = opts.host ?? "fake.oob.test";
        this.id = opts.id ?? "fakeid";
        this.hits = opts.hits ?? [];
    }

    async payload(): Promise<OobPayload> {
        return { host: this.host, id: this.id };
    }

    async poll(opts: OobPollOpts = {}): Promise<OobInteraction[]> {
        // Scripted hits are the oracle. `since` is a Collaborator-style watermark — ignore it so a hit
        // recorded before payload() still confirms. Filter by id when the caller asks.
        let out = this.hits;
        if (opts.id) out = out.filter((h) => !h.id || h.id === opts.id);
        return out;
    }
}
