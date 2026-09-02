// Client for the OOB (Burp Collaborator) routes of the VERDICT Audit REST extension (same 1338).
// Used to confirm blind SSRF/XXE/SQLi/OS-command-injection etc. out-of-band:
//   ① oobPayload() issues a unique domain → VERDICT embeds it at the target's injection point
//   ② oobPoll() collects interactions (DNS/HTTP/SMTP callbacks) → if any arrive, it's confirmed
// conn is the same as Audit REST (same extension, same port). Wrapped as BurpOobProvider for probe_oob.

import type { BurpAuditConn } from "./burp-audit.js";
import type { OobInteraction, OobPayload, OobPollOpts, OobProvider } from "./oob.js";

export type { OobInteraction } from "./oob.js";

function url(conn: BurpAuditConn, path: string): string {
    return `${conn.base.replace(/\/+$/, "")}${path}`;
}
function headers(conn: BurpAuditConn): Record<string, string> {
    return conn.token ? { "X-Scan-Token": conn.token } : {};
}

/** Returns whether Collaborator is enabled on the Burp side. available=false means OOB is unavailable. */
export async function oobStatus(conn: BurpAuditConn): Promise<{ available: boolean; server: string; error?: string }> {
    const res = await fetch(url(conn, "/oob/status"), { headers: headers(conn) });
    if (!res.ok) throw new Error(`oob /status failed: ${res.status}`);
    const j = (await res.json()) as { available?: boolean; server?: string; error?: string };
    return { available: !!j.available, server: j.server ?? "", ...(j.error ? { error: j.error } : {}) };
}

/** Issue a unique OOB payload. host=the full domain to inject, id=the correlation key for interactions. */
export async function oobPayload(conn: BurpAuditConn): Promise<{ host: string; id: string }> {
    const res = await fetch(url(conn, "/oob/payload"), { method: "POST", headers: headers(conn) });
    if (!res.ok) throw new Error(`oob /payload failed: ${res.status} ${(await res.text().catch(() => "")).slice(0, 200)}`);
    const j = (await res.json()) as { host?: string; id?: string };
    if (!j.host || !j.id) throw new Error("oob /payload returned no host/id");
    return { host: j.host, id: j.id };
}

/** Collect interactions from Collaborator (filter by since=epoch ms onward / matching id). */
export async function oobPoll(conn: BurpAuditConn, opts: { since?: number; id?: string } = {}): Promise<OobInteraction[]> {
    const qs = new URLSearchParams();
    if (opts.since != null) qs.set("since", String(opts.since));
    if (opts.id) qs.set("id", opts.id);
    const res = await fetch(url(conn, `/oob/interactions${qs.toString() ? `?${qs}` : ""}`), { headers: headers(conn) });
    if (!res.ok) throw new Error(`oob /interactions failed: ${res.status}`);
    const j = (await res.json()) as { interactions?: Array<{ id?: string; type?: string; time?: number; client_ip?: string }> };
    return (j.interactions ?? []).map((i) => ({ id: i.id ?? "", type: i.type ?? "?", time: i.time ?? 0, ...(i.client_ip ? { clientIp: i.client_ip } : {}) }));
}

/** Collaborator via the Audit REST extension. Same conn as --burp-scan's authenticated path. */
export class BurpOobProvider implements OobProvider {
    readonly kind = "burp" as const;
    constructor(private readonly conn: BurpAuditConn) {}
    payload(): Promise<OobPayload> {
        return oobPayload(this.conn);
    }
    poll(opts: OobPollOpts = {}): Promise<OobInteraction[]> {
        return oobPoll(this.conn, opts);
    }
}
