// Interactsh (ProjectDiscovery) OOB client — Collaborator-equivalent without Burp Pro.
// Protocol: RSA-2048 keypair + register → unique <correlation><nonce>.<server> hosts → poll + AES-CTR decrypt.
// Matches the public HTTP API (POST /register, GET /poll, POST /deregister). No real server in tests (fetch injected).
//
// Crypto (official interactsh storage.AESEncrypt / client.decryptMessage):
//   public-key  = base64(PEM of PKIX SPKI). Server ParsePKIXPublicKey ignores the PEM label, so
//                 Node's "BEGIN PUBLIC KEY" is fine (the Go client mislabels the same bytes "RSA PUBLIC KEY").
//   poll.aes_key = RSA-OAEP-SHA256(AES-256 key)
//   poll.data[]  = base64(IV[16] || AES-CTR(ciphertext))
// Poll is DESTRUCTIVE on the server (GetInteractions clears the bucket). We therefore (1) never drop
// rows on a client-side `since` clock (OAST timestamps are the server clock — skew would false-negative
// a real callback and the next poll would be empty) and (2) keep unmatched nonce hits in leftover so a
// poll({id: other}) cannot burn the callback probe_oob is waiting for.

import { generateKeyPairSync, privateDecrypt, randomBytes, createDecipheriv, constants, type KeyObject } from "node:crypto";
import type { OobInteraction, OobPayload, OobPollOpts, OobProvider } from "./oob.js";

export type FetchLike = (url: string, init?: RequestInit) => Promise<{
    ok: boolean;
    status: number;
    json: () => Promise<unknown>;
    text: () => Promise<string>;
}>;

const ALPHA = "abcdefghijklmnopqrstuvwxyz0123456789";
const CORRELATION_LEN = 20;
const NONCE_LEN = 13;
const SECRET_LEN = 20;
export const DEFAULT_INTERACTSH_SERVER = "oast.pro";

export interface InteractshOptions {
    /** Hostname or URL, e.g. oast.pro or https://oast.pro */
    server: string;
    /** Optional auth token for a protected / self-hosted server (Authorization header). */
    token?: string;
    fetchImpl?: FetchLike;
    correlationIdLength?: number;
    nonceLength?: number;
}

export interface ParsedInteractshServer {
    /** Hostname used in payload domains (no scheme). */
    host: string;
    /** API base, e.g. https://oast.pro */
    baseUrl: string;
}

export function parseInteractshServer(raw: string): ParsedInteractshServer {
    const s = raw.trim().replace(/\/+$/, "");
    if (!s) throw new Error("interactsh server is empty");
    if (/^https?:\/\//i.test(s)) {
        const u = new URL(s);
        return { host: u.hostname, baseUrl: `${u.protocol}//${u.host}` };
    }
    return { host: s, baseUrl: `https://${s}` };
}

function randomAlpha(n: number): string {
    const buf = randomBytes(n);
    let out = "";
    for (let i = 0; i < n; i++) out += ALPHA[buf[i]! % ALPHA.length];
    return out;
}

function aesCtrDecrypt(key: Buffer, blob: Buffer): Buffer {
    if (blob.length < 16) throw new Error("interactsh ciphertext too short");
    const iv = blob.subarray(0, 16);
    const body = blob.subarray(16);
    const bits = key.length * 8;
    if (bits !== 128 && bits !== 192 && bits !== 256) throw new Error(`unexpected AES key length ${key.length}`);
    const decipher = createDecipheriv(`aes-${bits}-ctr`, key, iv);
    return Buffer.concat([decipher.update(body), decipher.final()]);
}

function decodeAesKey(priv: KeyObject, aesKeyB64: string): Buffer {
    return privateDecrypt(
        { key: priv, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
        Buffer.from(aesKeyB64, "base64"),
    );
}

interface WireInteraction {
    protocol?: string;
    "unique-id"?: string;
    "full-id"?: string;
    "remote-address"?: string;
    timestamp?: string;
}

function extractNonce(correlationId: string, nonceLen: number, unique: string, full: string): string {
    const hay = unique.toLowerCase().startsWith(correlationId.toLowerCase()) ? unique : full || unique;
    const i = hay.toLowerCase().indexOf(correlationId.toLowerCase());
    if (i >= 0) {
        const n = hay.slice(i + correlationId.length, i + correlationId.length + nonceLen);
        if (n.length === nonceLen) return n;
    }
    return unique.slice(-nonceLen) || unique || full;
}

function toInteraction(raw: WireInteraction, nonce: string): OobInteraction | null {
    const unique = raw["unique-id"] ?? "";
    const full = raw["full-id"] ?? unique;
    const ts = raw.timestamp ? Date.parse(String(raw.timestamp)) : Date.now();
    const proto = (raw.protocol ?? "?").toUpperCase();
    const ip = raw["remote-address"];
    if (!full && !unique) return null;
    return { id: nonce, type: proto, time: Number.isFinite(ts) ? ts : Date.now(), ...(ip ? { clientIp: ip } : {}) };
}

function hitMatchesId(hit: OobInteraction, id: string): boolean {
    return hit.id === id || hit.id.startsWith(id);
}

function mergeHits(a: OobInteraction[], b: OobInteraction[]): OobInteraction[] {
    const out: OobInteraction[] = [];
    const seen = new Set<string>();
    for (const h of [...a, ...b]) {
        const k = `${h.id}|${h.type}|${h.time}|${h.clientIp ?? ""}`;
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(h);
    }
    return out;
}

export class InteractshOobProvider implements OobProvider {
    /** Hits decrypted from a poll that did not match the caller's nonce. Server poll is destructive. */
    private leftover: OobInteraction[] = [];
    readonly kind = "interactsh" as const;
    readonly serverHost: string;
    readonly correlationId: string;
    /** Exposed for tests that need to encrypt a matching poll payload. */
    readonly publicKeyPem: string;

    private constructor(
        private readonly baseUrl: string,
        private readonly token: string | undefined,
        private readonly fetchImpl: FetchLike,
        private readonly priv: KeyObject,
        publicKeyPem: string,
        correlationId: string,
        private readonly secret: string,
        serverHost: string,
        private readonly nonceLength: number,
    ) {
        this.publicKeyPem = publicKeyPem;
        this.correlationId = correlationId;
        this.serverHost = serverHost;
    }

    static async register(opts: InteractshOptions): Promise<InteractshOobProvider> {
        const parsed = parseInteractshServer(opts.server);
        const cidLen = opts.correlationIdLength ?? CORRELATION_LEN;
        const nonceLen = opts.nonceLength ?? NONCE_LEN;
        const correlationId = randomAlpha(cidLen);
        const secret = randomAlpha(SECRET_LEN);
        const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const publicKeyPem = pair.publicKey.export({ type: "spki", format: "pem" });
        if (typeof publicKeyPem !== "string") throw new Error("interactsh: unexpected public key export");
        const fetchImpl = opts.fetchImpl ?? (globalThis.fetch as FetchLike);
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (opts.token) headers.authorization = opts.token;
        const res = await fetchImpl(`${parsed.baseUrl}/register`, {
            method: "POST",
            headers,
            body: JSON.stringify({
                "public-key": Buffer.from(publicKeyPem).toString("base64"),
                "secret-key": secret,
                "correlation-id": correlationId,
            }),
        });
        if (!res.ok) {
            const body = await res.text().catch(() => "");
            throw new Error(`interactsh register failed: HTTP ${res.status}${body ? ` ${body.slice(0, 160)}` : ""}`);
        }
        return new InteractshOobProvider(
            parsed.baseUrl,
            opts.token,
            fetchImpl,
            pair.privateKey,
            publicKeyPem,
            correlationId,
            secret,
            parsed.host,
            nonceLen,
        );
    }

    async payload(): Promise<OobPayload> {
        const nonce = randomAlpha(this.nonceLength);
        return { host: `${this.correlationId}${nonce}.${this.serverHost}`, id: nonce };
    }

    async poll(opts: OobPollOpts = {}): Promise<OobInteraction[]> {
        const fetched = await this.fetchAndDecrypt();
        const merged = mergeHits(this.leftover, fetched);
        // `since` is a Collaborator watermark (local clock). Interactsh timestamps are the OAST
        // server's clock — filtering here would drop a real callback and, because poll is
        // destructive, the next loop would see an empty bucket. Correlation-id already isolates
        // the session; nonce (`opts.id`) isolates the payload.
        if (!opts.id) {
            this.leftover = [];
            return merged;
        }
        const matched = merged.filter((h) => hitMatchesId(h, opts.id!));
        this.leftover = merged.filter((h) => !hitMatchesId(h, opts.id!)).slice(-64);
        return matched;
    }

    private async fetchAndDecrypt(): Promise<OobInteraction[]> {
        const qs = new URLSearchParams({ id: this.correlationId, secret: this.secret });
        const headers: Record<string, string> = {};
        if (this.token) headers.authorization = this.token;
        const res = await this.fetchImpl(`${this.baseUrl}/poll?${qs.toString()}`, { headers });
        if (!res.ok) {
            if (res.status === 404) return []; // no interactions yet (some servers 404 an empty poll)
            throw new Error(`interactsh poll failed: HTTP ${res.status}`);
        }
        const j = (await res.json()) as { aes_key?: string; data?: string[] };
        if (!j.aes_key || !j.data?.length) return [];
        let aesKey: Buffer;
        try {
            aesKey = decodeAesKey(this.priv, j.aes_key);
        } catch (e) {
            throw new Error(`interactsh AES-key decrypt failed: ${String(e).slice(0, 120)}`);
        }
        const out: OobInteraction[] = [];
        for (const enc of j.data) {
            try {
                const plain = aesCtrDecrypt(aesKey, Buffer.from(enc, "base64")).toString("utf8");
                const raw = JSON.parse(plain) as WireInteraction;
                const nonce = extractNonce(this.correlationId, this.nonceLength, raw["unique-id"] ?? "", raw["full-id"] ?? "");
                const hit = toInteraction(raw, nonce);
                if (hit) out.push(hit);
            } catch {
                /* skip a single undecryptable row */
            }
        }
        return out;
    }

    async close(): Promise<void> {
        const headers: Record<string, string> = { "content-type": "application/json" };
        if (this.token) headers.authorization = this.token;
        try {
            await this.fetchImpl(`${this.baseUrl}/deregister`, {
                method: "POST",
                headers,
                body: JSON.stringify({ "correlation-id": this.correlationId, "secret-key": this.secret }),
            });
        } catch {
            /* best-effort */
        }
    }
}
