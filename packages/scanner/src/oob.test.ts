// Interactsh client + OOB resolver. No real OAST server — fetch is injected.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { createCipheriv, publicEncrypt, randomBytes, constants } from "node:crypto";
import { InteractshOobProvider, parseInteractshServer, DEFAULT_INTERACTSH_SERVER } from "./oob-interactsh.js";
import { resolveOobProvider } from "./oob-resolve.js";
import { FakeOobProvider } from "./oob.js";
import { BurpOobProvider } from "./burp-oob.js";
import type { FetchLike } from "./oob-interactsh.js";

function encryptPoll(publicKeyPem: string, aesKey: Buffer, interaction: object): { aes_key: string; data: string[] } {
    const iv = randomBytes(16);
    const bits = aesKey.length * 8;
    const cipher = createCipheriv(`aes-${bits}-ctr`, aesKey, iv);
    const body = Buffer.concat([cipher.update(JSON.stringify(interaction), "utf8"), cipher.final()]);
    const blob = Buffer.concat([iv, body]);
    const encKey = publicEncrypt({ key: publicKeyPem, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" }, aesKey);
    return { aes_key: encKey.toString("base64"), data: [blob.toString("base64")] };
}

test("parseInteractshServer strips scheme and trailing slash", () => {
    assert.deepEqual(parseInteractshServer("oast.pro"), { host: "oast.pro", baseUrl: "https://oast.pro" });
    assert.deepEqual(parseInteractshServer("https://oast.fun/"), { host: "oast.fun", baseUrl: "https://oast.fun" });
    assert.deepEqual(parseInteractshServer("http://127.0.0.1:8082"), { host: "127.0.0.1", baseUrl: "http://127.0.0.1:8082" });
    assert.equal(DEFAULT_INTERACTSH_SERVER, "oast.pro");
});

test("InteractshOobProvider register → payload host is correlation+nonce.server, poll decrypts AES-CTR", async () => {
    let registered: { publicKey?: string; secret?: string; correlation?: string } = {};
    let pollUrl = "";
    let clientPub = "";
    const fetchImpl: FetchLike = async (url, init) => {
        if (url.endsWith("/register") && init?.method === "POST") {
            const body = JSON.parse(String(init.body)) as { "public-key": string; "secret-key": string; "correlation-id": string };
            registered = { publicKey: body["public-key"], secret: body["secret-key"], correlation: body["correlation-id"] };
            clientPub = Buffer.from(body["public-key"], "base64").toString("utf8");
            return { ok: true, status: 200, json: async () => ({}), text: async () => "ok" };
        }
        if (url.includes("/poll?")) {
            pollUrl = url;
            const aesKey = randomBytes(16);
            const corr = registered.correlation ?? "";
            const nonce = "n".repeat(13);
            const wire = encryptPoll(clientPub, aesKey, {
                protocol: "dns",
                "unique-id": `${corr}${nonce}`,
                "full-id": `${corr}${nonce}.oast.pro`,
                "remote-address": "203.0.113.9",
                timestamp: "2026-09-01T00:00:00.000Z",
            });
            return { ok: true, status: 200, json: async () => wire, text: async () => JSON.stringify(wire) };
        }
        if (url.endsWith("/deregister")) return { ok: true, status: 200, json: async () => ({}), text: async () => "" };
        throw new Error(`unexpected fetch ${url}`);
    };
    const oob = await InteractshOobProvider.register({ server: "oast.pro", fetchImpl });
    assert.equal(registered.correlation?.length, 20);
    assert.equal(registered.secret?.length, 20);
    assert.match(registered.publicKey ?? "", /^[A-Za-z0-9+/=]+$/);
    const p = await oob.payload();
    assert.match(p.host, new RegExp(`^${oob.correlationId}[a-z0-9]{13}\\.oast\\.pro$`));
    assert.equal(p.id.length, 13);
    const hits = await oob.poll();
    assert.equal(hits.length, 1);
    assert.equal(hits[0]!.type, "DNS");
    assert.equal(hits[0]!.clientIp, "203.0.113.9");
    assert.equal(hits[0]!.id, "n".repeat(13));
    assert.match(pollUrl, /[?&]id=/);
    await oob.close();
});

test("Interactsh poll filters by payload nonce id and keeps unmatched hits after a destructive poll", async () => {
    let clientPub = "";
    let correlation = "";
    let remaining: { aes_key: string; data: string[] } | undefined;
    let minted = false;
    const fetchImpl: FetchLike = async (url, init) => {
        if (url.endsWith("/register")) {
            const body = JSON.parse(String(init?.body)) as { "public-key": string; "correlation-id": string };
            clientPub = Buffer.from(body["public-key"], "base64").toString("utf8");
            correlation = body["correlation-id"];
            return { ok: true, status: 200, json: async () => ({}), text: async () => "ok" };
        }
        if (url.includes("/poll?")) {
            if (!minted) {
                minted = true;
                remaining = encryptPoll(clientPub, randomBytes(16), {
                    protocol: "http",
                    "unique-id": `${correlation}aaaaaaaaaaaaa`,
                    timestamp: "2026-09-01T00:00:00.000Z",
                });
            }
            const payload = remaining;
            remaining = undefined; // server GetInteractions clears the bucket
            return { ok: true, status: 200, json: async () => payload ?? { data: [] }, text: async () => "" };
        }
        return { ok: true, status: 200, json: async () => ({}), text: async () => "" };
    };
    const oob = await InteractshOobProvider.register({ server: "https://oast.fun", fetchImpl });
    const miss = await oob.poll({ id: "bbbbbbbbbbbbb" });
    assert.equal(miss.length, 0);
    // Second poll: server is empty, leftover from the first poll must still yield the nonce-A hit.
    const hit = await oob.poll({ id: "aaaaaaaaaaaaa" });
    assert.equal(hit.length, 1);
    assert.equal(hit[0]!.type, "HTTP");
});

test("Interactsh poll does not drop hits on a client-side since watermark (OAST clock skew)", async () => {
    let clientPub = "";
    let correlation = "";
    const nonce = "n".repeat(13);
    const fetchImpl: FetchLike = async (url, init) => {
        if (url.endsWith("/register")) {
            const body = JSON.parse(String(init?.body)) as { "public-key": string; "correlation-id": string };
            clientPub = Buffer.from(body["public-key"], "base64").toString("utf8");
            correlation = body["correlation-id"];
            return { ok: true, status: 200, json: async () => ({}), text: async () => "ok" };
        }
        if (url.includes("/poll?")) {
            const aesKey = randomBytes(32);
            const wire = encryptPoll(clientPub, aesKey, {
                protocol: "dns",
                "unique-id": `${correlation}${nonce}.oast.pro`,
                "full-id": `${correlation}${nonce}.oast.pro`,
                timestamp: "2020-01-01T00:00:00.000Z",
            });
            return { ok: true, status: 200, json: async () => wire, text: async () => "" };
        }
        return { ok: true, status: 200, json: async () => ({}), text: async () => "" };
    };
    const oob = await InteractshOobProvider.register({ server: "oast.pro", fetchImpl });
    const hits = await oob.poll({ since: Date.now(), id: nonce });
    assert.equal(hits.length, 1);
    assert.equal(hits[0]!.id, nonce);
    assert.equal(hits[0]!.type, "DNS");
});

test("resolveOobProvider: empty env → null; none wins over BURP_AUDIT_API; burp uses audit URL", async () => {
    assert.equal(await resolveOobProvider({}), null);
    assert.equal(await resolveOobProvider({ BURP_AUDIT_API: "http://127.0.0.1:1338" }, { mode: "none" }), null);
    const burp = await resolveOobProvider({ BURP_AUDIT_API: "http://127.0.0.1:1338", BURP_AUDIT_TOKEN: "t" });
    assert.ok(burp instanceof BurpOobProvider);
    assert.equal(burp?.kind, "burp");
});

test("resolveOobProvider: VERDICT_OOB=interactsh registers against INTERACTSH_SERVER (no public default without opt-in)", async () => {
    let saw = "";
    const fetchImpl: FetchLike = async (url) => {
        saw = url;
        return { ok: true, status: 200, json: async () => ({}), text: async () => "ok" };
    };
    const oob = await resolveOobProvider({ VERDICT_OOB: "interactsh", INTERACTSH_SERVER: "https://oob.example.test" }, { fetchImpl });
    assert.equal(oob?.kind, "interactsh");
    assert.match(saw, /^https:\/\/oob\.example\.test\/register$/);
});

test("FakeOobProvider returns scripted hits", async () => {
    const fake = new FakeOobProvider({
        host: "x.oob.test",
        id: "abc",
        hits: [{ id: "abc", type: "DNS", time: 1, clientIp: "1.2.3.4" }],
    });
    const p = await fake.payload();
    assert.equal(p.host, "x.oob.test");
    const hits = await fake.poll({ id: "abc" });
    assert.equal(hits[0]!.type, "DNS");
    assert.equal((await fake.poll({ id: "nope" })).length, 0);
});
