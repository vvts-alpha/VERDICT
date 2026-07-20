// S3 — the native DNS-brute fallback. Inject a fake Resolve4 (zero real DNS, VERDICT no-network-in-test discipline):
// assert wordlist expansion (<word>.<apex>), NXDOMAIN → dropped, sanitization of hostile labels, concurrency bound,
// and the parseWordlist file parser.

import { test } from "node:test";
import assert from "node:assert/strict";
import { nativeBrute, parseWordlist, DEFAULT_SUBDOMAIN_WORDLIST } from "./index.js";
import type { Resolve4 } from "./index.js";

test("nativeBrute: resolves <word>.<apex>, keeps only resolving names (NXDOMAIN → dropped), active-tagged + sorted", async () => {
    const live = new Set(["www.example.com", "api.example.com"]);
    const resolve4: Resolve4 = async (host) => (live.has(host) ? ["1.2.3.4"] : []); // [] = did not resolve
    const out = await nativeBrute(resolve4, "example.com", ["api", "www", "nope", "ghost"]);
    assert.deepEqual(out, [
        { host: "api.example.com", source: "active" },
        { host: "www.example.com", source: "active" },
    ]);
});

test("nativeBrute: a rejecting resolver (SERVFAIL/timeout) drops the name, never throws", async () => {
    const resolve4: Resolve4 = async (host) => {
        if (host === "ok.example.com") return ["9.9.9.9"];
        throw new Error("SERVFAIL");
    };
    const out = await nativeBrute(resolve4, "example.com", ["ok", "boom"]);
    assert.deepEqual(out.map((c) => c.host), ["ok.example.com"]);
});

test("nativeBrute: sanitizes/dedupes labels — a hostile wordlist line can't smuggle anything into the query", async () => {
    const queried: string[] = [];
    const resolve4: Resolve4 = async (host) => {
        queried.push(host);
        return [];
    };
    await nativeBrute(resolve4, "example.com", ["api", "API", " api ", "bad label", "ev!l", "a.b", "", "ok-1"]);
    // "api"/"API"/" api " collapse to one; "bad label"/"ev!l"/"a.b"/"" are rejected; "ok-1" kept
    assert.deepEqual([...queried].sort(), ["api.example.com", "ok-1.example.com"]);
});

test("nativeBrute: honors the concurrency bound (never more than N in flight)", async () => {
    let inFlight = 0;
    let peak = 0;
    const resolve4: Resolve4 = async (host) => {
        inFlight++;
        peak = Math.max(peak, inFlight);
        await Promise.resolve();
        await Promise.resolve();
        inFlight--;
        return host.startsWith("w") ? ["1.1.1.1"] : [];
    };
    const words = Array.from({ length: 30 }, (_, i) => `w${i}`);
    const out = await nativeBrute(resolve4, "example.com", words, { concurrency: 4 });
    assert.ok(peak <= 4, `peak concurrency ${peak} exceeded 4`);
    assert.equal(out.length, 30);
});

test("parseWordlist: lowercases + dedupes, drops # comments / blanks / invalid labels", () => {
    const words = parseWordlist(["# a comment", "", "www", "API", "api", "  dev  ", "bad label", "ok_underscore", "x.y"].join("\n"));
    assert.deepEqual(words.sort(), ["api", "dev", "ok_underscore", "www"]);
});

test("bundled wordlist is non-trivial and clean (all valid DNS labels, deduped)", () => {
    assert.ok(DEFAULT_SUBDOMAIN_WORDLIST.length >= 100, `expected ~100 words, got ${DEFAULT_SUBDOMAIN_WORDLIST.length}`);
    assert.equal(new Set(DEFAULT_SUBDOMAIN_WORDLIST).size, DEFAULT_SUBDOMAIN_WORDLIST.length, "wordlist has duplicates");
    assert.ok(
        DEFAULT_SUBDOMAIN_WORDLIST.every((w) => /^[a-z0-9_-]+$/.test(w)),
        "wordlist has a non-label entry",
    );
});
