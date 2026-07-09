import { test } from "node:test";
import assert from "node:assert/strict";

import { probeHost, extractTitle, type ProbeResponse } from "./index.js";

const OK = (over: Partial<ProbeResponse> = {}): ProbeResponse => ({
    status: 200,
    headers: { server: "nginx/1.18" },
    body: "<html><head><title>  Sign  in </title></head></html>",
    finalUrl: "https://x/",
    ...over,
});

test("probeHost: resolves + HTTPS responds → alive, scheme=https, status/title/server captured", async () => {
    const p = await probeHost("api.example.com", async () => ["203.0.113.4"], async (url) => {
        assert.equal(url, "https://api.example.com/");
        return OK();
    });
    assert.deepEqual(p, {
        host: "api.example.com",
        addresses: ["203.0.113.4"],
        cnames: [],
        alive: true,
        scheme: "https",
        status: 200,
        title: "Sign in",
        server: "nginx/1.18",
        bodySample: "<html><head><title>  Sign  in </title></head></html>",
    });
});

test("probeHost: NXDOMAIN (resolver → []) → alive:false, never hits the network", async () => {
    let called = false;
    const p = await probeHost("gone.example.com", async () => [], async () => {
        called = true;
        return OK();
    });
    assert.equal(called, false, "must not probe a host that doesn't resolve");
    assert.equal(p.alive, false);
    assert.deepEqual(p.addresses, []);
    assert.equal(p.scheme, null);
});

test("probeHost: HTTPS transport error → falls back to HTTP", async () => {
    const p = await probeHost("legacy.example.com", async () => ["203.0.113.5"], async (url) => {
        if (url.startsWith("https://")) throw new Error("ECONNREFUSED");
        return OK({ status: 403, headers: {}, finalUrl: "http://x/" });
    });
    assert.equal(p.alive, true);
    assert.equal(p.scheme, "http");
    assert.equal(p.status, 403);
    assert.equal(p.server, null);
});

test("probeHost: resolves but both schemes error → alive:false", async () => {
    const p = await probeHost("dark.example.com", async () => ["203.0.113.6"], async () => {
        throw new Error("ETIMEDOUT");
    });
    assert.equal(p.alive, false);
    assert.deepEqual(p.addresses, ["203.0.113.6"]);
});

test("probeHost: 401 still counts as alive (a live host behind auth)", async () => {
    const p = await probeHost("admin.example.com", async () => ["203.0.113.7"], async () =>
        OK({ status: 401, body: "<html></html>" }),
    );
    assert.equal(p.alive, true);
    assert.equal(p.status, 401);
    assert.equal(p.title, null);
});

test("extractTitle: collapses whitespace, caps length, null when absent", () => {
    assert.equal(extractTitle("<title>\n  Hello   World\t</title>"), "Hello World");
    assert.equal(extractTitle("<html>no title here</html>"), null);
    assert.equal(extractTitle(`<title>${"x".repeat(500)}</title>`)?.length, 200);
});
