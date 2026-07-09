import { test } from "node:test";
import assert from "node:assert/strict";

import { scoreAsset } from "./index.js";
import type { Asset } from "@veritas/core";

const mk = (o: Partial<Asset>): Asset => ({
    host: "x.example.com",
    source: "crt.sh",
    resolved: ["1.2.3.4"],
    alive: true,
    scheme: "https",
    status: 200,
    title: null,
    tech: [],
    screenshot: null,
    inScope: true,
    ...o,
});

test("reachability gates the score: a dead host is 0/low", () => {
    const s = scoreAsset(mk({ alive: false, resolved: [], status: null, scheme: null }));
    assert.equal(s.total, 0);
    assert.equal(s.band, "low");
    assert.deepEqual(s.components, { sensitivity: 0, exposure: 0, weakness: 0, breadth: 0, anomaly: 0 });
});

test("out-of-scope / third-party-hosted also scores 0 even when alive", () => {
    assert.equal(scoreAsset(mk({ inScope: false })).total, 0);
    assert.equal(scoreAsset(mk({ thirdPartyHosted: true })).total, 0);
});

test("high-value host + sensitive title + reachable non-prod → high band", () => {
    const s = scoreAsset(mk({ host: "grafana-dev.example.com", status: 200, title: "Grafana" }));
    // sensitivity 34 (host 22 + title 12), exposure 20 (200 +10, nonprod +10), anomaly 3 (nonprod)
    assert.equal(s.components.sensitivity, 34);
    assert.equal(s.components.exposure, 20);
    assert.equal(s.components.anomaly, 3);
    assert.equal(s.total, 57);
    assert.equal(s.band, "high");
});

test("directory listing auto-escalates the band to critical", () => {
    const s = scoreAsset(mk({ host: "files.example.com", title: "Index of /", status: 200 }));
    assert.ok(s.autoEscalate.includes("directory listing (Index of /)"));
    assert.equal(s.band, "critical");
    assert.equal(s.components.exposure, 30); // 24 + 10, capped at 30
});

test("default install page raises weakness", () => {
    const s = scoreAsset(mk({ host: "srv1.example.com", title: "Welcome to nginx!", tech: ["nginx/1.25.0"], scheme: "http" }));
    assert.equal(s.components.weakness, 19); // default page 12 + version banner 4 + http 3
    assert.equal(s.band, "medium");
});

test("an Akamai-gated 403 prod host stays low (honest: no deep signal yet)", () => {
    const s = scoreAsset(mk({ host: "acctagg.wellsfargo.com", status: 403, title: null }));
    assert.equal(s.components.sensitivity, 6); // 401/403 = real gated surface
    assert.equal(s.total, 6);
    assert.equal(s.band, "low");
});

test("a reachable non-prod host scores on exposure + anomaly", () => {
    const s = scoreAsset(mk({ host: "acctagg-test.wellsfargo.com", status: 400, title: null }));
    assert.equal(s.components.exposure, 10); // externally-reachable non-prod
    assert.equal(s.components.anomaly, 3);
    assert.equal(s.total, 13);
});

test("a curated-path hit (.git) drives exposure + auto-escalates to critical", () => {
    const s = scoreAsset(mk({
        host: "app.example.com",
        status: 200,
        notablePaths: [{ path: "/.git/HEAD", status: 200, note: "readable .git (HEAD)", escalate: true }],
    }));
    assert.ok(s.autoEscalate.some((x) => x.includes(".git")));
    assert.equal(s.band, "critical");
    assert.equal(s.components.exposure, 25); // 200 (+10) + .git escalate (+15)
});

test("breadth counts spec/endpoint sources from surface probing", () => {
    const s = scoreAsset(mk({
        host: "api.example.com",
        status: 200,
        notablePaths: [
            { path: "/swagger.json", status: 200, note: "OpenAPI/Swagger spec", escalate: false },
            { path: "/robots.txt", status: 200, note: "robots.txt", escalate: false },
        ],
    }));
    assert.equal(s.components.breadth, 4); // 2 sources * 2
});

test("total is the capped sum of the five visible components", () => {
    const s = scoreAsset(mk({ host: "admin-vpn.example.com", status: 200, title: "Login" }));
    const sum = Object.values(s.components).reduce((a, b) => a + b, 0);
    assert.equal(s.total, Math.min(100, sum));
    assert.ok(s.total <= 100);
});
