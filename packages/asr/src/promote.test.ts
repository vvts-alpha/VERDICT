// S4 — the P3 promotion gate. selectPromotable must keep ONLY a real first-party app to pilot (alive + in-scope +
// not SaaS-hosted + not takeover-only), rank by the score cmdAsr computes, floor by band, cap to top-N, and return
// live refs into the inventory (so the caller can write asset.promoted back).

import { test } from "node:test";
import assert from "node:assert/strict";
import type { Asset, AssetBand, AssetInventory } from "@veritas/core";
import { selectPromotable } from "./index.js";

function asset(host: string, over: Partial<Asset> = {}): Asset {
    return { host, source: "crt.sh", resolved: ["1.2.3.4"], alive: true, scheme: "https", status: 200, title: null, tech: [], screenshot: null, inScope: true, ...over };
}
const score = (total: number, band: AssetBand) => ({ total, band, components: {}, autoEscalate: [] });
function inv(assets: Asset[]): AssetInventory {
    return { version: 1, generatedAt: "2026-01-01T00:00:00Z", apex: "example.com", assets };
}

test("selectPromotable: excludes dead / out-of-scope / third-party / takeover-only; keeps first-party live in-scope", () => {
    const out = selectPromotable(
        inv([
            asset("app.example.com", { score: score(50, "high") }),
            asset("dead.example.com", { alive: false, score: score(99, "critical") }),
            asset("saas.example.com", { thirdPartyHosted: true, score: score(99, "critical") }),
            asset("gone.example.com", { takeover: { service: "S3", vulnerable: true, confidence: "likely", note: "" }, score: score(99, "critical") }),
            asset("out.other.com", { inScope: false, score: score(99, "critical") }),
        ]),
    );
    assert.deepEqual(out.map((a) => a.host), ["app.example.com"]);
});

test("selectPromotable: ranks band → total → host (order-independent of the inventory's own order)", () => {
    const out = selectPromotable(
        inv([
            asset("low.example.com", { score: score(80, "medium") }),
            asset("crit.example.com", { score: score(10, "critical") }),
            asset("hi-b.example.com", { score: score(40, "high") }),
            asset("hi-a.example.com", { score: score(40, "high") }),
        ]),
    );
    // critical first (despite low total), then the two highs by host tiebreak, then medium
    assert.deepEqual(out.map((a) => a.host), ["crit.example.com", "hi-a.example.com", "hi-b.example.com", "low.example.com"]);
});

test("selectPromotable: top-N caps, minBand floors", () => {
    const list = inv([asset("a.example.com", { score: score(30, "high") }), asset("b.example.com", { score: score(20, "medium") }), asset("c.example.com", { score: score(10, "low") })]);
    assert.equal(selectPromotable(list, { top: 2 }).length, 2);
    assert.deepEqual(selectPromotable(list, { minBand: "high" }).map((a) => a.host), ["a.example.com"]); // medium/low floored out
});

test("selectPromotable: returns live refs — writing back promoted mutates the inventory asset", () => {
    const list = inv([asset("app.example.com", { score: score(50, "high") })]);
    const picked = selectPromotable(list);
    picked[0]!.promoted = "a-child-1";
    assert.equal(list.assets[0]?.promoted, "a-child-1");
});
