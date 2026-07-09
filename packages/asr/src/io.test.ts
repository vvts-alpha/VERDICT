import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { buildAssetInventory, writeAssetInventory, readAssetInventory } from "./index.js";
import type { Asset } from "@veritas/core";

const asset = (over: Partial<Asset> = {}): Asset => ({
    host: "api.example.com",
    source: "crt.sh",
    resolved: ["203.0.113.4"],
    alive: true,
    scheme: "https",
    status: 200,
    title: "API",
    tech: ["nginx/1.18"],
    screenshot: "hosts/api.example.com.png",
    inScope: true,
    ...over,
});

const AT = new Date("2020-01-01T00:00:00Z");

test("buildAssetInventory: stamps version/apex/generatedAt and carries the assets", () => {
    const inv = buildAssetInventory("example.com", [asset()], AT);
    assert.equal(inv.version, 1);
    assert.equal(inv.apex, "example.com");
    assert.equal(inv.generatedAt, "2020-01-01T00:00:00.000Z");
    assert.equal(inv.assets.length, 1);
});

test("write/read round-trips the inventory (incl. a dead host)", () => {
    const dir = mkdtempSync(join(tmpdir(), "asr-io-"));
    try {
        const path = join(dir, "asset_inventory.json");
        const dead = asset({
            host: "gone.example.com",
            alive: false,
            resolved: [],
            scheme: null,
            status: null,
            title: null,
            tech: [],
            screenshot: null,
        });
        const inv = buildAssetInventory("example.com", [asset(), dead], AT);
        writeAssetInventory(path, inv);
        assert.deepEqual(readAssetInventory(path), inv);
    } finally {
        rmSync(dir, { recursive: true, force: true });
    }
});
