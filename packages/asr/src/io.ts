// ASR ⑤ persistence — the asset inventory JSON (runs/<id>/asset_inventory.json), the Phase-0 contract artifact.
// Mirrors crawler/src/io.ts (writeScreenInventory). The Asset/AssetInventory contract types live in core.

import { readFileSync, writeFileSync } from "node:fs";

import type { Asset, AssetInventory } from "@veritas/core";

export function buildAssetInventory(
    apex: string,
    assets: Asset[],
    now: Date = new Date(),
    discovered?: number,
    degraded?: { reason: string },
    phase?: string,
): AssetInventory {
    return {
        version: 1,
        generatedAt: now.toISOString(),
        apex,
        ...(phase ? { phase } : {}),
        ...(discovered !== undefined ? { discovered } : {}),
        ...(degraded ? { degraded } : {}),
        assets,
    };
}

export function writeAssetInventory(path: string, inventory: AssetInventory): void {
    writeFileSync(path, JSON.stringify(inventory, null, 2) + "\n");
}

export function readAssetInventory(path: string): AssetInventory {
    return JSON.parse(readFileSync(path, "utf8")) as AssetInventory;
}
