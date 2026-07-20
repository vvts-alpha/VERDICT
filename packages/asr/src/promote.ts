// P3 selection — which discovered assets get promoted from wide-shallow ASR into a deep pilot run. Pure + unit-tested
// (VERDICT discipline). Never promote a dead / out-of-scope / third-party-hosted / takeover-only host: there is no
// first-party app to deep-pilot there. Ranked by the same score cmdAsr computes (band, then total, then host).

import type { Asset, AssetBand, AssetInventory } from "@veritas/core";

export interface PromoteOptions {
    /** Take the top-N ranked promotable hosts (default 5). */
    top?: number;
    /** Optional band floor — only promote hosts at/above this band (e.g. "high" skips medium/low). */
    minBand?: AssetBand;
}

const BAND_RANK: Record<AssetBand, number> = { critical: 3, high: 2, medium: 1, low: 0 };
const bandRank = (b: AssetBand | undefined): number => (b ? BAND_RANK[b] : 0);

/**
 * selectPromotable — the pilot-handoff gate. Keeps only assets that are a real, authorized, first-party app to pilot:
 * alive, in-scope, not third-party-hosted (SaaS carve-out) and not a takeover-only host (dangling CNAME → nothing to
 * pilot). Ranks by band → total → host (order-independent of the inventory's own sort), floors by `minBand`, and
 * returns the top-N as **live references** into `inventory.assets` so the caller can write `asset.promoted` back.
 */
export function selectPromotable(inventory: AssetInventory, opts: PromoteOptions = {}): Asset[] {
    const top = Math.max(0, opts.top ?? 5);
    const floor = opts.minBand ? BAND_RANK[opts.minBand] : -1;
    const eligible = inventory.assets.filter((a) => a.alive && a.inScope && !a.thirdPartyHosted && !a.takeover && bandRank(a.score?.band) >= floor);
    eligible.sort((x, y) => bandRank(y.score?.band) - bandRank(x.score?.band) || (y.score?.total ?? 0) - (x.score?.total ?? 0) || x.host.localeCompare(y.host));
    return eligible.slice(0, top);
}
