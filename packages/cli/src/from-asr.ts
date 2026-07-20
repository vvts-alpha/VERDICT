// P3 — the wide→deep handoff. Turn ASR's ranked asset_inventory.json into deep pilot runs: select promotable hosts,
// build a pilot manifest that PINS the ASR authorization boundary (never widens on promotion), launch one pilot run
// per host (VERDICT's one-run-one-target grain), write asset.promoted back, and rewrite the inventory with the links.
// The launcher is INJECTED so node:test spawns no real pilot (FakeLauncher); production re-invokes this same CLI.

import { spawn } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

import type { Asset, AssetBand } from "@veritas/core";
import { buildAssetInventory, readAssetInventory, selectPromotable, writeAssetInventory } from "@veritas/asr";

/** The ASR run's authorization boundary — inherited verbatim by every promoted pilot (§2.4). Never widened. */
export interface AsrScopePins {
    inScopeHosts: string[];
    outOfScopeHosts: string[];
}

/** The pilot-manifest subset a promotion emits (a structural subset of the CLI's AssessManifest; serialized to manifest.json). */
export interface PilotManifest {
    target: string;
    scopeMode: "etld";
    scope: { inScopeHosts: string[]; outOfScopeHosts: string[] };
    lockToTargets: boolean;
    focus?: string;
}

/**
 * Build a pilot manifest from a promoted asset. The scope is PINNED to the ASR run's boundary (`*.${apex}` + the same
 * carve-outs) — promotion can only narrow authorization, never widen it. `focus` carries the AI-triage attack angle
 * (the payoff of the triage layer) into the pilot's top objective; lockToTargets:false lets the pilot survey THIS
 * host's app within the pinned apex scope. Pins are copied, not aliased.
 */
export function buildPilotManifestFromAsset(a: Asset, pins: AsrScopePins, angle?: string): PilotManifest {
    const scheme = a.scheme ?? "https";
    const focus = angle?.trim();
    return {
        target: `${scheme}://${a.host}/`,
        scopeMode: "etld",
        scope: { inScopeHosts: [...pins.inScopeHosts], outOfScopeHosts: [...pins.outOfScopeHosts] },
        lockToTargets: false,
        ...(focus ? { focus } : {}),
    };
}

export interface LaunchInput {
    manifest: PilotManifest;
    childId: string;
    runsDir: string;
}
/** Injected launcher: spawn one deep pilot run for a promoted host. FakeLauncher in tests. */
export type PilotLauncher = (input: LaunchInput) => Promise<{ ok: boolean }>;

/** Production launcher: write the child manifest, then re-invoke THIS CLI (dev or built) as `pilot --manifest --id --out`. */
export const spawnPilotLauncher: PilotLauncher = ({ manifest, childId, runsDir }) =>
    new Promise((resolve) => {
        mkdirSync(join(runsDir, childId), { recursive: true });
        const manifestPath = join(runsDir, childId, "manifest.json");
        writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
        // process.execArgv carries the tsx loader in dev ([] when built); process.argv[1] is this CLI's entry — so the
        // child runs the same code path in either mode. No shell: childId/paths are argv, never interpolated into a command line.
        // --disable-warning=ExperimentalWarning keeps node:sqlite's first-use warning out of the child's output (dev
        // execArgv already carries it via the tsx script; a duplicate flag is harmless — this covers the built CLI).
        const child = spawn(process.execPath, [...process.execArgv, "--disable-warning=ExperimentalWarning", process.argv[1] ?? "", "pilot", "--manifest", manifestPath, "--id", childId, "--out", runsDir], { stdio: "inherit" });
        child.on("error", () => resolve({ ok: false }));
        child.on("exit", (code) => resolve({ ok: code === 0 }));
    });

export interface FromAsrOptions {
    /** Path to the ASR run's asset_inventory.json. */
    invPath: string;
    runsDir: string;
    /** The ASR authorization boundary to pin (read by the caller from the ASR run's stored assessment). */
    pins: AsrScopePins;
    top: number;
    minBand?: AssetBand;
    concurrency: number;
    /** Injected id generator (deterministic in tests). */
    newId: () => string;
}

export interface PromotedLink {
    host: string;
    childId: string;
    ok: boolean;
}

/**
 * runFromAsr — select promotable hosts, launch one pilot per host (bounded concurrency), write asset.promoted back,
 * and rewrite asset_inventory.json with the links. Pure orchestration over the injected launcher; the only I/O it
 * owns is the inventory file. Returns the promotion links (host → childId, launch ok).
 */
export async function runFromAsr(opts: FromAsrOptions, launch: PilotLauncher, log: (m: string) => void = console.log): Promise<PromotedLink[]> {
    const inv = readAssetInventory(opts.invPath);
    const hosts = selectPromotable(inv, { top: opts.top, ...(opts.minBand ? { minBand: opts.minBand } : {}) });
    if (hosts.length === 0) {
        log("  from-asr: no promotable hosts (need alive + in-scope + first-party + non-takeover)");
        return [];
    }
    const conc = Math.max(1, Math.min(opts.concurrency, hosts.length));
    log(`  from-asr: promoting ${hosts.length} host(s) → pilot (concurrency ${conc}):`);
    const promoted: PromotedLink[] = [];
    let idx = 0;
    const worker = async (): Promise<void> => {
        for (;;) {
            const a = hosts[idx++]; // idx++ is synchronous between awaits → no race on the single JS thread
            if (!a) break;
            const childId = opts.newId();
            const manifest = buildPilotManifestFromAsset(a, opts.pins, a.ai?.angle);
            log(`    → ${a.host}  [${a.score?.band ?? "low"}]  ${childId}${manifest.focus ? `  focus: ${manifest.focus}` : ""}`);
            const r = await launch({ manifest, childId, runsDir: opts.runsDir });
            a.promoted = childId; // mutate the live inventory ref (selectPromotable returns refs into inv.assets)
            promoted.push({ host: a.host, childId, ok: r.ok });
        }
    };
    await Promise.all(Array.from({ length: conc }, () => worker()));
    writeAssetInventory(opts.invPath, buildAssetInventory(inv.apex, inv.assets, new Date(), inv.discovered));
    return promoted;
}
