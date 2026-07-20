// S4 — the P3 handoff. buildPilotManifestFromAsset must PIN the ASR scope (never widen) + carry the triage angle;
// runFromAsr must select the right hosts, launch one pilot each (FakeLauncher — node:test spawns nothing), write
// asset.promoted back to the inventory, and honor top-N.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Asset, AssetBand, AssetInventory } from "@veritas/core";
import { buildPilotManifestFromAsset, runFromAsr } from "./from-asr.js";
import type { LaunchInput, PilotLauncher } from "./from-asr.js";

function asset(host: string, over: Partial<Asset> = {}): Asset {
    return { host, source: "crt.sh", resolved: ["1.2.3.4"], alive: true, scheme: "https", status: 200, title: null, tech: [], screenshot: null, inScope: true, ...over };
}
const score = (total: number, band: AssetBand) => ({ total, band, components: {}, autoEscalate: [] });
const PINS = { inScopeHosts: ["*.example.com"], outOfScopeHosts: ["*.blog.example.com"] };

function writeInv(assets: Asset[], extra: Partial<AssetInventory> = {}): string {
    const dir = mkdtempSync(join(tmpdir(), "fromasr-"));
    const invPath = join(dir, "asset_inventory.json");
    const inv: AssetInventory = { version: 1, generatedAt: "2026-01-01T00:00:00Z", apex: "example.com", discovered: assets.length, assets, ...extra };
    writeFileSync(invPath, JSON.stringify(inv));
    return invPath;
}

test("buildPilotManifestFromAsset: pins the ASR scope verbatim (never widens) + carries the trimmed triage angle", () => {
    const m = buildPilotManifestFromAsset(asset("api.example.com", { scheme: "http" }), PINS, "  S3 bucket exposed → try takeover  ");
    assert.equal(m.target, "http://api.example.com/");
    assert.equal(m.scopeMode, "etld");
    assert.deepEqual(m.scope.inScopeHosts, ["*.example.com"]);
    assert.deepEqual(m.scope.outOfScopeHosts, ["*.blog.example.com"]);
    assert.equal(m.lockToTargets, false);
    assert.equal(m.focus, "S3 bucket exposed → try takeover");
    // pins are copied, not aliased — mutating the manifest must not mutate the caller's boundary
    m.scope.inScopeHosts.push("*.evil.com");
    assert.deepEqual(PINS.inScopeHosts, ["*.example.com"]);
});

test("buildPilotManifestFromAsset: no angle → no focus; null scheme → https", () => {
    const m = buildPilotManifestFromAsset(asset("x.example.com", { scheme: null }), PINS);
    assert.equal(m.target, "https://x.example.com/");
    assert.equal(m.focus, undefined);
});

test("runFromAsr: selects promotable, launches one pilot per host with pinned scope, writes back promoted", async () => {
    const invPath = writeInv([
        asset("api.example.com", { score: score(90, "critical"), ai: { category: "api", band: "critical", rationale: "", angle: "auth bypass" } }),
        asset("app.example.com", { score: score(50, "high") }),
        asset("dead.example.com", { alive: false }),
        asset("saas.example.com", { thirdPartyHosted: true }),
        asset("gone.example.com", { takeover: { service: "S3", vulnerable: true, confidence: "likely", note: "" } }),
        asset("out.other.com", { inScope: false }),
    ]);
    const calls: LaunchInput[] = [];
    let n = 0;
    const fake: PilotLauncher = async (input) => {
        calls.push(input);
        return { ok: true };
    };
    const promoted = await runFromAsr({ invPath, runsDir: join(invPath, ".."), pins: PINS, top: 5, concurrency: 1, newId: () => `a-child-${++n}` }, fake, () => {});
    // only the two first-party live in-scope hosts, critical before high
    assert.deepEqual(calls.map((c) => c.manifest.target), ["https://api.example.com/", "https://app.example.com/"]);
    assert.deepEqual(calls[0]?.manifest.scope.inScopeHosts, ["*.example.com"]);
    assert.equal(calls[0]?.manifest.focus, "auth bypass"); // angle wired through
    assert.deepEqual(
        promoted.map((p) => [p.host, p.childId]),
        [
            ["api.example.com", "a-child-1"],
            ["app.example.com", "a-child-2"],
        ],
    );
    // write-back persisted
    const after = JSON.parse(readFileSync(invPath, "utf8")) as AssetInventory;
    assert.equal(after.assets.find((a) => a.host === "api.example.com")?.promoted, "a-child-1");
    assert.equal(after.assets.find((a) => a.host === "dead.example.com")?.promoted, undefined);
});

test("runFromAsr: top-N caps the promotion count", async () => {
    const invPath = writeInv(["a", "b", "c"].map((h, i) => asset(`${h}.example.com`, { score: score(10 - i, "high") })));
    const promoted = await runFromAsr({ invPath, runsDir: join(invPath, ".."), pins: PINS, top: 2, concurrency: 2, newId: (() => { let n = 0; return () => `c${++n}`; })() }, async () => ({ ok: true }), () => {});
    assert.equal(promoted.length, 2);
});

test("runFromAsr: nothing promotable → no launches, empty result", async () => {
    const invPath = writeInv([asset("dead.example.com", { alive: false }), asset("saas.example.com", { thirdPartyHosted: true })]);
    let launched = 0;
    const promoted = await runFromAsr({ invPath, runsDir: join(invPath, ".."), pins: PINS, top: 5, concurrency: 1, newId: () => "x" }, async () => { launched++; return { ok: true }; }, () => {});
    assert.equal(launched, 0);
    assert.equal(promoted.length, 0);
});
