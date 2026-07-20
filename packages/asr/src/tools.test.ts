// S2 — external-tool discovery adapters. FakeRunTool injects canned stdout (zero real subprocess, VERDICT test discipline):
// parse, missing-binary degrade, and the T3MP3ST safety rule that argv is hardcoded (only the normalized apex interpolated).

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSubfinderJson, subfinderDiscover } from "./index.js";
import type { RunTool } from "./index.js";

test("parseSubfinderJson: -json lines → hosts; non-JSON / no-host lines skipped", () => {
    const out = parseSubfinderJson(
        [JSON.stringify({ host: "a.example.com", source: "crtsh" }), JSON.stringify({ host: "b.example.com" }), "not json", "", JSON.stringify({ nothost: "x" })].join("\n"),
    );
    assert.deepEqual(out.sort(), ["a.example.com", "b.example.com"]);
});

test("subfinderDiscover: stdout → import-tagged candidates", async () => {
    const rt: RunTool = async () => ({ ok: true, stdout: JSON.stringify({ host: "api.example.com" }) + "\n" + JSON.stringify({ host: "www.example.com" }) + "\n", stderr: "", missing: false });
    const r = await subfinderDiscover(rt, "example.com");
    assert.equal(r.missing, false);
    assert.deepEqual(r.candidates.map((c) => c.host).sort(), ["api.example.com", "www.example.com"]);
    assert.ok(r.candidates.every((c) => c.source === "import"));
});

test("subfinderDiscover: missing binary → { candidates: [], missing: true } (degrade, no throw)", async () => {
    const rt: RunTool = async () => ({ ok: false, stdout: "", stderr: "", missing: true });
    const r = await subfinderDiscover(rt, "example.com");
    assert.equal(r.missing, true);
    assert.equal(r.candidates.length, 0);
});

test("subfinderDiscover: argv is HARDCODED — only the apex is interpolated (no operator-supplied flags)", async () => {
    let captured: { bin: string; args: string[] } | null = null;
    const rt: RunTool = async (bin, args) => {
        captured = { bin, args };
        return { ok: true, stdout: "", stderr: "", missing: false };
    };
    await subfinderDiscover(rt, "example.com");
    assert.deepEqual(captured, { bin: "subfinder", args: ["-d", "example.com", "-all", "-silent", "-json"] });
});
