// S2 — external-tool discovery adapters. FakeRunTool injects canned stdout (zero real subprocess, VERDICT test discipline):
// parse, missing-binary degrade, and the T3MP3ST safety rule that argv is hardcoded (only the normalized apex interpolated).

import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSubfinderJson, subfinderDiscover, dnsxBrute } from "./index.js";
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

test("dnsxBrute: stdout → active-tagged candidates; argv hardcoded (apex + operator file paths only)", async () => {
    let captured: { bin: string; args: string[] } | null = null;
    const rt: RunTool = async (bin, args) => {
        captured = { bin, args };
        return { ok: true, stdout: JSON.stringify({ host: "dev.example.com", a: ["1.2.3.4"] }) + "\n", stderr: "", missing: false };
    };
    const r = await dnsxBrute(rt, "example.com", { wordlist: "/wl.txt", resolvers: "/res.txt" });
    assert.equal(r.missing, false);
    assert.deepEqual(r.candidates, [{ host: "dev.example.com", source: "active" }]);
    assert.deepEqual(captured, { bin: "dnsx", args: ["-d", "example.com", "-w", "/wl.txt", "-r", "/res.txt", "-a", "-silent", "-json"] });
});

test("dnsxBrute: no resolvers → -r omitted; missing binary → degrade (caller falls back to native)", async () => {
    let captured: string[] = [];
    const rt: RunTool = async (_bin, args) => {
        captured = args;
        return { ok: true, stdout: "", stderr: "", missing: false };
    };
    await dnsxBrute(rt, "example.com", { wordlist: "/wl.txt" });
    assert.deepEqual(captured, ["-d", "example.com", "-w", "/wl.txt", "-a", "-silent", "-json"]); // no -r

    const missingRt: RunTool = async () => ({ ok: false, stdout: "", stderr: "", missing: true });
    const r = await dnsxBrute(missingRt, "example.com", { wordlist: "/wl.txt" });
    assert.equal(r.missing, true);
    assert.equal(r.candidates.length, 0);
});

test("dnsxBrute: binary present but ERRORED (timeout / bad resolvers) → failed:true, not missing (caller falls back to native)", async () => {
    const erroredRt: RunTool = async () => ({ ok: false, stdout: "", stderr: "timeout", missing: false }); // ran, non-zero exit
    const r = await dnsxBrute(erroredRt, "example.com", { wordlist: "/wl.txt" });
    assert.equal(r.missing, false);
    assert.equal(r.failed, true);
    assert.equal(r.candidates.length, 0);
});
