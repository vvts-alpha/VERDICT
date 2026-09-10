import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { DesktopSettings } from "./settings.js";

test("saving, reloading, and clearing context settings updates the next run without stale environment limits", async (t) => {
    const dir = mkdtempSync(join(tmpdir(), "verdict-settings-context-"));
    const handlers = new Map<string, (...args: unknown[]) => unknown>();
    t.mock.module("electron", { namedExports: {
        app: { getPath: () => dir },
        ipcMain: { handle: (name: string, fn: (...args: unknown[]) => unknown) => handlers.set(name, fn) },
    } });
    const { setupSettingsIpc, loadSettings, applyLlmSettingsToEnv } = await import("./settings.js");
    setupSettingsIpc();
    const save = (settings: DesktopSettings) => handlers.get("settings:set")!(undefined, settings) as DesktopSettings;
    try {
        save({ provider: "other", deepModel: "deep", lightModel: "light", deepContextTokens: 1_000_000, lightContextTokens: 128_000 });
        const restored = loadSettings();
        assert.equal(restored.deepContextTokens, 1_000_000);
        assert.equal(restored.lightContextTokens, 128_000);
        assert.equal(JSON.parse(readFileSync(join(dir, "settings.json"), "utf8")).lightContextTokens, 128_000);
        const env: NodeJS.ProcessEnv = {};
        applyLlmSettingsToEnv(restored, env);
        assert.equal(env.VERDICT_LLM_CONTEXT_TOKENS, "1000000");
        assert.equal(env.VERDICT_LLM_FAST_CONTEXT_TOKENS, "128000");
        assert.throws(() => save({ ...restored, lightContextTokens: -1 }), /Max context/);
        assert.equal(loadSettings().lightContextTokens, 128_000, "invalid input cannot overwrite saved settings");
        save({ provider: "other", deepModel: "deep" });
        applyLlmSettingsToEnv(loadSettings(), env);
        assert.equal(env.VERDICT_LLM_CONTEXT_TOKENS, undefined);
        assert.equal(env.VERDICT_LLM_FAST_CONTEXT_TOKENS, undefined);
    } finally { rmSync(dir, { recursive: true, force: true }); }
});
