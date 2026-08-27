// Desktop settings — the in-app place to configure the LLM (provider / endpoint / key / Deep + Light models) and the
// automation browser path, so switching the AI is easy and no env juggling is needed (BYOK, self-contained). Persisted
// to userData/settings.json; mapped to the VERDICT_LLM_* / VERDICT_BROWSER_PATH env the child assessment processes read.

import { app, ipcMain } from "electron";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface DesktopSettings {
    /** "claude-cli" (Max subscription; needs the `claude` binary) or "openai" (any OpenAI-compatible endpoint incl. OpenCodeGo). */
    provider: "claude-cli" | "openai";
    /** openai: base URL, e.g. https://opencode.ai/zen/go/v1 */
    baseURL?: string;
    /** openai: API key (stored locally in userData; never leaves the machine). */
    apiKey?: string;
    /** Deep model — high-value diagnosis / scenario / deterministic path (VERDICT_LLM_MODEL). */
    deepModel?: string;
    /** Light model — survey / methodology / low-value screens (VERDICT_LLM_FAST_MODEL). */
    lightModel?: string;
    /** Chromium binary for automation (VERDICT_BROWSER_PATH). Blank = rely on the env / a bundled browser. */
    browserPath?: string;
    /** Upstream proxy for ALL traffic (browser + raw http), e.g. http://127.0.0.1:8080. Passed to pilot runs as --proxy. */
    proxy?: string;
}

const DEFAULTS: DesktopSettings = { provider: "claude-cli" };

function file(): string {
    return join(app.getPath("userData"), "settings.json");
}

export function loadSettings(): DesktopSettings {
    try {
        return { ...DEFAULTS, ...(JSON.parse(readFileSync(file(), "utf8")) as Partial<DesktopSettings>) };
    } catch {
        return { ...DEFAULTS };
    }
}

function saveSettings(s: DesktopSettings): DesktopSettings {
    const clean: DesktopSettings = { provider: s.provider === "openai" ? "openai" : "claude-cli" };
    for (const k of ["baseURL", "apiKey", "deepModel", "lightModel", "browserPath", "proxy"] as const) {
        const v = s[k];
        if (typeof v === "string" && v.trim()) clean[k] = v.trim();
    }
    writeFileSync(file(), `${JSON.stringify(clean, null, 2)}\n`);
    return clean;
}

/** Map settings to the env the child assessment processes read. Only NON-empty keys are emitted (so an unset field
 *  falls back to the app's own env / built-in defaults rather than clobbering it with "" ). */
export function settingsToEnv(s: DesktopSettings): Record<string, string> {
    const env: Record<string, string> = {};
    env.VERDICT_LLM_PROVIDER = s.provider;
    if (s.baseURL) env.VERDICT_LLM_BASE_URL = s.baseURL;
    if (s.apiKey) env.VERDICT_LLM_API_KEY = s.apiKey;
    if (s.deepModel) env.VERDICT_LLM_MODEL = s.deepModel;
    if (s.lightModel) env.VERDICT_LLM_FAST_MODEL = s.lightModel;
    if (s.browserPath) env.VERDICT_BROWSER_PATH = s.browserPath;
    if (s.proxy) env.VERDICT_PROXY = s.proxy; // the value; activation is via the --proxy arg the desktop appends (env alone never activates)
    return env;
}

/** Wire the get/set IPC the renderer's Settings panel uses. */
export function setupSettingsIpc(): void {
    ipcMain.handle("settings:get", () => loadSettings());
    ipcMain.handle("settings:set", (_e, s: DesktopSettings) => saveSettings(s));
}
