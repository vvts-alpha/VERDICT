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
    /** Upstream proxy for ALL traffic (browser + raw http), e.g. http://127.0.0.1:8080. Passed to pilot runs as --proxy.
     *  To route through Burp, set this to Burp's proxy listener. */
    proxy?: string;
    /** Burp: run a post-diagnosis Burp active scan on each run (adds --burp-scan). Needs a REST/Audit endpoint below. */
    burpScan?: boolean;
    /** Burp Pro REST API base URL, e.g. http://127.0.0.1:1337 (BURP_API). */
    burpApi?: string;
    /** Burp Pro REST API key (BURP_API_KEY). */
    burpApiKey?: string;
    /** Burp resource pool name (BURP_RESOURCE_POOL). */
    burpResourcePool?: string;
    /** VERDICT Audit REST extension URL, e.g. http://127.0.0.1:1338 — scans behind login by submitting the authed
     *  raw requests (BURP_AUDIT_API). Preferred over the plain REST API for authenticated targets. */
    burpAuditApi?: string;
    /** VERDICT Audit REST token (BURP_AUDIT_TOKEN). */
    burpAuditToken?: string;
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
    for (const k of ["baseURL", "apiKey", "deepModel", "lightModel", "browserPath", "proxy", "burpApi", "burpApiKey", "burpResourcePool", "burpAuditApi", "burpAuditToken"] as const) {
        const v = s[k];
        if (typeof v === "string" && v.trim()) clean[k] = v.trim();
    }
    if (s.burpScan) clean.burpScan = true;
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
    // Burp: the connection is read from env by the burp-scan phase; --burp-scan (appended as a child arg) enables it.
    if (s.burpApi) env.BURP_API = s.burpApi;
    if (s.burpApiKey) env.BURP_API_KEY = s.burpApiKey;
    if (s.burpResourcePool) env.BURP_RESOURCE_POOL = s.burpResourcePool;
    if (s.burpAuditApi) env.BURP_AUDIT_API = s.burpAuditApi;
    if (s.burpAuditToken) env.BURP_AUDIT_TOKEN = s.burpAuditToken;
    return env;
}

/** Wire the get/set IPC the renderer's Settings panel uses. */
export function setupSettingsIpc(): void {
    ipcMain.handle("settings:get", () => loadSettings());
    ipcMain.handle("settings:set", (_e, s: DesktopSettings) => saveSettings(s));
}
