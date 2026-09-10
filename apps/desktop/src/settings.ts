// Desktop settings — the in-app place to configure the LLM (provider / endpoint / key / Deep + Light models) and the
// automation browser path, so switching the AI is easy and no env juggling is needed (BYOK, self-contained). Persisted
// to userData/settings.json; mapped to the VERDICT_LLM_* / VERDICT_BROWSER_PATH env the child assessment processes read.

import { checkReadiness } from "@veritas/server";
import { parseContextTokens, type ModelContextSettings } from "@veritas/core/llm-context";
import { app, ipcMain } from "electron";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { MODEL_PROVIDERS, normalizeModelProvider, modelConnectionEnv, type ModelProvider } from "./model-providers.js";

export interface DesktopSettings extends ModelContextSettings {
    /** Named service selection; non-Claude services use the OpenAI-compatible transport. */
    provider: ModelProvider;
    /** openai: base URL, e.g. https://opencode.ai/zen/go/v1 */
    baseURL?: string;
    /** API key, stored locally and sent to the configured provider for authentication. */
    apiKey?: string;
    /** Deep model — high-value diagnosis / scenario / deterministic path (VERDICT_LLM_MODEL). */
    deepModel?: string;
    /** Light model — survey / methodology / low-value screens (VERDICT_LLM_FAST_MODEL). */
    lightModel?: string;
    /** Chromium binary for automation (VERDICT_BROWSER_PATH). Blank = installed Chrome/Edge, else Playwright's bundle. */
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
    /** OOB for blind SSRF/XXE: off | interactsh (free, opt-in public/self-host) | burp (Collaborator via Audit REST). */
    oobProvider?: "off" | "interactsh" | "burp";
    /** Interactsh server hostname or URL (INTERACTSH_SERVER). Blank + interactsh = oast.pro. */
    interactshServer?: string;
    /** Token for a protected Interactsh server (INTERACTSH_TOKEN). */
    interactshToken?: string;
    /** Standing FACTS about your targets (auth shape, tenant model, where the API lives). Pre-fills the New form's
     *  "Operator context" on new runs (the per-run value overrides), and is appended to every stage's system prompt as
     *  --context. Additive only: it guides the agent, never overrides safety / scope / evidence-discipline. */
    operatorContext?: string;
}

const DEFAULTS: DesktopSettings = { provider: "claude-cli" };

function file(): string {
    return join(app.getPath("userData"), "settings.json");
}

/** Installed Chrome/Edge/Chromium — Playwright's bundled chromium_headless_shell is not shipped in the desktop app. */
export function detectSystemChromium(): string | undefined {
    const env = process.env;
    const candidates: string[] = [];
    if (process.platform === "win32") {
        const pf = env.PROGRAMFILES ?? "C:\\Program Files";
        const pf86 = env["PROGRAMFILES(X86)"] ?? "C:\\Program Files (x86)";
        const local = env.LOCALAPPDATA ?? "";
        candidates.push(
            join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            join(local, "Google", "Chrome", "Application", "chrome.exe"),
            join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
        );
    } else if (process.platform === "darwin") {
        candidates.push(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
        );
    } else {
        candidates.push(
            "/usr/bin/google-chrome-stable",
            "/usr/bin/google-chrome",
            "/usr/bin/chromium-browser",
            "/usr/bin/chromium",
            "/usr/bin/microsoft-edge",
            "/snap/bin/chromium",
        );
    }
    return candidates.find((p) => p.length > 0 && existsSync(p));
}

export function loadSettings(): DesktopSettings {
    try {
        const s = { ...DEFAULTS, ...(JSON.parse(readFileSync(file(), "utf8")) as Partial<DesktopSettings>) };
        return { ...s, provider: normalizeModelProvider(s.provider, s.baseURL) };
    } catch {
        return { ...DEFAULTS };
    }
}

function saveSettings(s: DesktopSettings): DesktopSettings {
    const clean: DesktopSettings = { provider: normalizeModelProvider(s.provider, s.baseURL) };
    for (const k of ["baseURL", "apiKey", "deepModel", "lightModel", "browserPath", "proxy", "burpApi", "burpApiKey", "burpResourcePool", "burpAuditApi", "burpAuditToken", "interactshServer", "interactshToken", "operatorContext"] as const) {
        const v = s[k];
        if (typeof v === "string" && v.trim()) clean[k] = v.trim();
    }
    for (const k of ["deepContextTokens", "lightContextTokens"] as const) {
        const value = parseContextTokens(s[k]);
        if (value !== undefined) clean[k] = value;
    }
    if (!clean.baseURL && MODEL_PROVIDERS[clean.provider].baseURL) clean.baseURL = MODEL_PROVIDERS[clean.provider].baseURL;
    if (s.burpScan) clean.burpScan = true;
    if (s.oobProvider === "interactsh" || s.oobProvider === "burp" || s.oobProvider === "off") clean.oobProvider = s.oobProvider;
    writeFileSync(file(), `${JSON.stringify(clean, null, 2)}\n`);
    return clean;
}

/** Map settings to the env the child assessment processes read. Only NON-empty keys are emitted (so an unset field
 *  falls back to the app's own env / built-in defaults rather than clobbering it with "" ). */
export function settingsToEnv(s: DesktopSettings): Record<string, string> {
    const env: Record<string, string> = {};
    Object.assign(env, modelConnectionEnv(s));
    const browser = s.browserPath?.trim() || detectSystemChromium();
    if (browser) {
        env.VERDICT_BROWSER_PATH = browser;
        if (!s.browserPath) console.log("[verdict] scan browser:", browser);
    } else if (process.platform === "win32") {
        // Last resort: Playwright looks up the installed Edge by channel name (no path needed).
        env.VERDICT_BROWSER_CHANNEL = "msedge";
        console.log("[verdict] scan browser: channel=msedge");
    }
    if (s.proxy) env.VERDICT_PROXY = s.proxy; // the value; activation is via the --proxy arg the desktop appends (env alone never activates)
    // Burp: the connection is read from env by the burp-scan phase; --burp-scan (appended as a child arg) enables it.
    if (s.burpApi) env.BURP_API = s.burpApi;
    if (s.burpApiKey) env.BURP_API_KEY = s.burpApiKey;
    if (s.burpResourcePool) env.BURP_RESOURCE_POOL = s.burpResourcePool;
    if (s.burpAuditApi) env.BURP_AUDIT_API = s.burpAuditApi;
    if (s.burpAuditToken) env.BURP_AUDIT_TOKEN = s.burpAuditToken;
    if (s.oobProvider === "off") env.VERDICT_OOB = "none";
    else if (s.oobProvider === "interactsh") {
        env.VERDICT_OOB = "interactsh";
        env.INTERACTSH_SERVER = s.interactshServer || "oast.pro";
        if (s.interactshToken) env.INTERACTSH_TOKEN = s.interactshToken;
    } else if (s.oobProvider === "burp") env.VERDICT_OOB = "burp";
    else if (s.interactshServer) {
        // Auto: a filled server is itself opt-in (resolveOobProvider then picks Interactsh).
        env.INTERACTSH_SERVER = s.interactshServer;
        if (s.interactshToken) env.INTERACTSH_TOKEN = s.interactshToken;
    }
    return env;
}

/** Apply Settings onto process.env so the in-process server (Ask, PDF export) sees the same provider/browser
 *  as scan children. childEnv only wraps spawned CLI processes — without this, Ask defaults to `claude` and
 *  PDF looks for Playwright's unbundled chromium_headless_shell. */
export function applyLlmSettingsToEnv(s: DesktopSettings = loadSettings(), env: NodeJS.ProcessEnv = process.env): void {
    for (const key of ["VERDICT_LLM_PROVIDER", "VERDICT_LLM_BASE_URL", "VERDICT_LLM_API_KEY", "VERDICT_LLM_MODEL", "VERDICT_LLM_FAST_MODEL", "VERDICT_LLM_CONTEXT_TOKENS", "VERDICT_LLM_FAST_CONTEXT_TOKENS"]) delete env[key];
    Object.assign(env, modelConnectionEnv(s));
    const browser = s.browserPath?.trim() || detectSystemChromium();
    if (browser) {
        env.VERDICT_BROWSER_PATH = browser;
        delete env.VERDICT_BROWSER_CHANNEL;
    } else if (process.platform === "win32") {
        delete env.VERDICT_BROWSER_PATH;
        env.VERDICT_BROWSER_CHANNEL = "msedge";
    }
}

/** Wire the get/set IPC the renderer's Settings panel uses. */
export function setupSettingsIpc(onSaved?: (s: DesktopSettings) => void): void {
    ipcMain.handle("settings:get", () => loadSettings());
    let checking = false;
    ipcMain.handle("settings:check", async (_e, draft?: DesktopSettings) => {
        if (checking) throw new Error("A connection check is already running");
        checking = true;
        try {
            const selected = draft ?? loadSettings();
            const env = { ...process.env };
            // Draft blanks must clear previously applied model settings, just as Save does.
            applyLlmSettingsToEnv(selected, env);
            Object.assign(env, settingsToEnv(selected));
            return await checkReadiness(env, !!selected.burpScan);
        } finally { checking = false; }
    });
    ipcMain.handle("settings:set", (_e, s: DesktopSettings) => {
        const clean = saveSettings(s);
        onSaved?.(clean);
        return clean;
    });
}
