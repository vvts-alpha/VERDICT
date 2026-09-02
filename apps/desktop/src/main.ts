// VERDICT desktop shell (Electron). First slice: host @veritas/server IN-PROCESS in the Electron main
// (the node:sqlite store opens here — verified by the spike), and show the existing React WebUI in a window
// pointed at the local server. Assessments still run as isolated child processes (wired via runLauncher below).
//
// The store, WS projection, and evidence contracts are unchanged — this is the same server the `serve` command
// runs, just hosted by Electron instead of a bare Node process (docs/DESKTOP_APP.md, "backend nearly unchanged").

import { app, BrowserWindow, ipcMain, Menu, session, shell, type WebContents } from "electron";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { join } from "node:path";
import { existsSync, mkdirSync } from "node:fs";
import { startServer, type RunningServer, type RunLauncherConfig } from "@veritas/server";
import { applyAttendedProxy, setupAttendedBrowser } from "./attended-browser.js";
import { setupSettingsIpc, loadSettings, settingsToEnv, applyLlmSettingsToEnv } from "./settings.js";

/** App root (apps/desktop) — main.js lives in dist/, so one level up. Used to locate the preload. */
const APP_ROOT = fileURLToPath(new URL("..", import.meta.url));

/** The desktop's OWN renderer build (apps/desktop/dist-renderer) — a separate frontend build from the web UI.
 *  The in-process server serves it, so the renderer reaches the API/WS over the same relative URLs as the web UI. */
function resolveWebRoot(): string {
    return join(APP_ROOT, "dist-renderer");
}

/** Absolute path to the CLI entry the Supervisor forks to run an assessment (must be spawn-loadable). */
function resolveCliPath(): string | undefined {
    try {
        const require = createRequire(import.meta.url);
        return require.resolve("@veritas/cli/dist/main.js");
    } catch {
        return undefined;
    }
}

let server: RunningServer | null = null;
let win: BrowserWindow | null = null;

/** Drop File/Edit/View from a window. Report HTML/PDF opens via target=_blank as a child BrowserWindow;
 *  without this, Windows/Linux show Electron's default application menu on that popup. */
function stripAppMenu(created: BrowserWindow): void {
    created.removeMenu();
    created.setAutoHideMenuBar(true);
    created.setMenuBarVisibility(false);
}

/** Same-origin popups (report HTML/PDF, inventory) stay in-app without a menu; everything else goes to the OS browser. */
function attachPopupPolicy(contents: WebContents): void {
    contents.setWindowOpenHandler(({ url }) => {
        const origin = server?.url ?? "http://127.0.0.1";
        if (!url.startsWith(origin)) {
            void shell.openExternal(url);
            return { action: "deny" };
        }
        return {
            action: "allow",
            overrideBrowserWindowOptions: {
                title: "VERDICT",
                autoHideMenuBar: true,
            },
        };
    });
}

async function boot(): Promise<void> {
    // All writable state lives under userData (the install dir is read-only in a packaged app).
    const runsDir = join(app.getPath("userData"), "runs");
    mkdirSync(runsDir, { recursive: true });

    const webRoot = resolveWebRoot();
    if (!existsSync(join(webRoot, "index.html"))) console.error(`[verdict] renderer build not found at ${webRoot} — run the desktop renderer build (pnpm --filter @veritas/desktop build)`);

    // Launcher: assessments run as isolated child processes (crash containment + a reliable kill path). Under a
    // packaged app this needs an unpacked cliPath + an absolute runsDir + the openai LLM provider (no `claude` binary).
    const cliPath = resolveCliPath();
    const runLauncher: RunLauncherConfig | undefined = cliPath
        ? {
              runsDir,
              cliPath,
              nodePath: process.execPath,
              // ELECTRON_RUN_AS_NODE makes `process.execPath` (the Electron binary) run as plain Node for the child
              // (verified: it has node:sqlite + loads @veritas/core). A thunk so in-app Settings (LLM provider / Deep +
              // Light models / browser path) apply to the NEXT run without an app restart. Settings win over the app env.
              childEnv: () => ({ ...process.env, ELECTRON_RUN_AS_NODE: "1", ...settingsToEnv(loadSettings()) }),
              // Per-run flags derived from Settings for pilot runs: --proxy (env alone never activates it) and
              // --burp-scan (enable the post-diagnosis Burp active scan; the Burp connection comes from the env above).
              childArgs: (command) => {
                  if (!command.startsWith("pilot")) return [];
                  const s = loadSettings();
                  const args: string[] = [];
                  if (s.proxy) args.push("--proxy", s.proxy);
                  if (s.burpScan) args.push("--burp-scan");
                  return args;
              },
              cwd: app.getPath("userData"),
              onLog: (m: string) => console.log("[run]", m),
          }
        : undefined;
    if (!runLauncher) console.warn("[verdict] @veritas/cli not resolvable — assessments cannot be launched from the UI yet");

    // Ask + PDF run in this process via @veritas/server (not a CLI child), so Settings LLM/browser env
    // must live on process.env (childEnv only wraps spawned scans).
    applyLlmSettingsToEnv();

    server = await startServer({
        runsDir,
        host: "127.0.0.1", // single-user localhost — never bind 0.0.0.0 from the desktop app
        port: 0, // ephemeral: avoid clashing with a separately-running `serve`
        webRoot,
        // no authPasswords: local single-user app (loopback only)
        ...(runLauncher ? { runLauncher } : {}),
        onLog: (m) => console.log("[server]", m),
    });
    console.log(`[verdict] server on ${server.url} (runs: ${runsDir})`);

    // The local UI must not go through the operator's HTTP_PROXY / Windows system proxy (Burp, corporate
    // MITM, …). Chromium will otherwise fetch http://127.0.0.1:<port>/ via that proxy and boot with
    // ERR_PROXY_CONNECTION_FAILED. The attended Browser tab uses partition persist:attended and is pointed
    // at Settings' upstream proxy separately (applyAttendedProxy).
    await session.defaultSession.setProxy({ mode: "direct" });
    await applyAttendedProxy();

    // Windows/Linux draw the application menu inside the window. The main chrome is frameless; popups
    // (Export → HTML/PDF) must not grow File/Edit/View either. macOS keeps the screen-top app menu.
    if (process.platform !== "darwin") Menu.setApplicationMenu(null);
    app.on("browser-window-created", (_e, created) => {
        stripAppMenu(created);
        attachPopupPolicy(created.webContents);
    });

    win = new BrowserWindow({
        width: 1400,
        height: 900,
        minWidth: 900,
        minHeight: 600,
        title: "VERDICT",
        backgroundColor: "#0f1116", // matches the web UI --bg so there is no white flash before load
        frame: false, // custom in-app title bar (DesktopChrome) — the app frame, not a browser window
        webPreferences: {
            contextIsolation: true,
            nodeIntegration: false,
            preload: join(APP_ROOT, "preload.cjs"),
        },
    });

    // Window controls (the custom title bar calls these over the preload bridge).
    ipcMain.on("win:minimize", () => win?.minimize());
    ipcMain.on("win:toggle-maximize", () => (win?.isMaximized() ? win.unmaximize() : win?.maximize()));
    ipcMain.on("win:close", () => win?.close());
    // Refocus the app's HTML contents (the attended-browser WebContentsView steals OS focus, which otherwise eats the
    // first click on a title-bar button). The renderer calls this when the pointer enters the title bar.
    ipcMain.on("win:focus-chrome", () => win?.webContents.focus());
    ipcMain.handle("win:is-maximized", () => !!win?.isMaximized());
    ipcMain.handle("app:info", () => ({ version: app.getVersion(), electron: process.versions.electron, node: process.versions.node, chrome: process.versions.chrome }));
    win.on("maximize", () => win?.webContents.send("win:maximize-changed", true));
    win.on("unmaximize", () => win?.webContents.send("win:maximize-changed", false));

    // In-app settings (LLM provider / Deep + Light models / browser path / proxy) — childEnv thunk (scans) +
    // process.env (Ask + PDF). Saving proxy also reapplies it to the attended Browser tab (no app restart).
    setupSettingsIpc((s) => {
        applyLlmSettingsToEnv(s);
        void applyAttendedProxy();
    });

    // Attended embedded browser (human login / CAPTCHA inside the one window; session handoff to the auto pilot).
    const attb = setupAttendedBrowser(win, runsDir);
    attachPopupPolicy(win.webContents);
    win.webContents.on("did-fail-load", (_e, code, desc, url) => console.error(`[verdict] did-fail-load ${code} ${desc} ${url}`));
    await win.loadURL(server.url); // resolves after the page finishes loading

    // Debug self-test: VERDICT_ATTB_URL loads that URL in the embedded browser, captures the VIEW (proving Electron's
    // own Chromium rendered the real page) + captures the session cookies (the handoff primitive), then exits.
    const attbUrl = process.env.VERDICT_ATTB_URL;
    if (attbUrl) {
        await attb.open(attbUrl);
        await new Promise((r) => setTimeout(r, 1500));
        if (process.env.VERDICT_ATTB_SHOT) await attb.captureViewPng(process.env.VERDICT_ATTB_SHOT);
        const cap = await attb.captureCookies();
        console.log("[verdict] attb self-test:", JSON.stringify(cap));
        await server?.close();
        app.exit(cap.ok ? 0 : 3);
    }

    // Debug/CI: VERDICT_SHOT=<path> captures the rendered window to a PNG (loadURL already resolved = loaded), then exits.
    const shotPath = process.env.VERDICT_SHOT;
    if (shotPath) {
        if (process.env.VERDICT_SHOT_QUERY) await win.loadURL(server.url + process.env.VERDICT_SHOT_QUERY);
        await new Promise((r) => setTimeout(r, 2500)); // let the React app render + WS connect
        const img = await win.webContents.capturePage();
        const { writeFile } = await import("node:fs/promises");
        await writeFile(shotPath, img.toPNG());
        console.log("[verdict] shot →", shotPath);
        await server?.close();
        app.exit(0);
    }
}

app.setName("VERDICT"); // stable userData dir (~/.config/VERDICT) instead of the generic "Electron"
app.disableHardwareAcceleration(); // headless/WSL friendliness; the UI is a plain document, not GPU-bound
// Burp MITM: Chromium would otherwise blank the attended Browser tab (no cert interstitial in WebContentsView).
app.commandLine.appendSwitch("ignore-certificate-errors");
// Burp's HTTP/2 interception commonly yields a white page; the local UI is HTTP/1.1 so this is safe.
app.commandLine.appendSwitch("disable-http2");

app.on("certificate-error", (event, _wc, url, error, _certificate, callback) => {
    event.preventDefault();
    console.warn("[verdict] certificate-error ignored:", error, url);
    callback(true);
});

app.whenReady()
    .then(boot)
    .catch((e) => {
        console.error("[verdict] boot failed:", e);
        app.exit(1);
    });

app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0 && server) {
        win = new BrowserWindow({ width: 1400, height: 900, title: "VERDICT", backgroundColor: "#0f1116" });
        void win.loadURL(server.url);
    }
});

// Reap child assessment processes + close the server before the app exits.
app.on("before-quit", (e) => {
    if (server) {
        e.preventDefault();
        const s = server;
        server = null;
        void s.close().finally(() => app.exit(0));
    }
});

app.on("window-all-closed", () => {
    // macOS convention keeps the app alive; on Linux/Windows quit with the last window.
    if (process.platform !== "darwin") app.quit();
});
