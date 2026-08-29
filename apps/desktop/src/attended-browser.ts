// Attended (human-phase) embedded browser. Uses Electron's OWN Chromium as a WebContentsView placed INSIDE the app
// window — so the operator logs in / clears CAPTCHA in a REAL browser (no automation mode, no navigator.webdriver =
// far harder to fingerprint than stealth Playwright), all in the one window. After login, the session is captured
// (cookies → a raw `Cookie:` header file) and handed to the automation pilot (which loadCookieFile reads). This is the
// 人間フェーズ side of the division-of-labour in docs/DESKTOP_APP.md; the auto phase stays on Playwright (headless).

import { WebContentsView, ipcMain, session, type BrowserWindow } from "electron";
import { writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { loadSettings } from "./settings.js";

/** A persistent, ISOLATED session so the human's login survives view close and never mixes with the app's own session. */
export const ATTENDED_PARTITION = "persist:attended";

function resolveAttendedProxy(): string | undefined {
    const v = loadSettings().proxy?.trim() || process.env.VERDICT_PROXY || process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
    return v?.trim() || undefined;
}

/** Route the attended Browser tab through Settings' upstream proxy (Burp). The app UI session stays `direct`
 *  so localhost is never sent to that proxy. Blank = direct (same as Settings copy). */
export async function applyAttendedProxy(proxy = resolveAttendedProxy()): Promise<void> {
    const ses = session.fromPartition(ATTENDED_PARTITION);
    const url = proxy?.trim() ?? "";
    if (!url) {
        await ses.setProxy({ mode: "direct" });
        console.log("[verdict] attended browser proxy: direct");
    } else {
        // Do NOT bypass 127.0.0.1 — Burp listens on loopback, and local labs must still be intercepted.
        await ses.setProxy({ proxyRules: url });
        console.log("[verdict] attended browser proxy:", url);
    }
    // Always ignore TLS errors here: Burp MITM presents its own CA, and the WebContentsView has no
    // cert-interstitial chrome (failures show as a blank page).
    ses.setCertificateVerifyProc((_req, cb) => cb(0));
}

interface Bounds {
    x: number;
    y: number;
    width: number;
    height: number;
}

/** Debug handles (used by main's VERDICT_ATTB_URL self-test to verify the embedded browser + session capture). */
export interface AttendedBrowserDebug {
    open(url: string): Promise<void>;
    captureViewPng(path: string): Promise<boolean>;
    captureCookies(): Promise<{ ok: boolean; path?: string; count?: number; host?: string; header?: string; error?: string }>;
}

export function setupAttendedBrowser(win: BrowserWindow, runsDir: string): AttendedBrowserDebug {
    let view: WebContentsView | null = null;

    const emit = (channel: string, payload: unknown): void => {
        if (!win.isDestroyed()) win.webContents.send(channel, payload);
    };

    const ensureView = (): WebContentsView => {
        if (view) return view;
        const v = new WebContentsView({ webPreferences: { partition: ATTENDED_PARTITION } });
        win.contentView.addChildView(v);
        const wc = v.webContents;
        const navState = (): void =>
            emit("attbrowser:navigated", {
                url: wc.getURL(),
                title: wc.getTitle(),
                canGoBack: wc.navigationHistory.canGoBack(),
                canGoForward: wc.navigationHistory.canGoForward(),
                loading: wc.isLoading(),
            });
        wc.on("did-navigate", navState);
        wc.on("did-navigate-in-page", navState);
        wc.on("did-start-loading", navState);
        wc.on("did-stop-loading", navState);
        wc.on("certificate-error", (event, url, error, _cert, callback) => {
            event.preventDefault();
            console.warn("[verdict] attended cert ignored:", error, url);
            callback(true);
        });
        wc.on("did-fail-load", (_e, code, desc, url, isMainFrame) => {
            if (!isMainFrame) return;
            console.error(`[verdict] attended did-fail-load ${code} ${desc} ${url}`);
            emit("attbrowser:error", `${desc} (${code})`);
        });
        // Keep target popups inside the same view rather than spawning OS windows (stay in the one window).
        wc.setWindowOpenHandler(({ url }) => {
            void wc.loadURL(url);
            return { action: "deny" };
        });
        view = v;
        return v;
    };

    const destroyView = (): void => {
        if (!view) return;
        win.contentView.removeChildView(view);
        // WebContentsView's webContents is closed when the view is GC'd; drop the reference.
        view = null;
    };

    ipcMain.handle("attbrowser:open", async (_e, url: string) => {
        await applyAttendedProxy();
        const v = ensureView();
        await v.webContents.loadURL(url).catch((err) => emit("attbrowser:error", String(err).slice(0, 200)));
    });

    ipcMain.on("attbrowser:set-bounds", (_e, b: Bounds) => {
        if (!view) return;
        view.setBounds({ x: Math.round(b.x), y: Math.round(b.y), width: Math.round(b.width), height: Math.round(b.height) });
    });

    ipcMain.on("attbrowser:close", () => destroyView());

    ipcMain.handle("attbrowser:navigate", async (_e, url: string) => {
        if (!view) return;
        await view.webContents.loadURL(url).catch((err) => emit("attbrowser:error", String(err).slice(0, 200)));
    });

    ipcMain.on("attbrowser:back", () => view?.webContents.navigationHistory.goBack());
    ipcMain.on("attbrowser:forward", () => view?.webContents.navigationHistory.goForward());
    ipcMain.on("attbrowser:reload", () => view?.webContents.reload());

    // Capture the current session as a raw `Cookie:` header file the pilot can load (attended → automation handoff).
    const captureCookies = async (assessmentId?: string): Promise<{ ok: boolean; path?: string; count?: number; host?: string; header?: string; error?: string }> => {
        if (!view) return { ok: false, error: "no attended browser open" };
        const wc = view.webContents;
        const url = wc.getURL();
        if (!url || url === "about:blank") return { ok: false, error: "navigate to the target and log in first" };
        const cookies = await wc.session.cookies.get({ url }); // cookies that would be sent to this URL = the session
        if (cookies.length === 0) return { ok: false, error: "no cookies for this page yet (log in first)" };
        const header = cookies.map((c) => `${c.name}=${c.value}`).join("; ");
        const host = new URL(url).host;
        const outDir = assessmentId ? join(runsDir, assessmentId) : join(runsDir, "_sessions");
        mkdirSync(outDir, { recursive: true });
        const outPath = join(outDir, `attended_cookies_${host.replace(/[^a-zA-Z0-9._-]/g, "_")}.txt`);
        writeFileSync(outPath, `${header}\n`);
        return { ok: true, path: outPath, count: cookies.length, host, header };
    };
    ipcMain.handle("attbrowser:capture", (_e, assessmentId?: string) => captureCookies(assessmentId));

    return {
        open: async (url: string) => {
            await applyAttendedProxy();
            const v = ensureView();
            v.setBounds({ x: 0, y: 80, width: 1200, height: 700 }); // give it real size so it renders (debug self-test)
            await v.webContents.loadURL(url);
        },
        captureViewPng: async (path: string) => {
            if (!view) return false;
            const img = await view.webContents.capturePage();
            writeFileSync(path, img.toPNG());
            return true;
        },
        captureCookies: () => captureCookies(),
    };
}
