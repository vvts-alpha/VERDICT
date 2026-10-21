import { useEffect, useRef, useState, type ReactNode } from "react";
import { AttendedBrowser } from "./AttendedBrowser";
import { Settings } from "./Settings";
import { Button } from "@veritas/webui/ui/button";
import { DesktopShellContext, type DesktopShell } from "@veritas/webui";
import { useT } from "@veritas/webui/i18n";
import { AppWindow, Settings as SettingsIcon } from "lucide-react";

// Desktop app chrome: a custom (frameless-window) title bar with window controls, rendered ONLY when running
// inside the Electron shell (window.verdictDesktop present). In a plain browser it is a pass-through — the
// `serve` web UI is byte-identical. The title bar sits above the existing app content, which fills the rest.
// Desktop-level views (Main / Browser / Settings) are navigated via the app sidebar — the shell publishes
// them through DesktopShellContext so the shared sidebar renders them like any other nav.

type DeskView = "main" | "browser" | "settings";

function WinIcon({ kind }: { kind: "min" | "max" | "restore" | "close" }) {
    // 10×10 monochrome line icons (stroke = currentColor) — no emoji, matches the UI's restrained iconography.
    const common = { width: 10, height: 10, viewBox: "0 0 10 10", fill: "none", stroke: "currentColor", strokeWidth: 1 } as const;
    if (kind === "min") return <svg {...common}><line x1="0" y1="5.5" x2="10" y2="5.5" /></svg>;
    if (kind === "close")
        return (
            <svg {...common}>
                <line x1="0.7" y1="0.7" x2="9.3" y2="9.3" />
                <line x1="9.3" y1="0.7" x2="0.7" y2="9.3" />
            </svg>
        );
    if (kind === "restore")
        return (
            <svg {...common}>
                <rect x="0.5" y="2.5" width="6" height="6" />
                <path d="M2.5 2.5 V0.5 H8.5 V6.5 H6.5" />
            </svg>
        );
    return <svg {...common}><rect x="0.5" y="0.5" width="9" height="9" /></svg>;
}

export function DesktopChrome({ children }: { children: ReactNode }) {
    const t = useT();
    const desktop = typeof window !== "undefined" ? window.verdictDesktop : undefined;
    const [maximized, setMaximized] = useState(false);
    // Debug: VERDICT_ATTB_URL (via ?attb=<url>) auto-opens the attended browser to a URL for screenshot verification.
    const attbDebug = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("attb") : null;
    const settingsDebug = typeof window !== "undefined" && new URLSearchParams(window.location.search).get("settings") === "1";
    const [view, setView] = useState<DeskView>(attbDebug ? "browser" : settingsDebug ? "settings" : "main");
    const [browserSeed, setBrowserSeed] = useState(attbDebug ?? "about:blank");
    const [browserHandoffId, setBrowserHandoffId] = useState<string | undefined>(undefined);
    // Settings registers a leave-guard: returns false (and raises its inline confirm bar) when edits are unsaved.
    const settingsGuard = useRef<(() => boolean) | null>(null);
    // A guarded navigation that was vetoed — after the user confirms "Discard", the ORIGINALLY chosen
    // destination runs (not a plain fallback to main).
    const pendingLeave = useRef<(() => void) | null>(null);

    useEffect(() => {
        if (!desktop) return;
        void desktop.isMaximized().then(setMaximized).catch(() => {});
        return desktop.onMaximizeChange(setMaximized);
    }, [desktop]);

    // Any navigation out of the current view — vetoed while Settings has unsaved edits; the vetoed
    // destination is remembered so confirming "Discard" continues to it.
    const runGuarded = (fn: () => void): boolean => {
        if (view === "settings" && settingsGuard.current && !settingsGuard.current()) {
            pendingLeave.current = fn;
            return false;
        }
        fn();
        return true;
    };
    const onNavigate = (next: string): boolean =>
        runGuarded(() => {
            // A plain nav click isn't a handoff open — drop the stale handoff context so the banner and
            // its resolve action don't linger from a previous handoff-driven open. Guard on `view` so
            // re-clicking the already-open nav item doesn't remount (and reload) the browser.
            if (next === "browser" && view !== "browser") setBrowserHandoffId(undefined);
            setView(next as DeskView);
        });
    // Settings calls this once the leave is settled (clean close or confirmed discard).
    const confirmLeaveSettings = (): void => {
        const fn = pendingLeave.current ?? (() => setView("main"));
        pendingLeave.current = null;
        // The leave is already confirmed — a nested guarded call inside `fn` must not re-veto on the
        // still-dirty flag (that would leave the confirm bar up and need a second Discard).
        const g = settingsGuard.current;
        settingsGuard.current = null;
        try {
            fn();
        } finally {
            settingsGuard.current = g;
        }
    };

    // Handoff-initiated browser opens bypass the leave-guard (a pending captcha/auth wall blocks the scan).
    const openBrowser = (url?: string, handoffId?: string): void => {
        const u = url?.trim();
        if (u) setBrowserSeed(u);
        setBrowserHandoffId(handoffId?.trim() || undefined);
        pendingLeave.current = null;
        setView("browser");
    };

    useEffect(() => {
        if (!desktop) return;
        const onShow = (e: Event): void => {
            const d = (e as CustomEvent<{ url?: string; handoffId?: string }>).detail;
            openBrowser(d?.url, d?.handoffId);
        };
        window.addEventListener("verdict-show-browser", onShow);
        return () => window.removeEventListener("verdict-show-browser", onShow);
    }, [desktop]);

    if (!desktop) return <>{children}</>; // plain browser → unchanged web UI

    const shell: DesktopShell = {
        view,
        onNavigate,
        runGuarded,
        nav: [
            { key: "browser", label: t("Browser"), icon: AppWindow },
            { key: "settings", label: t("Settings"), icon: SettingsIcon },
        ],
        views: {
            browser: (
                <AttendedBrowser
                    key={`${browserSeed}\0${browserHandoffId ?? ""}`}
                    initialUrl={browserSeed}
                    handoffId={browserHandoffId}
                    onClose={() => void onNavigate("main")}
                />
            ),
            settings: (
                <Settings
                    onClose={confirmLeaveSettings}
                    registerLeaveGuard={(fn) => {
                        settingsGuard.current = fn;
                    }}
                />
            ),
        },
    };

    return (
        <div className="flex h-screen flex-col">
            {/* onMouseEnter refocuses the HTML so a title-bar click acts on the first press even while the
                attended-browser native view holds OS focus (otherwise the first click just steals focus back). */}
            <div data-desk-titlebar="" className="flex h-[38px] shrink-0 items-stretch border-b border-border bg-card" onMouseEnter={() => desktop.focusChrome?.()}>
                <Button type="button" variant="ghost" data-desk-no-drag="" className="h-full gap-2 rounded-none px-4 text-xs font-bold tracking-widest" onClick={() => void onNavigate("main")} title={t("Main — back to the assessments view")}>
                    <span className="inline-block size-2 rounded-sm bg-primary" aria-hidden="true" />
                    VERDICT
                </Button>
                {/* Native title-bar convention: double-click the empty drag region to toggle maximize/restore. */}
                <div className="flex-1" onDoubleClick={() => desktop?.toggleMaximize()} />
                <div className="flex items-stretch" data-desk-no-drag="">
                    <Button type="button" variant="ghost" size="icon" className="h-full w-11 rounded-none text-muted-foreground" onClick={() => desktop.minimize()} aria-label={t("Minimize")} title={t("Minimize")}>
                        <WinIcon kind="min" />
                    </Button>
                    <Button type="button" variant="ghost" size="icon" className="h-full w-11 rounded-none text-muted-foreground" onClick={() => desktop.toggleMaximize()} aria-label={maximized ? t("Restore") : t("Maximize")} title={maximized ? t("Restore") : t("Maximize")}>
                        <WinIcon kind={maximized ? "restore" : "max"} />
                    </Button>
                    <Button type="button" variant="ghost" size="icon" className="h-full w-11 rounded-none text-muted-foreground hover:bg-destructive hover:text-foreground" onClick={() => desktop.close()} aria-label={t("Close")} title={t("Close")}>
                        <WinIcon kind="close" />
                    </Button>
                </div>
            </div>
            <div className="relative min-h-0 flex-1 overflow-hidden">
                <DesktopShellContext.Provider value={shell}>{children}</DesktopShellContext.Provider>
            </div>
        </div>
    );
}
