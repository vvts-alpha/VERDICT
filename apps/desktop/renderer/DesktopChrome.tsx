import { useEffect, useState, type ReactNode } from "react";
import { AttendedBrowser } from "./AttendedBrowser";

// Desktop app chrome: a custom (frameless-window) title bar with window controls, rendered ONLY when running
// inside the Electron shell (window.verdictDesktop present). In a plain browser it is a pass-through — the
// `serve` web UI is byte-identical. The title bar sits above the existing app content, which fills the rest.

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
    const desktop = typeof window !== "undefined" ? window.verdictDesktop : undefined;
    const [maximized, setMaximized] = useState(false);
    // Debug: VERDICT_ATTB_URL (via ?attb=<url>) auto-opens the attended browser to a URL for screenshot verification.
    const attbDebug = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("attb") : null;
    const [browserOpen, setBrowserOpen] = useState(!!attbDebug);

    useEffect(() => {
        if (!desktop) return;
        void desktop.isMaximized().then(setMaximized).catch(() => {});
        return desktop.onMaximizeChange(setMaximized);
    }, [desktop]);

    if (!desktop) return <>{children}</>; // plain browser → unchanged web UI

    return (
        <div className="desk-shell">
            <div className="desk-titlebar">
                <span className="desk-brand">
                    <span className="desk-mark" aria-hidden="true" />
                    VERDICT
                </span>
                <div className="desk-drag" />
                <button
                    type="button"
                    className={`desk-tool${browserOpen ? " active" : ""}`}
                    onClick={() => setBrowserOpen((v) => !v)}
                    title="Attended browser — log in to the target by hand, then capture the session for the scan"
                >
                    Browser
                </button>
                <div className="desk-winctl">
                    <button type="button" className="desk-wbtn" onClick={() => desktop.minimize()} aria-label="Minimize" title="Minimize">
                        <WinIcon kind="min" />
                    </button>
                    <button type="button" className="desk-wbtn" onClick={() => desktop.toggleMaximize()} aria-label={maximized ? "Restore" : "Maximize"} title={maximized ? "Restore" : "Maximize"}>
                        <WinIcon kind={maximized ? "restore" : "max"} />
                    </button>
                    <button type="button" className="desk-wbtn desk-wclose" onClick={() => desktop.close()} aria-label="Close" title="Close">
                        <WinIcon kind="close" />
                    </button>
                </div>
            </div>
            <div className="desk-content">
                {children}
                {browserOpen ? <AttendedBrowser initialUrl={attbDebug ?? "about:blank"} onClose={() => setBrowserOpen(false)} /> : null}
            </div>
        </div>
    );
}
