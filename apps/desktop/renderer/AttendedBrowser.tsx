import { useEffect, useRef, useState } from "react";

// The attended embedded browser panel. A native Electron WebContentsView (real Chromium) is drawn by the main
// process OVER the placeholder region below — the human navigates + logs in there (no automation fingerprint).
// This React layer is just the chrome: a toolbar (nav + URL + capture) and a placeholder that reports its on-screen
// bounds to main so the native view stays aligned. "Capture session" writes the login cookies to a file the pilot loads.

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.browser : undefined);

export function AttendedBrowser({ initialUrl, onClose }: { initialUrl: string; onClose: () => void }) {
    const holderRef = useRef<HTMLDivElement>(null);
    const [urlField, setUrlField] = useState(initialUrl);
    const [nav, setNav] = useState({ canGoBack: false, canGoForward: false, loading: false });
    const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);

    // Keep the native view aligned with the placeholder region.
    useEffect(() => {
        const b = bridge();
        if (!b) return;
        const report = (): void => {
            const el = holderRef.current;
            if (!el) return;
            const r = el.getBoundingClientRect();
            b.setBounds({ x: r.left, y: r.top, width: r.width, height: r.height });
        };
        report();
        const ro = new ResizeObserver(report);
        if (holderRef.current) ro.observe(holderRef.current);
        window.addEventListener("resize", report);
        void b.open(initialUrl);
        const off = b.onNavigated((s) => {
            setUrlField(s.url);
            setNav({ canGoBack: s.canGoBack, canGoForward: s.canGoForward, loading: s.loading });
        });
        return () => {
            ro.disconnect();
            window.removeEventListener("resize", report);
            off();
            b.close();
        };
    }, [initialUrl]);

    const go = (): void => {
        let u = urlField.trim();
        if (!u) return;
        if (!/^https?:\/\//i.test(u)) u = `https://${u}`;
        void bridge()?.navigate(u);
    };
    const capture = async (): Promise<void> => {
        const r = await bridge()?.capture();
        if (!r) return;
        setNote(r.ok ? { ok: true, text: `captured ${r.count} cookie(s) for ${r.host} → ${r.path}` } : { ok: false, text: r.error ?? "capture failed" });
    };

    return (
        <div className="attb">
            <div className="attb-bar">
                <button type="button" className="attb-btn" disabled={!nav.canGoBack} onClick={() => bridge()?.back()} title="Back" aria-label="Back">‹</button>
                <button type="button" className="attb-btn" disabled={!nav.canGoForward} onClick={() => bridge()?.forward()} title="Forward" aria-label="Forward">›</button>
                <button type="button" className="attb-btn" onClick={() => bridge()?.reload()} title="Reload" aria-label="Reload">⟳</button>
                <input
                    className="attb-url"
                    value={urlField}
                    spellCheck={false}
                    onChange={(e) => setUrlField(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") go(); }}
                    placeholder="https://target/login"
                />
                <button type="button" className="attb-capture" onClick={() => void capture()} title="Save the login session for the scan">Capture session</button>
                <button type="button" className="attb-close" onClick={onClose} title="Close">Close</button>
            </div>
            {note ? <div className={note.ok ? "attb-note ok" : "attb-note err"}>{note.text}</div> : null}
            {/* The native WebContentsView is positioned by main over this region. */}
            <div className="attb-view" ref={holderRef} />
        </div>
    );
}
