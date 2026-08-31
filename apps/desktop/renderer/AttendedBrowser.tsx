import { useEffect, useRef, useState } from "react";

// The attended embedded browser panel. A native Electron WebContentsView (real Chromium) is drawn by the main
// process OVER the placeholder region below — the human navigates + logs in there (no automation fingerprint).
// This React layer is just the chrome: a toolbar (nav + URL + capture) and a placeholder that reports its on-screen
// bounds to main so the native view stays aligned. "Capture session" writes the login cookies to a file the pilot loads.

async function copyText(text: string): Promise<boolean> {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        return false;
    }
}

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.browser : undefined);

// A start page shown when the attended browser opens with no target — makes "Browser" read as "start an attended scan".
const START_PAGE =
    "data:text/html;charset=utf-8," +
    encodeURIComponent(
        `<!doctype html><html><head><meta charset="utf-8"><style>
        html,body{height:100%;margin:0}
        body{background:#14161a;color:#8a93a0;font:14px ui-monospace,Menlo,Consolas,monospace;display:flex;align-items:center;justify-content:center}
        .c{max-width:520px;padding:24px}
        h1{color:#d7dbe0;font-size:16px;letter-spacing:1px;margin:0 0 14px}
        ol{line-height:1.9;padding-left:20px;margin:0}
        b{color:#6db0ff}
        </style></head><body><div class="c">
        <h1>Attended assessment</h1>
        <ol>
          <li>Type the target's login URL in the address bar above and press Enter.</li>
          <li>Log in / clear any CAPTCHA by hand — this is a real browser, not automation.</li>
          <li>Click <b>Capture session</b> to save cookies and localStorage (SPA tokens).</li>
          <li>Click <b>Scan with session →</b> to run an authenticated scan (headless, in this window).</li>
        </ol>
        </div></body></html>`,
    );

export function AttendedBrowser({
    initialUrl,
    handoffId,
    onClose,
}: {
    initialUrl: string;
    /** When set, this panel was opened from a pending HumanHandoff (CAPTCHA / auth wall). */
    handoffId?: string;
    onClose: () => void;
}) {
    const holderRef = useRef<HTMLDivElement>(null);
    const [urlField, setUrlField] = useState(initialUrl);
    const [currentUrl, setCurrentUrl] = useState(initialUrl);
    const [nav, setNav] = useState({ canGoBack: false, canGoForward: false, loading: false });
    const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
    const [captured, setCaptured] = useState<{ path: string; host: string; header?: string; cookies?: number; localStorage?: number } | null>(null);
    const [launching, setLaunching] = useState(false);

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
        void b.open(initialUrl && initialUrl !== "about:blank" ? initialUrl : START_PAGE);
        const off = b.onNavigated((s) => {
            const real = s.url && s.url !== "about:blank" && !s.url.startsWith("data:");
            setUrlField(real ? s.url : ""); // hide the internal start-page data: URL — show the placeholder instead
            if (real) setCurrentUrl(s.url);
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
    const copyUrl = async (): Promise<void> => {
        const u = (urlField.trim() || currentUrl).trim();
        if (!u || u.startsWith("data:")) return;
        const ok = await copyText(u);
        setNote({ ok, text: ok ? "copied URL" : "copy failed" });
    };
    const copyCookies = async (): Promise<void> => {
        if (!captured?.header) return;
        const ok = await copyText(captured.header);
        setNote({ ok, text: ok ? "copied Cookie header" : "copy failed" });
    };
    const capture = async (): Promise<void> => {
        const r = await bridge()?.capture();
        if (!r) return;
        if (r.ok && r.path && r.host) {
            setCaptured({ path: r.path, host: r.host, header: r.header, cookies: r.count, localStorage: r.localStorage });
            const cookieN = r.count ?? 0;
            const lsN = r.localStorage ?? 0;
            const what = [
                cookieN ? `${cookieN} cookie(s)` : "",
                lsN ? `${lsN} localStorage key(s)` : "",
            ].filter(Boolean).join(" + ") || "session";
            setNote({
                ok: true,
                text: handoffId
                    ? `captured ${what} for ${r.host} — click Logged in → continue`
                    : `captured ${what} for ${r.host} — start an authenticated scan below`,
            });
        } else {
            setCaptured(null);
            setNote({ ok: false, text: r.error ?? "capture failed" });
        }
    };

    // Option B: inject the captured session into the run currently open (?id=) — it applies mid-scan at the pilot's
    // next between-screens checkpoint, so a running scan becomes authenticated without a restart.
    const currentRunId = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("id") : null;
    const inject = async (): Promise<boolean> => {
        if (!captured || !currentRunId) return false;
        setLaunching(true);
        try {
            const res = await fetch(`/api/assessments/${encodeURIComponent(currentRunId)}/inject-session`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ cookieFile: captured.path }),
            });
            if (res.ok) {
                setNote({ ok: true, text: `session injected into the running scan — it continues authenticated at the next screen` });
                return true;
            }
            const j = (await res.json().catch(() => ({}))) as { error?: string };
            setNote({ ok: false, text: j.error ?? `inject failed (${res.status})` });
            return false;
        } catch (e) {
            setNote({ ok: false, text: String(e) });
            return false;
        } finally {
            setLaunching(false);
        }
    };

    // Mid-run CAPTCHA/auth: inject cookies into Playwright, mark the handoff resolved, return to Main.
    const continueHandoff = async (): Promise<void> => {
        if (!handoffId || !currentRunId || !captured) return;
        const ok = await inject();
        if (!ok) return;
        setLaunching(true);
        try {
            await fetch(`/api/assessments/${encodeURIComponent(currentRunId)}/handoffs/${encodeURIComponent(handoffId)}/resolve`, {
                method: "POST",
            });
            onClose();
        } catch (e) {
            setNote({ ok: false, text: String(e) });
            setLaunching(false);
        }
    };

    // Attended → auto handoff: launch a headless authenticated scan of this target using the captured session cookie.
    const scan = async (): Promise<void> => {
        if (!captured) return;
        setLaunching(true);
        try {
            const res = await fetch("/api/run", {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({
                    command: "pilot",
                    manifest: { target: currentUrl, auth: { roles: [{ name: "session", cookieFile: captured.path }] } },
                    options: {},
                }),
            });
            const j = (await res.json()) as { id?: string; error?: string };
            if (res.ok && j.id) {
                window.location.href = `/?id=${encodeURIComponent(j.id)}`; // navigate the app to the new run (unmounts + closes this browser)
            } else {
                setNote({ ok: false, text: j.error ?? `launch failed (${res.status})` });
                setLaunching(false);
            }
        } catch (e) {
            setNote({ ok: false, text: String(e) });
            setLaunching(false);
        }
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
                <button type="button" className="attb-copy" disabled={!urlField.trim() && !currentUrl} onClick={() => void copyUrl()} title="Copy URL" aria-label="Copy URL">Copy</button>
                <button type="button" className="attb-capture" onClick={() => void capture()} title="Save cookies + localStorage (SPA Bearer) for the scan">Capture session</button>
                {captured?.header ? (
                    <button type="button" className="attb-copy" onClick={() => void copyCookies()} title="Copy the Cookie header to the clipboard (Repeater / curl)">Copy cookies</button>
                ) : null}
                {captured && currentRunId && !handoffId ? (
                    <button type="button" className="attb-scan" disabled={launching} onClick={() => void inject()} title="Inject this session into the scan you're viewing — it continues authenticated, no restart">
                        {launching ? "Injecting…" : "Inject into this run →"}
                    </button>
                ) : null}
                {captured && !handoffId ? (
                    <button type="button" className="attb-scan" disabled={launching} onClick={() => void scan()} title={`Start a new headless authenticated scan of ${captured.host} with this session`}>
                        {launching ? "Starting…" : "Scan (new run) →"}
                    </button>
                ) : null}
                {handoffId && currentRunId ? (
                    <button
                        type="button"
                        className="attb-scan"
                        disabled={launching || !captured}
                        onClick={() => void continueHandoff()}
                        title="Inject the captured cookies into the scan, mark the handoff done, and return to Main"
                    >
                        {launching ? "Continuing…" : "Logged in → continue"}
                    </button>
                ) : null}
                <button type="button" className="attb-close" onClick={onClose} title="Close">Close</button>
            </div>
            {handoffId ? (
                <div className="attb-handoff">
                    Scan waiting on you — log in / clear CAPTCHA here (real browser). Then Capture session
                    {currentRunId ? " and Logged in → continue (injects cookies into the scan)." : "."}
                </div>
            ) : null}
            {note ? <div className={note.ok ? "attb-note ok" : "attb-note err"}>{note.text}</div> : null}
            {/* The native WebContentsView is positioned by main over this region. */}
            <div className="attb-view" ref={holderRef} />
        </div>
    );
}
