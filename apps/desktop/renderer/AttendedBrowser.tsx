import { useEffect, useRef, useState } from "react";
import { ChevronLeft, ChevronRight, RotateCw } from "lucide-react";
import { Button } from "@veritas/webui/ui/button";
import { Input } from "@veritas/webui/ui/input";
import { NativeSelect } from "@veritas/webui/ui/native-select";
import { useT, type T } from "@veritas/webui/i18n";

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
// Colours/font mirror the app theme (zinc + sans) — it's a separate document, so Tailwind can't reach it.
function startPage(t: T): string {
    return (
        "data:text/html;charset=utf-8," +
        encodeURIComponent(
            `<!doctype html><html><head><meta charset="utf-8"><style>
            html,body{height:100%;margin:0}
            body{background:#09090b;color:#a1a1aa;font:14px/1.6 ui-sans-serif,system-ui,"Segoe UI",sans-serif;display:flex;align-items:center;justify-content:center}
            .c{max-width:560px;padding:24px}
            h1{color:#e4e4e7;font-size:15px;font-weight:600;letter-spacing:.01em;margin:0 0 16px}
            ol{line-height:1.9;padding-left:20px;margin:0}
            b{color:#e4e4e7;font-weight:600}
            </style></head><body><div class="c">
            <h1>${t("Attended assessment")}</h1>
            <ol>
              <li>${t("Type the target's login URL in the address bar above and press Enter.")}</li>
              <li>${t("Log in / clear any CAPTCHA by hand — this is a real browser, not automation.")}</li>
              <li>${t("Click {action} to save cookies and localStorage (SPA tokens).", { action: `<b>${t("Capture session")}</b>` })}</li>
              <li>${t("Click {action} to run an authenticated scan (headless, in this window).", { action: `<b>${t("Scan (new run) →")}</b>` })}</li>
            </ol>
            </div></body></html>`,
        )
    );
}

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
    const t = useT();
    const holderRef = useRef<HTMLDivElement>(null);
    const [urlField, setUrlField] = useState(initialUrl);
    const [currentUrl, setCurrentUrl] = useState(initialUrl);
    const [nav, setNav] = useState({ canGoBack: false, canGoForward: false, loading: false });
    const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
    const [captured, setCaptured] = useState<{ path: string; host: string; header?: string; cookies?: number; localStorage?: number } | null>(null);
    const [launching, setLaunching] = useState(false);
    const [sessionRoles, setSessionRoles] = useState<string[]>([]);
    const [sessionRole, setSessionRole] = useState("");

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
        void b.open(initialUrl && initialUrl !== "about:blank" ? initialUrl : startPage(t));
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
        setNote({ ok, text: ok ? t("copied URL") : t("copy failed") });
    };
    const copyCookies = async (): Promise<void> => {
        if (!captured?.header) return;
        const ok = await copyText(captured.header);
        setNote({ ok, text: ok ? t("copied Cookie header") : t("copy failed") });
    };
    const capture = async (): Promise<void> => {
        const r = await bridge()?.capture();
        if (!r) return;
        if (r.ok && r.path && r.host) {
            setCaptured({ path: r.path, host: r.host, header: r.header, cookies: r.count, localStorage: r.localStorage });
            const cookieN = r.count ?? 0;
            const lsN = r.localStorage ?? 0;
            const what = [
                cookieN ? t("{n} cookie(s)", { n: cookieN }) : "",
                lsN ? t("{n} localStorage key(s)", { n: lsN }) : "",
            ].filter(Boolean).join(" + ") || t("session");
            setNote({
                ok: true,
                text: handoffId
                    ? t("captured {what} for {host} — click Logged in → continue", { what, host: r.host })
                    : t("captured {what} for {host} — start an authenticated scan below", { what, host: r.host }),
            });
        } else {
            setCaptured(null);
            setNote({ ok: false, text: r.error ?? t("capture failed") });
        }
    };

    // Option B: inject the captured session into the run currently open (?id=) — it applies mid-scan at the pilot's
    // next between-screens checkpoint, so a running scan becomes authenticated without a restart.
    const currentRunId = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("id") : null;
    const inject = async (): Promise<boolean> => {
        if (!captured || !currentRunId) return false;
        setLaunching(true);
        try {
            const res = await fetch(`/api/assessments/${encodeURIComponent(currentRunId)}/continue-session`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify({ cookieFile: captured.path, ...(handoffId ? { handoffId } : {}), ...(sessionRole ? { role: sessionRole } : {}) }),
            });
            const j = await res.json();
            if (res.ok) {
                setNote({ ok: true, text: j.action === "restarted" ? t("Diagnosis restarted with the captured session") : t("Session queued; the running diagnosis will apply it shortly") });
                return true;
            }
            if (Array.isArray(j.roles)) setSessionRoles(j.roles);
            setNote({ ok: false, text: j.error ?? t("continue failed ({status})", { status: res.status }) });
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
        onClose();
    };

    // Attended → auto handoff: launch a headless authenticated scan of this target using the captured session cookie.
    const scan = async (): Promise<void> => {
        if (!captured) return;
        setLaunching(true);
        try {
            const checks = await window.verdictDesktop?.settings.check();
            if (checks?.some((c) => c.status === "error")) {
                setNote({ ok: false, text: t("Setup check failed. Open Settings → Check connections before starting.") });
                return;
            }
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
                setNote({ ok: false, text: j.error ?? t("launch failed ({status})", { status: res.status }) });
                setLaunching(false);
            }
        } catch (e) {
            setNote({ ok: false, text: String(e) });
            setLaunching(false);
        } finally {
            setLaunching(false);
        }
    };

    return (
        <div className="flex h-full min-h-0 flex-col bg-background">
            {/* Row 1 — pure browser chrome: navigation, the URL, and close. Stable regardless of session state. */}
            <div className="flex items-center gap-2 border-b border-border bg-card px-2 py-1.5">
                <Button type="button" variant="outline" size="icon-sm" disabled={!nav.canGoBack} onClick={() => bridge()?.back()} title={t("Back")} aria-label={t("Back")}><ChevronLeft /></Button>
                <Button type="button" variant="outline" size="icon-sm" disabled={!nav.canGoForward} onClick={() => bridge()?.forward()} title={t("Forward")} aria-label={t("Forward")}><ChevronRight /></Button>
                <Button type="button" variant="outline" size="icon-sm" onClick={() => bridge()?.reload()} title={t("Reload")} aria-label={t("Reload")}><RotateCw /></Button>
                <Input
                    className="min-w-0 flex-1 font-mono"
                    value={urlField}
                    spellCheck={false}
                    onChange={(e) => setUrlField(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") go(); }}
                    placeholder="https://target/login"
                />
                <Button type="button" variant="outline" size="sm" disabled={!urlField.trim() && !currentUrl} onClick={() => void copyUrl()} title={t("Copy URL")} aria-label={t("Copy URL")}>{t("Copy URL")}</Button>
                <Button type="button" variant="ghost" size="sm" onClick={onClose} title={t("Close")}>{t("Close")}</Button>
            </div>
            {/* Row 2 — the attended-session flow: capture, then the one contextual action the state allows
                (mid-run continue / new scan / handoff resume). Growing here never moves the browser chrome. */}
            <div className="flex flex-wrap items-center gap-2 border-b border-border bg-card px-2 py-1.5">
                <Button type="button" size="sm" onClick={() => void capture()} title={t("Save cookies + localStorage (SPA Bearer) for the scan")}>{t("Capture session")}</Button>
                {captured?.header ? (
                    <Button type="button" variant="outline" size="sm" onClick={() => void copyCookies()} title={t("Copy the Cookie header to the clipboard (Repeater / curl)")}>{t("Copy cookies")}</Button>
                ) : null}
                {sessionRoles.length ? (
                    <label className="flex items-center gap-2 text-xs text-muted-foreground" title={t("Which manifest role the captured login belongs to")}>
                        {t("Logged-in role")}
                        <NativeSelect className="w-40" value={sessionRole} onChange={(e) => setSessionRole(e.target.value)}>
                            <option value="">{t("Choose role")}</option>
                            {sessionRoles.map((role) => <option key={role} value={role}>{role}</option>)}
                        </NativeSelect>
                    </label>
                ) : null}
                {captured && currentRunId && !handoffId ? (
                    <Button type="button" size="sm" className="bg-success text-on-success hover:bg-success/80" disabled={launching} onClick={() => void inject()} title={t("Apply the captured login and continue this diagnosis; restart it if stopped")}>
                        {launching ? t("Continuing…") : t("Continue this run →")}
                    </Button>
                ) : null}
                {captured && !handoffId ? (
                    <Button type="button" size="sm" className="bg-success text-on-success hover:bg-success/80" disabled={launching} onClick={() => void scan()} title={t("Start a new headless authenticated scan of {host} with this session", { host: captured.host })}>
                        {launching ? t("Starting…") : t("Scan (new run) →")}
                    </Button>
                ) : null}
                {handoffId && currentRunId ? (
                    <Button
                        type="button"
                        size="sm" className="bg-success text-on-success hover:bg-success/80"
                        disabled={launching || !captured}
                        onClick={() => void continueHandoff()}
                        title={t("Apply the captured login, restart the diagnosis if stopped, and return to Main")}
                    >
                        {launching ? t("Continuing…") : t("Logged in → continue")}
                    </Button>
                ) : null}
            </div>
            {handoffId ? (
                <div className="border-b border-warning bg-warning/15 px-3 py-2 text-xs text-warning">
                    {currentRunId
                        ? t("Scan waiting on you — log in / clear CAPTCHA here (real browser). Then Capture session and Logged in → continue (injects cookies into the scan).")
                        : t("Scan waiting on you — log in / clear CAPTCHA here (real browser). Then Capture session.")}
                </div>
            ) : null}
            {note ? <div role="status" className={`border-b border-border px-3 py-1 text-xs ${note.ok ? "text-primary" : "text-destructive"}`}>{note.text}</div> : null}
            {/* The native WebContentsView is positioned by main over this region. */}
            <div className="min-h-0 flex-1 bg-inset" ref={holderRef} />
        </div>
    );
}
