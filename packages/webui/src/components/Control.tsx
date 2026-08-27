import { useState } from "react";
import type { StateView } from "@veritas/core";
import { useRole } from "../api";

// Operator control surface for a running (or resumable) assessment: add a target URL for extra investigation,
// and reconfigure the live scan (rate / max-screens / widen scope). Both post to the control-channel endpoints;
// changes land at the pilot's next between-screens checkpoint. Operator-only (viewers get a read-only note).
export function Control({ view }: { view: StateView }) {
    const { canWrite } = useRole();
    const [url, setUrl] = useState("");
    const [extend, setExtend] = useState(false);
    const [rate, setRate] = useState("");
    const [maxScreens, setMaxScreens] = useState("");
    const [addHost, setAddHost] = useState("");
    const [note, setNote] = useState<{ ok: boolean; text: string } | null>(null);
    const [busy, setBusy] = useState(false);

    if (!canWrite) {
        return (
            <div className="newform">
                <p className="mode-prompt">Read-only (viewer). Live control — add target / reconfigure — is operator-only.</p>
            </div>
        );
    }

    const send = async (path: string, body: unknown, okText: string): Promise<void> => {
        setBusy(true);
        try {
            const r = await fetch(`/api/assessments/${view.id}/${path}`, {
                method: "POST",
                headers: { "content-type": "application/json" },
                body: JSON.stringify(body),
            });
            if (r.ok) {
                setNote({ ok: true, text: okText });
            } else {
                const err = (await r.json().catch(() => ({}))) as { error?: string };
                setNote({ ok: false, text: err.error ?? `failed (${r.status})` });
            }
        } catch (e) {
            setNote({ ok: false, text: String(e) });
        } finally {
            setBusy(false);
        }
    };

    const addTarget = async (): Promise<void> => {
        const u = url.trim();
        if (!u) return;
        await send("add-target", { url: u, extendScope: extend }, `queued ${u} — diagnoses now if the run is active, otherwise on the next Resume`);
        setUrl("");
    };

    const reconfigure = async (): Promise<void> => {
        const body: Record<string, unknown> = {};
        if (rate.trim()) body.rateMs = Number(rate);
        if (maxScreens.trim()) body.maxScreens = Number(maxScreens);
        if (addHost.trim()) body.addHosts = [addHost.trim()];
        if (Object.keys(body).length === 0) {
            setNote({ ok: false, text: "nothing to apply — set a rate, max-screens, or a host" });
            return;
        }
        await send("reconfigure", body, "applied — takes effect at the next screen");
        setRate("");
        setMaxScreens("");
        setAddHost("");
    };

    return (
        <div className="newform">
            <details className="nf-section" open>
                <summary>Add target — investigate a specific URL</summary>
                <div className="nf-field">
                    <span>URL (must be in scope, or tick “extend scope”)</span>
                    <input value={url} placeholder="https://host/path" onChange={(e) => setUrl(e.target.value)} />
                </div>
                <div className="nf-checks">
                    <label>
                        <input type="checkbox" checked={extend} onChange={(e) => setExtend(e.target.checked)} />
                        extend scope to this host — only if it is within your authorization
                    </label>
                </div>
                <div className="nf-actions">
                    <button type="button" className="nf-launch" disabled={busy || !url.trim()} onClick={() => void addTarget()}>
                        Add target
                    </button>
                </div>
            </details>

            <details className="nf-section" open>
                <summary>Reconfigure the running scan (live)</summary>
                <div className="nf-checks">
                    <span className="nf-field nf-inline">
                        <span>rate ms</span>
                        <input value={rate} inputMode="numeric" placeholder="250" onChange={(e) => setRate(e.target.value)} />
                    </span>
                    <span className="nf-field nf-inline">
                        <span>max screens</span>
                        <input value={maxScreens} inputMode="numeric" placeholder="40" onChange={(e) => setMaxScreens(e.target.value)} />
                    </span>
                </div>
                <div className="nf-field">
                    <span>add in-scope host</span>
                    <input value={addHost} placeholder="api.host" onChange={(e) => setAddHost(e.target.value)} />
                </div>
                <div className="nf-actions">
                    <button type="button" className="nf-launch" disabled={busy} onClick={() => void reconfigure()}>
                        Apply
                    </button>
                </div>
            </details>

            {note ? <p className={note.ok ? "ctl-ok" : "nf-err"}>{note.text}</p> : null}
            <p className="mode-prompt">
                Changes land at the next between-screens checkpoint. Proxy is restart-class — change it by stopping and resuming the run with a new proxy.
            </p>
        </div>
    );
}
