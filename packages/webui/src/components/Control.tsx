import { useState } from "react";
import type { StateView } from "@veritas/core";
import { useRole } from "../api";
import { Disclosure } from "./Disclosure";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";

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
            <div className="p-2">
                <p className="text-xs text-muted-foreground">Read-only (viewer). Live control — add target / reconfigure — is operator-only.</p>
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
        <div className="space-y-4 pb-10">
            <Disclosure defaultOpen title="Add target — investigate a specific URL" className="p-4" triggerClassName="font-semibold text-foreground">
                <div className="mt-3 space-y-3">
                <label className="flex flex-col gap-1 text-xs text-muted-foreground">
                    URL (must be in scope, or tick “extend scope”)
                    <Input value={url} placeholder="https://host/path" onChange={(e) => setUrl(e.target.value)} />
                </label>
                <label className="flex items-center gap-2">
                    <Checkbox checked={extend} onCheckedChange={(checked) => setExtend(checked === true)} />
                    extend scope to this host — only if it is within your authorization
                </label>
                <Button type="button" disabled={busy || !url.trim()} onClick={() => void addTarget()}>Add target</Button>
                </div>
            </Disclosure>

            <Disclosure defaultOpen title="Reconfigure the running scan (live)" className="p-4" triggerClassName="font-semibold text-foreground">
                <div className="mt-3 space-y-3">
                <div className="flex flex-wrap gap-3">
                    <label className="flex flex-col gap-1 text-xs text-muted-foreground">rate ms
                        <Input className="w-28" value={rate} inputMode="numeric" placeholder="250" onChange={(e) => setRate(e.target.value)} />
                    </label>
                    <label className="flex flex-col gap-1 text-xs text-muted-foreground">max screens
                        <Input className="w-28" value={maxScreens} inputMode="numeric" placeholder="40" onChange={(e) => setMaxScreens(e.target.value)} />
                    </label>
                </div>
                <label className="flex flex-col gap-1 text-xs text-muted-foreground">add in-scope host
                    <Input value={addHost} placeholder="api.host" onChange={(e) => setAddHost(e.target.value)} />
                </label>
                <Button type="button" disabled={busy} onClick={() => void reconfigure()}>Apply</Button>
                </div>
            </Disclosure>

            {note ? <p role="status" className={note.ok ? "text-primary" : "text-destructive"}>{note.text}</p> : null}
            <p className="text-xs text-muted-foreground">
                Changes land at the next between-screens checkpoint. Proxy is restart-class — change it by stopping and resuming the run with a new proxy.
            </p>
        </div>
    );
}
