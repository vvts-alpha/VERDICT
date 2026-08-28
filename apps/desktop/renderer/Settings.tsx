import { useEffect, useState, type ReactNode } from "react";

// In-app settings, organized like a native app: a left category nav + a right pane (not one long form).
// Configure the AI (provider/models), network (proxy + automation browser), and Burp — persisted by the main
// process to userData/settings.json and applied to the NEXT assessment run (no restart).

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.settings : undefined);

const EMPTY: DesktopSettings = { provider: "claude-cli" };
const SECTIONS = ["AI provider", "Models", "Network", "Burp"] as const;
type Section = (typeof SECTIONS)[number];

export function Settings({ onClose }: { onClose: () => void }) {
    const [s, setS] = useState<DesktopSettings>(EMPTY);
    const [section, setSection] = useState<Section>("AI provider");
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        void bridge()?.get().then((v) => setS(v ?? EMPTY));
    }, []);

    const set = <K extends keyof DesktopSettings>(k: K, v: DesktopSettings[K]): void => {
        setS((prev) => ({ ...prev, [k]: v }));
        setSaved(false);
    };

    const save = async (): Promise<void> => {
        const v = await bridge()?.set(s);
        if (v) {
            setS(v);
            setSaved(true);
        }
    };

    const Field = ({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) => (
        <label className="settings-field">
            <span>
                {label}
                {hint ? <em>{hint}</em> : null}
            </span>
            {children}
        </label>
    );
    const Text = ({ k, ph, type = "text" }: { k: keyof DesktopSettings; ph?: string; type?: string }) => (
        <input type={type} value={(s[k] as string) ?? ""} placeholder={ph} spellCheck={false} onChange={(e) => set(k, e.target.value)} />
    );

    const openai = s.provider === "openai";

    return (
        <div className="settings-overlay" onClick={onClose}>
            <div className="settings-card" onClick={(e) => e.stopPropagation()}>
                <div className="settings-head">
                    <h2>Settings</h2>
                    <button type="button" className="settings-x" onClick={onClose} aria-label="Close">×</button>
                </div>

                <div className="settings-body">
                    <nav className="settings-nav">
                        {SECTIONS.map((sec) => (
                            <button key={sec} type="button" className={section === sec ? "active" : ""} onClick={() => setSection(sec)}>
                                {sec}
                            </button>
                        ))}
                    </nav>

                    <div className="settings-pane">
                        {section === "AI provider" ? (
                            <>
                                <Field label="Provider">
                                    <select value={s.provider} onChange={(e) => set("provider", e.target.value as DesktopSettings["provider"])}>
                                        <option value="claude-cli">Claude (subscription CLI)</option>
                                        <option value="openai">OpenAI-compatible (OpenCodeGo / OpenAI / local)</option>
                                    </select>
                                </Field>
                                {openai ? (
                                    <>
                                        <Field label="Base URL"><Text k="baseURL" ph="https://opencode.ai/zen/go/v1" /></Field>
                                        <Field label="API key"><Text k="apiKey" ph="sk-…" type="password" /></Field>
                                    </>
                                ) : (
                                    <p className="settings-note-inline">The Claude subscription CLI needs the `claude` binary on PATH. Switch to OpenAI-compatible to use OpenCodeGo / a local model.</p>
                                )}
                            </>
                        ) : null}

                        {section === "Models" ? (
                            <>
                                <Field label="Deep model" hint="high-value diagnosis / scenario"><Text k="deepModel" ph={openai ? "hy3" : "claude-opus-4-8"} /></Field>
                                <Field label="Light model" hint="survey / methodology / low-value"><Text k="lightModel" ph={openai ? "hy3" : "claude-sonnet-5"} /></Field>
                            </>
                        ) : null}

                        {section === "Network" ? (
                            <>
                                <Field label="Upstream proxy" hint="all scan traffic (browser + http), e.g. Burp — blank = direct"><Text k="proxy" ph="http://127.0.0.1:8080" /></Field>
                                <Field label="Chromium path" hint="the headless scan browser (blank = env / bundled)"><Text k="browserPath" ph="/path/to/chrome" /></Field>
                            </>
                        ) : null}

                        {section === "Burp" ? (
                            <>
                                <label className="settings-toggle">
                                    <input type="checkbox" checked={!!s.burpScan} onChange={(e) => set("burpScan", e.target.checked)} />
                                    <span>Run a Burp active scan after diagnosis on each run <em>needs a REST or Audit endpoint below</em></span>
                                </label>
                                <div className="settings-sec">Audit REST <em>scans behind login (recommended)</em></div>
                                <Field label="Audit REST URL" hint="the VERDICT Burp Audit extension, e.g. http://127.0.0.1:1338"><Text k="burpAuditApi" ph="http://127.0.0.1:1338" /></Field>
                                <Field label="Audit token"><Text k="burpAuditToken" ph="token" type="password" /></Field>
                                <div className="settings-sec">Burp Pro REST <em>fallback</em></div>
                                <Field label="REST API URL"><Text k="burpApi" ph="http://127.0.0.1:1337" /></Field>
                                <Field label="API key"><Text k="burpApiKey" ph="key" type="password" /></Field>
                                <Field label="Resource pool"><Text k="burpResourcePool" ph="default" /></Field>
                            </>
                        ) : null}
                    </div>
                </div>

                <div className="settings-actions">
                    <button type="button" className="settings-save" onClick={() => void save()}>Save</button>
                    {saved ? <span className="settings-saved">saved — applies to the next run</span> : null}
                </div>
            </div>
        </div>
    );
}
