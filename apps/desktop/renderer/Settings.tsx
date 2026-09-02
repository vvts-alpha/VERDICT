import { useEffect, useState, type ReactNode } from "react";

// In-app settings, organized like a native app: a left category nav + a right pane (not one long form).
// Configure the AI (provider/models), network (proxy + automation browser), and Burp — persisted by the main
// process to userData/settings.json and applied to the NEXT assessment run (no restart).

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.settings : undefined);

const EMPTY: DesktopSettings = { provider: "claude-cli" };
const SECTIONS = ["Models", "Network", "OOB", "Burp"] as const;
type Section = (typeof SECTIONS)[number];
type StringKey = Exclude<keyof DesktopSettings, "provider" | "burpScan" | "oobProvider">;

// Hoisted: defining these inside Settings remounted every <input> on each keystroke (focus lost after 1 char).
function Field({ label, hint, children }: { label: string; hint?: string; children: ReactNode }) {
    return (
        <label className="settings-field">
            <span>
                {label}
                {hint ? <em>{hint}</em> : null}
            </span>
            {children}
        </label>
    );
}

function Text({
    value,
    onChange,
    ph,
    type = "text",
}: {
    value: string;
    onChange: (v: string) => void;
    ph?: string;
    type?: string;
}) {
    return <input type={type} value={value} placeholder={ph} spellCheck={false} onChange={(e) => onChange(e.target.value)} />;
}

export function Settings({ onClose }: { onClose: () => void }) {
    const [s, setS] = useState<DesktopSettings>(EMPTY);
    const [section, setSection] = useState<Section>("Models");
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        void bridge()?.get().then((v) => setS(v ?? EMPTY));
    }, []);

    const set = <K extends keyof DesktopSettings>(k: K, v: DesktopSettings[K]): void => {
        setS((prev) => ({ ...prev, [k]: v }));
        setSaved(false);
    };
    const setStr = (k: StringKey) => (v: string) => set(k, v);

    const save = async (): Promise<void> => {
        const v = await bridge()?.set(s);
        if (v) {
            setS(v);
            setSaved(true);
        }
    };

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
                        {section === "Models" ? (
                            <>
                                <Field label="Provider">
                                    <select value={s.provider} onChange={(e) => set("provider", e.target.value as DesktopSettings["provider"])}>
                                        <option value="claude-cli">Claude (subscription CLI)</option>
                                        <option value="openai">OpenAI-compatible (OpenCodeGo / OpenAI / local)</option>
                                    </select>
                                </Field>
                                {openai ? (
                                    <>
                                        <Field label="Base URL"><Text value={s.baseURL ?? ""} onChange={setStr("baseURL")} ph="https://opencode.ai/zen/go/v1" /></Field>
                                        <Field label="API key"><Text value={s.apiKey ?? ""} onChange={setStr("apiKey")} ph="sk-…" type="password" /></Field>
                                    </>
                                ) : (
                                    <p className="settings-note-inline">The Claude subscription CLI needs the `claude` binary on PATH. Switch to OpenAI-compatible to use OpenCodeGo / a local model.</p>
                                )}
                                <div className="settings-sec">Model tiering</div>
                                <Field label="Deep model" hint="high-value diagnosis / scenario"><Text value={s.deepModel ?? ""} onChange={setStr("deepModel")} ph={openai ? "hy3" : "claude-opus-4-8"} /></Field>
                                <Field label="Light model" hint="survey / methodology / low-value"><Text value={s.lightModel ?? ""} onChange={setStr("lightModel")} ph={openai ? "hy3" : "claude-sonnet-5"} /></Field>
                            </>
                        ) : null}

                        {section === "Network" ? (
                            <>
                                <Field label="Upstream proxy" hint="Browser tab + scan traffic (browser + http), e.g. Burp — blank = direct"><Text value={s.proxy ?? ""} onChange={setStr("proxy")} ph="http://127.0.0.1:8080" /></Field>
                                <Field label="Chromium path" hint="headless scan browser — blank = installed Chrome/Edge"><Text value={s.browserPath ?? ""} onChange={setStr("browserPath")} ph="C:\Program Files\Google\Chrome\Application\chrome.exe" /></Field>
                            </>
                        ) : null}

                        {section === "OOB" ? (
                            <>
                                <p className="settings-note-inline">
                                    Blind SSRF/XXE/SQLi need an out-of-band callback host. Interactsh is free (public server is opt-in third-party egress). Burp Collaborator needs the Audit REST extension.
                                </p>
                                <Field label="Provider">
                                    <select
                                        value={s.oobProvider ?? ""}
                                        onChange={(e) => {
                                            const v = e.target.value;
                                            set("oobProvider", v === "interactsh" || v === "burp" || v === "off" ? v : undefined);
                                        }}
                                    >
                                        <option value="">Auto (Interactsh if a server is set, else Burp Audit REST, else off)</option>
                                        <option value="off">Off</option>
                                        <option value="interactsh">Interactsh (free)</option>
                                        <option value="burp">Burp Collaborator (Audit REST)</option>
                                    </select>
                                </Field>
                                {s.oobProvider === "interactsh" || !s.oobProvider ? (
                                    <>
                                        <Field label="Interactsh server" hint="hostname or URL — blank with Interactsh selected = oast.pro">
                                            <Text value={s.interactshServer ?? ""} onChange={setStr("interactshServer")} ph="oast.pro" />
                                        </Field>
                                        <Field label="Interactsh token" hint="only for a protected / self-hosted server">
                                            <Text value={s.interactshToken ?? ""} onChange={setStr("interactshToken")} ph="token" type="password" />
                                        </Field>
                                    </>
                                ) : null}
                                {s.oobProvider === "burp" ? (
                                    <p className="settings-note-inline">Uses the Audit REST URL on the Burp tab (default http://127.0.0.1:1338). Collaborator must be enabled in the Burp project.</p>
                                ) : null}
                            </>
                        ) : null}

                        {section === "Burp" ? (
                            <>
                                <label className="settings-toggle">
                                    <input type="checkbox" checked={!!s.burpScan} onChange={(e) => set("burpScan", e.target.checked)} />
                                    <span>Run a Burp active scan after diagnosis on each run <em>needs a REST or Audit endpoint below</em></span>
                                </label>
                                <div className="settings-sec">Audit REST <em>scans behind login (recommended)</em></div>
                                <Field label="Audit REST URL" hint="the VERDICT Burp Audit extension, e.g. http://127.0.0.1:1338"><Text value={s.burpAuditApi ?? ""} onChange={setStr("burpAuditApi")} ph="http://127.0.0.1:1338" /></Field>
                                <Field label="Audit token"><Text value={s.burpAuditToken ?? ""} onChange={setStr("burpAuditToken")} ph="token" type="password" /></Field>
                                <div className="settings-sec">Burp Pro REST <em>fallback</em></div>
                                <Field label="REST API URL"><Text value={s.burpApi ?? ""} onChange={setStr("burpApi")} ph="http://127.0.0.1:1337" /></Field>
                                <Field label="API key"><Text value={s.burpApiKey ?? ""} onChange={setStr("burpApiKey")} ph="key" type="password" /></Field>
                                <Field label="Resource pool"><Text value={s.burpResourcePool ?? ""} onChange={setStr("burpResourcePool")} ph="default" /></Field>
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
