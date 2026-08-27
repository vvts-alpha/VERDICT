import { useEffect, useState } from "react";

// In-app settings: switch the AI (provider/endpoint/key) and the Deep + Light models, plus the automation browser
// path. Persisted by the main process to userData/settings.json and applied to the NEXT assessment run (no restart).

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.settings : undefined);

const EMPTY: DesktopSettings = { provider: "claude-cli" };

export function Settings({ onClose }: { onClose: () => void }) {
    const [s, setS] = useState<DesktopSettings>(EMPTY);
    const [saved, setSaved] = useState(false);

    useEffect(() => {
        void bridge()?.get().then((v) => setS(v ?? EMPTY));
    }, []);

    const field = <K extends keyof DesktopSettings>(k: K, v: DesktopSettings[K]): void => {
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

    const openai = s.provider === "openai";

    return (
        <div className="settings-overlay" onClick={onClose}>
            <div className="settings-card" onClick={(e) => e.stopPropagation()}>
                <div className="settings-head">
                    <h2>Settings</h2>
                    <button type="button" className="settings-x" onClick={onClose} aria-label="Close">×</button>
                </div>

                <div className="settings-sec">AI provider</div>
                <div className="settings-field">
                    <span>Provider</span>
                    <select value={s.provider} onChange={(e) => field("provider", e.target.value as DesktopSettings["provider"])}>
                        <option value="claude-cli">Claude (subscription CLI)</option>
                        <option value="openai">OpenAI-compatible (OpenCodeGo / OpenAI / local)</option>
                    </select>
                </div>
                {openai ? (
                    <>
                        <div className="settings-field">
                            <span>Base URL</span>
                            <input value={s.baseURL ?? ""} placeholder="https://opencode.ai/zen/go/v1" spellCheck={false} onChange={(e) => field("baseURL", e.target.value)} />
                        </div>
                        <div className="settings-field">
                            <span>API key</span>
                            <input type="password" value={s.apiKey ?? ""} placeholder="sk-…" spellCheck={false} onChange={(e) => field("apiKey", e.target.value)} />
                        </div>
                    </>
                ) : null}

                <div className="settings-sec">Models</div>
                <div className="settings-grid">
                    <div className="settings-field">
                        <span>Deep model <em>high-value diagnosis / scenario</em></span>
                        <input value={s.deepModel ?? ""} placeholder={openai ? "hy3" : "claude-opus-4-8"} spellCheck={false} onChange={(e) => field("deepModel", e.target.value)} />
                    </div>
                    <div className="settings-field">
                        <span>Light model <em>survey / methodology / low-value</em></span>
                        <input value={s.lightModel ?? ""} placeholder={openai ? "hy3" : "claude-sonnet-5"} spellCheck={false} onChange={(e) => field("lightModel", e.target.value)} />
                    </div>
                </div>

                <div className="settings-sec">Network</div>
                <div className="settings-field">
                    <span>Upstream proxy <em>routes all scan traffic (browser + http), e.g. Burp — blank = direct</em></span>
                    <input value={s.proxy ?? ""} placeholder="http://127.0.0.1:8080" spellCheck={false} onChange={(e) => field("proxy", e.target.value)} />
                </div>
                <div className="settings-field">
                    <span>Chromium path <em>for the headless scan browser (leave blank to use the env / bundled)</em></span>
                    <input value={s.browserPath ?? ""} placeholder="/path/to/chrome" spellCheck={false} onChange={(e) => field("browserPath", e.target.value)} />
                </div>

                <div className="settings-actions">
                    <button type="button" className="settings-save" onClick={() => void save()}>Save</button>
                    {saved ? <span className="settings-saved">saved — applies to the next run</span> : null}
                </div>
            </div>
        </div>
    );
}
