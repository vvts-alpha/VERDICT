import type { ReadinessCheck } from "@veritas/core";
import { DEFAULT_CONTEXT_TOKENS, MIN_CONTEXT_TOKENS, parseContextTokens } from "@veritas/core/llm-context";
import { MODEL_PROVIDERS, type ModelProvider } from "../src/model-providers";
import { useEffect, useRef, useState, type ReactNode } from "react";

// In-app settings, organized like a native app: a left category nav + a right pane (not one long form).
// Configure the AI (provider/models), network (proxy + automation browser), and Burp — persisted by the main
// process to userData/settings.json and applied to the NEXT assessment run (no restart).

const bridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.settings : undefined);
const appBridge = () => (typeof window !== "undefined" ? window.verdictDesktop?.app : undefined);

const EMPTY: DesktopSettings = { provider: "claude-cli" };
const SECTIONS = ["Models", "Agent", "Network", "OOB", "Burp", "About"] as const;
type Section = (typeof SECTIONS)[number];
type StringKey = Exclude<keyof DesktopSettings, "provider" | "burpScan" | "oobProvider" | "deepContextTokens" | "lightContextTokens">;

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

function TextArea({ value, onChange, ph, rows = 4 }: { value: string; onChange: (v: string) => void; ph?: string; rows?: number }) {
    return <textarea value={value} placeholder={ph} spellCheck={false} rows={rows} onChange={(e) => onChange(e.target.value)} />;
}

export function Settings({ onClose }: { onClose: () => void }) {
    const [s, setS] = useState<DesktopSettings>(EMPTY);
    const modelDrafts = useRef<Partial<Record<ModelProvider, Pick<DesktopSettings, "baseURL" | "apiKey" | "deepModel" | "lightModel" | "deepContextTokens" | "lightContextTokens">>>>({});
    const [section, setSection] = useState<Section>("Models");
    const [saved, setSaved] = useState(false);
    const [checking, setChecking] = useState(false);
    const [checks, setChecks] = useState<ReadinessCheck[]>([]);
    const [error, setError] = useState("");
    const editVersion = useRef(0);
    const [info, setInfo] = useState<AppInfo | null>(null);

    useEffect(() => {
        void bridge()?.get().then((v) => setS(v ?? EMPTY));
        void appBridge()?.info().then(setInfo);
    }, []);

    const set = <K extends keyof DesktopSettings>(k: K, v: DesktopSettings[K]): void => {
        setS((prev) => ({ ...prev, [k]: v }));
        setSaved(false);
        setChecks([]);
        editVersion.current++;
    };
    const setStr = (k: StringKey) => (v: string) => set(k, v);

    const selectProvider = (provider: ModelProvider): void => {
        if (provider === s.provider) return;
        const { baseURL, apiKey, deepModel, lightModel, deepContextTokens, lightContextTokens } = s;
        modelDrafts.current[s.provider] = { baseURL, apiKey, deepModel, lightModel, deepContextTokens, lightContextTokens };
        const draft = modelDrafts.current[provider] ?? { baseURL: MODEL_PROVIDERS[provider].baseURL };
        setS({ ...s, provider, baseURL: draft.baseURL, apiKey: draft.apiKey, deepModel: draft.deepModel, lightModel: draft.lightModel, deepContextTokens: draft.deepContextTokens, lightContextTokens: draft.lightContextTokens });
        setSaved(false);
        setChecks([]);
        setError("");
        editVersion.current++;
    };

    const save = async (): Promise<void> => {
        setError("");
        try {
            parseContextTokens(s.deepContextTokens);
            parseContextTokens(s.lightContextTokens);
            const v = await bridge()?.set(s);
            if (v) {
                setS(v);
                setSaved(true);
            }
        } catch (e) { setError(e instanceof Error ? e.message : "Settings could not be saved."); }
    };

    const check = async (): Promise<void> => {
        setChecking(true); setChecks([]); setError("");
        const version = editVersion.current;
        try { const result = await bridge()?.check(s) ?? []; if (version === editVersion.current) setChecks(result); }
        catch { setError("Connection checks could not finish. Try again shortly."); }
        finally { setChecking(false); }
    };

    const openai = s.provider !== "claude-cli";

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
                                    <select value={s.provider} onChange={(e) => selectProvider(e.target.value as ModelProvider)}>
                                        {Object.entries(MODEL_PROVIDERS).map(([value, preset]) => <option key={value} value={value}>{preset.label}</option>)}
                                    </select>
                                </Field>
                                {openai ? (
                                    <>
                                        {s.provider === "other" ? <p className="settings-note-inline">Use an OpenAI-compatible API endpoint, including a local model server.</p> : null}
                                        <Field label="Base URL"><Text value={s.baseURL ?? ""} onChange={setStr("baseURL")} ph={MODEL_PROVIDERS[s.provider].baseURL || "https://your-provider.example/v1"} /></Field>
                                        <Field label="API key"><Text value={s.apiKey ?? ""} onChange={setStr("apiKey")} ph="sk-…" type="password" /></Field>
                                    </>
                                ) : (
                                    <p className="settings-note-inline">The Claude subscription CLI needs the `claude` binary on PATH. Choose OpenCodeGo, OrcaRouter, or Other to use an API provider.</p>
                                )}
                                <div className="settings-sec">Model tiering</div>
                                <div className={openai ? "settings-grid" : undefined}>
                                    <Field label="Deep model" hint="high-value diagnosis / scenario"><Text value={s.deepModel ?? ""} onChange={setStr("deepModel")} ph={openai ? "Model ID from your provider" : "Claude model name"} /></Field>
                                    {openai ? <Field label="Deep max context" hint="tokens">
                                        <input type="number" min={MIN_CONTEXT_TOKENS} step="1" value={s.deepContextTokens ?? ""} placeholder={String(DEFAULT_CONTEXT_TOKENS)} onChange={(e) => set("deepContextTokens", e.target.value === "" ? undefined : e.target.valueAsNumber)} />
                                    </Field> : null}
                                    <Field label="Light model" hint="survey / methodology / low-value"><Text value={s.lightModel ?? ""} onChange={setStr("lightModel")} ph={openai ? "Model ID from your provider" : "Claude model name"} /></Field>
                                    {openai ? <Field label="Light max context" hint="tokens">
                                        <input type="number" min={MIN_CONTEXT_TOKENS} step="1" value={s.lightContextTokens ?? ""} placeholder={String(!s.lightModel || s.lightModel === s.deepModel ? s.deepContextTokens ?? DEFAULT_CONTEXT_TOKENS : DEFAULT_CONTEXT_TOKENS)} onChange={(e) => set("lightContextTokens", e.target.value === "" ? undefined : e.target.valueAsNumber)} />
                                    </Field> : null}
                                </div>
                                <p className="settings-note-inline">{openai
                                    ? "Max context includes input and response. VERDICT reserves room for replies and summarizes older history as it fills. Blank defaults to 256,000 tokens; Light inherits Deep when they use the same model. Use each model's supported limit."
                                    : "Claude manages its context window and automatic compaction."}</p>
                            </>
                        ) : null}

                        {section === "Agent" ? (
                            <>
                                <p className="settings-note-inline">
                                    <b>Operator context</b> is standing FACTS about your targets — auth shape, tenant model, where the API lives. It pre-fills the New form on every run and is appended to each stage's system prompt (<code>--context</code>). Additive only: it guides the agent, it never overrides the safety / scope / evidence-discipline rules. Leave blank if your targets differ each time (set it per run instead).
                                </p>
                                <Field label="Operator context" hint="target facts — pre-fills New; editable per run">
                                    <TextArea
                                        value={s.operatorContext ?? ""}
                                        onChange={setStr("operatorContext")}
                                        rows={6}
                                        ph={"e.g. Auth is a JWT in the X-Auth header.\nTenant id is the last path segment.\nThe API is GraphQL at /graphql.\nTest accounts share org 42."}
                                    />
                                </Field>
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

                        {section === "About" ? (
                            <>
                                <p className="settings-note-inline"><b>VERDICT</b> — autonomous web / API pentest agent. AI drives · evidence proves · scans behind login.</p>
                                <div className="settings-about">
                                    <div className="settings-about-row"><span>Version</span><b>{info?.version ?? "…"}</b></div>
                                    <div className="settings-about-row"><span>Electron</span><b>{info?.electron ?? "…"}</b></div>
                                    <div className="settings-about-row"><span>Node</span><b>{info?.node ?? "…"}</b></div>
                                    <div className="settings-about-row"><span>Chromium</span><b>{info?.chrome ?? "…"}</b></div>
                                </div>
                            </>
                        ) : null}
                    </div>
                </div>

                <div className="settings-checks" aria-live="polite">
                    {checks.map((c) => <p key={c.name} style={{ color: c.status === "error" ? "var(--err)" : c.status === "ok" ? "var(--ok)" : "var(--muted)" }}><b>{c.name}: {c.status}</b> — {c.message}</p>)}
                    {error ? <p role="alert">{error}</p> : null}
                </div>
                <div className="settings-actions">
                    <button type="button" className="settings-save" disabled={checking} onClick={() => void check()}>{checking ? "Checking…" : "Check connections"}</button>
                    <button type="button" className="settings-save" onClick={() => void save()}>Save</button>
                    <small>Checks use the values above without saving. Model checks send short test requests and may use quota.</small>
                    {saved ? <span className="settings-saved">saved — applies to the next run</span> : null}
                </div>
            </div>
        </div>
    );
}
