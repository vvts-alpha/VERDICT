import type { ReadinessCheck } from "@veritas/core";
import { DEFAULT_CONTEXT_TOKENS, MIN_CONTEXT_TOKENS, parseContextTokens } from "@veritas/core/llm-context";
import { MODEL_PROVIDERS, type ModelProvider } from "../src/model-providers";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { X } from "lucide-react";
import { Button } from "@veritas/webui/ui/button";
import { Checkbox } from "@veritas/webui/ui/checkbox";
import { Input } from "@veritas/webui/ui/input";
import { NativeSelect } from "@veritas/webui/ui/native-select";
import { Textarea } from "@veritas/webui/ui/textarea";

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
        <label className="my-2 flex flex-col gap-1 text-xs">
            <span className="text-muted-foreground">
                {label}
                {hint ? <em className="ml-2 text-[11px] not-italic">{hint}</em> : null}
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
    return <Input type={type} value={value} placeholder={ph} spellCheck={false} onChange={(e) => onChange(e.target.value)} />;
}

function TextArea({ value, onChange, ph, rows = 4 }: { value: string; onChange: (v: string) => void; ph?: string; rows?: number }) {
    return <Textarea value={value} placeholder={ph} spellCheck={false} rows={rows} onChange={(e) => onChange(e.target.value)} />;
}

export function Settings({ onClose, registerLeaveGuard }: { onClose: () => void; registerLeaveGuard?: (fn: () => boolean) => void }) {
    const [s, setS] = useState<DesktopSettings>(EMPTY);
    const modelDrafts = useRef<Partial<Record<ModelProvider, Pick<DesktopSettings, "baseURL" | "apiKey" | "deepModel" | "lightModel" | "deepContextTokens" | "lightContextTokens">>>>({});
    const [section, setSection] = useState<Section>("Models");
    const [saved, setSaved] = useState(false);
    // True while the form holds edits the main process has not stored — guards the silent-discard close paths.
    const [dirty, setDirty] = useState(false);
    // Closing with unsaved edits shows an inline confirm bar instead of a native confirm() dialog.
    const [confirmDiscard, setConfirmDiscard] = useState(false);
    const [checking, setChecking] = useState(false);
    const [checks, setChecks] = useState<ReadinessCheck[]>([]);
    const [error, setError] = useState("");
    const editVersion = useRef(0);
    const [info, setInfo] = useState<AppInfo | null>(null);

    useEffect(() => {
        void bridge()?.get().then((v) => {
            setS(v ?? EMPTY);
            setDirty(false);
        });
        void appBridge()?.info().then(setInfo);
    }, []);

    const set = <K extends keyof DesktopSettings>(k: K, v: DesktopSettings[K]): void => {
        setS((prev) => ({ ...prev, [k]: v }));
        setSaved(false);
        setDirty(true);
        setConfirmDiscard(false); // fresh edits re-arm the close guard
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
        setDirty(true);
        setConfirmDiscard(false);
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
                setDirty(false);
                setConfirmDiscard(false);
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

    // × / Esc / top-nav navigation must not silently discard edits — they show the inline confirm
    // bar first. The guard veto (return false) keeps the shell from switching views; Discard calls
    // onClose, which bypasses the guard by construction and continues to the pending destination.
    useEffect(() => {
        registerLeaveGuard?.(() => {
            if (!dirty) return true;
            setConfirmDiscard(true);
            return false;
        });
    }, [dirty, registerLeaveGuard]);
    const requestClose = (): void => {
        if (dirty) {
            setConfirmDiscard(true);
            return;
        }
        onClose();
    };

    return (
        <div className="h-full min-h-0 overflow-auto px-4 py-10">
            <div role="dialog" aria-labelledby="settings-title" className="mx-auto flex w-full max-w-[720px] flex-col rounded-xl border border-border bg-card px-5 py-4 shadow-xl" onKeyDown={(e) => { if (e.key === "Escape") { e.stopPropagation(); requestClose(); } }}>
                <div className="mb-2 flex items-center justify-between border-b border-border pb-3">
                    <h2 id="settings-title" className="text-base font-semibold">Settings</h2>
                    <Button type="button" variant="ghost" size="icon-sm" onClick={requestClose} aria-label="Close"><X /></Button>
                </div>
                {confirmDiscard ? (
                    <div className="my-2 flex items-center gap-2 rounded border border-warning bg-warning/15 p-2 text-xs text-warning" role="alert">
                        <span className="flex-1">Unsaved changes — discard them?</span>
                        <Button type="button" size="sm" variant="destructive" onClick={onClose}>Discard</Button>
                        <Button type="button" size="sm" variant="outline" onClick={() => setConfirmDiscard(false)}>Keep editing</Button>
                    </div>
                ) : null}

                <div className="grid min-h-0 flex-1 grid-cols-[150px_minmax(0,1fr)] gap-5 overflow-hidden">
                    <nav className="flex flex-col gap-1 overflow-y-auto border-r border-border pr-3" aria-label="Settings categories">
                        {SECTIONS.map((sec) => (
                            <Button key={sec} type="button" variant="ghost" className={`justify-start ${section === sec ? "bg-accent text-primary" : "text-muted-foreground"}`} onClick={() => setSection(sec)}>
                                {sec}
                            </Button>
                        ))}
                    </nav>

                    <div className="min-h-0 overflow-y-auto pr-1">
                        {section === "Models" ? (
                            <>
                                <Field label="Provider">
                                    <NativeSelect className="w-full" value={s.provider} onChange={(e) => selectProvider(e.target.value as ModelProvider)}>
                                        {Object.entries(MODEL_PROVIDERS).map(([value, preset]) => <option key={value} value={value}>{preset.label}</option>)}
                                    </NativeSelect>
                                </Field>
                                {openai ? (
                                    <>
                                        {s.provider === "other" ? <p className="my-2 text-xs leading-relaxed text-muted-foreground">Use an OpenAI-compatible API endpoint, including a local model server.</p> : null}
                                        <Field label="Base URL"><Text value={s.baseURL ?? ""} onChange={setStr("baseURL")} ph={MODEL_PROVIDERS[s.provider].baseURL || "https://your-provider.example/v1"} /></Field>
                                        <Field label="API key"><Text value={s.apiKey ?? ""} onChange={setStr("apiKey")} ph="sk-…" type="password" /></Field>
                                    </>
                                ) : (
                                    <p className="my-2 text-xs leading-relaxed text-muted-foreground">The Claude subscription CLI needs the `claude` binary on PATH. Choose OpenCodeGo, OrcaRouter, or Other to use an API provider.</p>
                                )}
                                <div className="mt-4 mb-2 text-xs font-semibold uppercase tracking-wide text-primary">Model tiering</div>
                                <div className={openai ? "grid grid-cols-2 items-end gap-x-4" : undefined}>
                                    <Field label="Deep model" hint="high-value diagnosis / scenario"><Text value={s.deepModel ?? ""} onChange={setStr("deepModel")} ph={openai ? "Model ID from your provider" : "Claude model name"} /></Field>
                                    {openai ? <Field label="Deep max context" hint="tokens">
                                        <Input type="number" min={MIN_CONTEXT_TOKENS} step="1" value={s.deepContextTokens ?? ""} placeholder={String(DEFAULT_CONTEXT_TOKENS)} onChange={(e) => set("deepContextTokens", e.target.value === "" ? undefined : e.target.valueAsNumber)} />
                                    </Field> : null}
                                    <Field label="Light model" hint="survey / methodology / low-value"><Text value={s.lightModel ?? ""} onChange={setStr("lightModel")} ph={openai ? "Model ID from your provider" : "Claude model name"} /></Field>
                                    {openai ? <Field label="Light max context" hint="tokens">
                                        <Input type="number" min={MIN_CONTEXT_TOKENS} step="1" value={s.lightContextTokens ?? ""} placeholder={String(!s.lightModel || s.lightModel === s.deepModel ? s.deepContextTokens ?? DEFAULT_CONTEXT_TOKENS : DEFAULT_CONTEXT_TOKENS)} onChange={(e) => set("lightContextTokens", e.target.value === "" ? undefined : e.target.valueAsNumber)} />
                                    </Field> : null}
                                </div>
                                <p className="my-2 text-xs leading-relaxed text-muted-foreground">{openai
                                    ? "Max context includes input and response. VERDICT reserves room for replies and summarizes older history as it fills. Blank defaults to 256,000 tokens; Light inherits Deep when they use the same model. Use each model's supported limit."
                                    : "Claude manages its context window and automatic compaction."}</p>
                            </>
                        ) : null}

                        {section === "Agent" ? (
                            <>
                                <p className="my-2 text-xs leading-relaxed text-muted-foreground">
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
                                <p className="my-2 text-xs leading-relaxed text-muted-foreground">
                                    Blind SSRF/XXE/SQLi need an out-of-band callback host. Interactsh is free (public server is opt-in third-party egress). Burp Collaborator needs the Audit REST extension.
                                </p>
                                <Field label="Provider">
                                    <NativeSelect className="w-full"
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
                                    </NativeSelect>
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
                                    <p className="my-2 text-xs leading-relaxed text-muted-foreground">Uses the Audit REST URL on the Burp tab (default http://127.0.0.1:1338). Collaborator must be enabled in the Burp project.</p>
                                ) : null}
                            </>
                        ) : null}

                        {section === "Burp" ? (
                            <>
                                <label className="my-3 flex items-start gap-2 text-sm">
                                    <Checkbox checked={!!s.burpScan} onCheckedChange={(checked) => set("burpScan", checked === true)} />
                                    <span>Run a Burp active scan after diagnosis on each run <em className="block text-xs not-italic text-muted-foreground">needs a REST or Audit endpoint below</em></span>
                                </label>
                                <div className="mt-4 mb-2 text-xs font-semibold uppercase tracking-wide text-primary">Audit REST <em>scans behind login (recommended)</em></div>
                                <Field label="Audit REST URL" hint="the VERDICT Burp Audit extension, e.g. http://127.0.0.1:1338"><Text value={s.burpAuditApi ?? ""} onChange={setStr("burpAuditApi")} ph="http://127.0.0.1:1338" /></Field>
                                <Field label="Audit token"><Text value={s.burpAuditToken ?? ""} onChange={setStr("burpAuditToken")} ph="token" type="password" /></Field>
                                <div className="mt-4 mb-2 text-xs font-semibold uppercase tracking-wide text-primary">Burp Pro REST <em>fallback</em></div>
                                <Field label="REST API URL"><Text value={s.burpApi ?? ""} onChange={setStr("burpApi")} ph="http://127.0.0.1:1337" /></Field>
                                <Field label="API key"><Text value={s.burpApiKey ?? ""} onChange={setStr("burpApiKey")} ph="key" type="password" /></Field>
                                <Field label="Resource pool"><Text value={s.burpResourcePool ?? ""} onChange={setStr("burpResourcePool")} ph="default" /></Field>
                            </>
                        ) : null}

                        {section === "About" ? (
                            <>
                                <img src="/verdict-main.png" alt="VERDICT" className="mt-2 w-full rounded-md border border-border" />
                                <p className="my-2 text-xs leading-relaxed text-muted-foreground"><b>VERDICT</b> — autonomous web / API pentest agent. AI drives · evidence proves · scans behind login.</p>
                                <div className="mt-3 text-sm [&>div]:flex [&>div]:justify-between [&>div]:border-b [&>div]:border-border [&>div]:py-2 [&_span]:text-muted-foreground">
                                    <div><span>Version</span><b>{info?.version ?? "…"}</b></div>
                                    <div><span>Electron</span><b>{info?.electron ?? "…"}</b></div>
                                    <div><span>Node</span><b>{info?.node ?? "…"}</b></div>
                                    <div><span>Chromium</span><b>{info?.chrome ?? "…"}</b></div>
                                </div>
                            </>
                        ) : null}
                    </div>
                </div>

                <div className="max-h-44 overflow-y-auto text-xs" aria-live="polite">
                    {checks.map((c) => <p key={c.name} className={c.status === "error" ? "text-destructive" : c.status === "warn" ? "text-warning" : c.status === "ok" ? "text-success" : "text-muted-foreground"}><b>{c.name}: {c.status}</b> — {c.message}</p>)}
                    {error ? <p role="alert" className="text-destructive">{error}</p> : null}
                </div>
                <div className="mt-5 flex flex-wrap items-center gap-3">
                    <Button type="button" disabled={checking} onClick={() => void check()}>{checking ? "Checking…" : "Check connections"}</Button>
                    <Button type="button" onClick={() => void save()}>Save</Button>
                    <small className="basis-full text-muted-foreground">Checks use the values above without saving. Model checks send short test requests and may use quota.</small>
                    {saved ? <span className="text-xs text-success">saved — applies to the next run</span> : null}
                </div>
            </div>
        </div>
    );
}
