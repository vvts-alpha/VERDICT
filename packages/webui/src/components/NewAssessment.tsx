// "+ New" full manifest editor → POST /api/run → navigate to the launched run.
// Builds an AssessManifest JSON (target / scope / crawl / auth.roles) + run options.
import type { ReadinessCheck } from "@veritas/core";
import { useEffect, useState } from "react";
import { ArrowLeft, Lock, Play, Upload, X } from "lucide-react";
import { Disclosure } from "./Disclosure";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";
import { NativeSelect } from "./ui/native-select";
import { Textarea } from "./ui/textarea";

type AuthMethod = "manual" | "credentials" | "cookie";
interface Role {
  name: string;
  method: AuthMethod;
  password: string;
  description: string;
  cookieFile: string;
  loginUrl: string;
}

// Selectable models. Used for tiering: deep (high-value screens) / fast (survey, low-value screens).
const MODELS = [
  { id: "claude-opus-4-8", label: "Opus 4.8" },
  { id: "claude-sonnet-5", label: "Sonnet 5" },
  { id: "claude-haiku-4-5-20251001", label: "Haiku 4.5" },
];

function lines(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

export function NewAssessment({ onCancel, apiSpec = false }: { onCancel: () => void; apiSpec?: boolean }) {
  const [command, setCommand] = useState<"pilot" | "assess">("pilot");
  const [target, setTarget] = useState("");
  const [specText, setSpecText] = useState("");
  const [specName, setSpecName] = useState("");
  const [model, setModel] = useState("claude-opus-4-8"); // deep default = Opus
  const [fastModel, setFastModel] = useState("claude-sonnet-5"); // fast default = Sonnet
  const [useDesktopSettings, setUseDesktopSettings] = useState(false);
  const desktopBridge = typeof window !== "undefined" ? (window as any).verdictDesktop : undefined;

  // If running inside the desktop app, prefer its persisted settings (Deep / Light models)
  useEffect(() => {
    if (!desktopBridge?.settings) return;
    void desktopBridge.settings.get().then((s: any) => {
      if (!s) return;
      if (s.deepModel) setModel(s.deepModel);
      if (s.lightModel) setFastModel(s.lightModel);
      if (s.operatorContext) setContext((prev) => prev || s.operatorContext); // pre-fill from the global Settings default (per-run edits win)
      setUseDesktopSettings(true);
    });
  }, [desktopBridge]);
  const [rate, setRate] = useState("250");
  const [maxTurns, setMaxTurns] = useState("");
  const [focus, setFocus] = useState(""); // operator's emphasis hint → top priority of the scenario stage
  const [context, setContext] = useState(""); // operator's standing target facts → appended to every stage's system prompt
  const [headed, setHeaded] = useState(false);
  const [surveyOnly, setSurveyOnly] = useState(false);
  const [exhaustive, setExhaustive] = useState(false);
  const [burpScan, setBurpScan] = useState(false);
  const [burpProxy, setBurpProxy] = useState(false);
  // attended is derived from per-role method=manual (see Auth roles below).
  // scope breadth mode (how the host allow-set is built) + multiple seeds (a hard list)
  const [scopeMode, setScopeMode] = useState<"same-origin" | "etld" | "unrestricted">("etld");
  const [targetUrls, setTargetUrls] = useState("");
  const [lockToTargets, setLockToTargets] = useState(false); // lock to the URL list (no cross-crawling)
  // scope overrides (blank = derive from target on the server)
  const [inHosts, setInHosts] = useState("");
  const [outHosts, setOutHosts] = useState("");
  const [inPaths, setInPaths] = useState("");
  const [outPaths, setOutPaths] = useState("");
  const [scopePreview, setScopePreview] = useState<string[]>([]);
  useEffect(() => {
    setScopePreview([]);
    if (inHosts.trim()) { setScopePreview(lines(inHosts)); return; }
    const controller = new AbortController();
    const timer = window.setTimeout(() => {
      const urls = [...new Set([target.trim(), ...lines(targetUrls)].filter(Boolean))];
      if (!urls.length) return;
      const query = new URLSearchParams({ mode: scopeMode });
      for (const url of urls) query.append("url", url);
      void fetch(`/api/scope-preview?${query}`, { signal: controller.signal }).then(async (res) => {
        if (!res.ok) return;
        const data = await res.json() as { hosts: string[] };
        if (!controller.signal.aborted) setScopePreview(data.hosts);
      }).catch(() => {});
    }, 250);
    return () => { window.clearTimeout(timer); controller.abort(); };
  }, [target, targetUrls, scopeMode, inHosts]);
  // crawl
  const [followLinks, setFollowLinks] = useState(true);
  const [maxDepth, setMaxDepth] = useState("10"); // crawl default depth = 10
  // auth roles
  const [roles, setRoles] = useState<Role[]>([]);
  // Site-wide HTTP Basic/Digest (a wall before the app's own login)
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  // Custom headers (WAF bypass / engagement-required headers). Multiple, entered as separate name/value.
  const [headersList, setHeadersList] = useState<Array<{ name: string; value: string }>>([]);
  const [loginUrl, setLoginUrl] = useState(""); // entry URL for manual login (attended)
  const [maxScreens, setMaxScreens] = useState(""); // cap on the number of screens to diagnose (blank = default 40)
  const [maxSurveyScreens, setMaxSurveyScreens] = useState(""); // cap on the number of screens the survey maps (blank = unlimited)
  const [keepAliveMin, setKeepAliveMin] = useState(""); // keepalive touch interval in minutes (blank = default 4, "0" = off)
  const [anchorUrl, setAnchorUrl] = useState(""); // goto-safe authed hub (menu) — reach cold-nav-bouncing routes by clicking from here (blank = off)

  const [busy, setBusy] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checks, setChecks] = useState<ReadinessCheck[]>([]);
  const [err, setErr] = useState<string | null>(null);

  const setHeader = (i: number, patch: Partial<{ name: string; value: string }>): void =>
    setHeadersList((hs) => hs.map((h, j) => (j === i ? { ...h, ...patch } : h)));
  const addHeader = (): void => setHeadersList((hs) => [...hs, { name: "", value: "" }]);
  const rmHeader = (i: number): void => setHeadersList((hs) => hs.filter((_, j) => j !== i));

  // Load a URL list from a file (CSV / a plain list) → expand into the Target URLs textarea.
  const importUrlList = (file: File): void => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      // Per line → treat the first cell of each line (comma/tab/space separated) as a URL. Keep only lines containing http(s).
      const urls = text
        .split(/\r?\n/)
        .map((ln) => (ln.split(/[,\t]/)[0] ?? "").trim().replace(/^["']|["']$/g, ""))
        .filter((u) => /^https?:\/\//i.test(u));
      if (urls.length) setTargetUrls((prev) => [...lines(prev), ...urls].filter((u, i, a) => a.indexOf(u) === i).join("\n"));
      else setErr("no http(s) URLs found in the file");
    };
    reader.readAsText(file);
  };

  const setRole = (i: number, patch: Partial<Role>): void =>
    setRoles((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addRole = (): void => setRoles((rs) => [...rs, { name: "", method: "manual", password: "", description: "", cookieFile: "", loginUrl: "" }]);
  const rmRole = (i: number): void => setRoles((rs) => rs.filter((_, j) => j !== i));

  const checkSetup = async (): Promise<boolean> => {
    if (!desktopBridge?.settings?.check) return true;
    setChecking(true); setChecks([]);
    try {
      const saved = await desktopBridge.settings.get();
      const result: ReadinessCheck[] = await desktopBridge.settings.check({ ...saved,
        ...(model ? { deepModel: model } : {}), ...(fastModel ? { lightModel: fastModel } : {}),
        burpScan: burpScan || saved.burpScan,
      });
      setChecks(result);
      return result.length > 0 && result.every((c) => c.status !== "error");
    } catch { setErr("Could not check setup. Open Settings and check connections."); return false; }
    finally { setChecking(false); }
  };

  const submit = async (): Promise<void> => {
    if (!target.trim()) {
      setErr("Target URL is required");
      return;
    }
    // Require an explicit http(s) scheme. Without it "example.com" throws in new URL() and "host:3000" misparses to an
    // empty scope downstream, so reject here with a clear message (the server re-validates as the real backstop).
    try {
      const u = new URL(target.trim());
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error();
    } catch {
      setErr(`Target must start with http:// or https:// (e.g. https://${target.trim()})`);
      return;
    }
    let spec: unknown;
    if (apiSpec) {
      try {
        spec = JSON.parse(specText);
        if (!spec || typeof spec !== "object") throw new Error();
      } catch { setErr("Choose a valid OpenAPI / Swagger JSON file first"); return; }
    }
    setErr(null);
    setBusy(true);

    const scope: Record<string, string[]> = {};
    if (lines(inHosts).length) scope.inScopeHosts = lines(inHosts);
    if (lines(outHosts).length) scope.outOfScopeHosts = lines(outHosts);
    if (lines(inPaths).length) scope.inScopePathPrefixes = lines(inPaths);
    if (lines(outPaths).length) scope.outOfScopePathPrefixes = lines(outPaths);

    const named = roles.filter((r) => r.name.trim());
    const authRoles = named.map((r) => {
      const base = { name: r.name.trim(), ...(r.description ? { description: r.description } : {}), ...(r.loginUrl.trim() ? { loginUrl: r.loginUrl.trim() } : {}) };
      if (r.method === "credentials") return { ...base, ...(r.password ? { pass: r.password } : {}) };
      if (r.method === "cookie") return { ...base, ...(r.cookieFile ? { cookieFile: r.cookieFile } : {}) };
      return base; // manual: name(+description) only → logged in via the Sessions tab
    });
    // If there's even one manual role, it's attended (= open a control channel for logging in via the WebUI).
    const anyManual = named.some((r) => r.method === "manual");

    const manifest: Record<string, unknown> = { target: target.trim() };
    manifest.scopeMode = scopeMode; // breadth of the host allow-set (same-origin / etld / unrestricted)
    const extraTargets = lines(targetUrls).filter((u) => u !== target.trim());
    if (extraTargets.length) manifest.targets = extraTargets; // extra seeds (a hard list of multiple URLs)
    if (command === "pilot" && lockToTargets) manifest.lockToTargets = true; // diagnose only the list, no cross-crawling
    if (Object.keys(scope).length) manifest.scope = scope;
    const crawl: Record<string, unknown> = {};
    if (!followLinks) crawl.followLinks = false;
    if (maxDepth) crawl.maxDepth = Number.parseInt(maxDepth, 10);
    if (Object.keys(crawl).length) manifest.crawl = crawl;
    const auth: Record<string, unknown> = {};
    if (authRoles.length) auth.roles = authRoles;
    if (basicUser.trim() && basicPass) auth.httpBasic = { user: basicUser.trim(), pass: basicPass }; // site-wide Basic/Digest
    if (Object.keys(auth).length) manifest.auth = auth;
    // Custom headers (only those with a name filled in) → manifest.http.headers
    const headers: Record<string, string> = {};
    for (const h of headersList) if (h.name.trim()) headers[h.name.trim()] = h.value;
    if (Object.keys(headers).length) manifest.http = { headers };

    const options: Record<string, unknown> = {};
    if (model) options.model = model;
    if (command === "pilot" && fastModel && fastModel !== model) options.fastModel = fastModel; // model tiering
    if (rate) options.rate = Number.parseInt(rate, 10);
    if (command === "pilot" && maxTurns) options.maxTurns = Number.parseInt(maxTurns, 10);
    if (headed) options.headed = true;
    if (command === "pilot" && surveyOnly) options.surveyOnly = true;
    if (command === "pilot" && exhaustive) options.exhaustive = true;
    if (command === "pilot" && burpScan) options.burpScan = true;
    if (command === "pilot" && burpProxy) options.burpProxy = true;
    if (command === "pilot" && anyManual) options.attended = true;
    if (loginUrl.trim()) options.loginUrl = loginUrl.trim();
    if (command === "pilot" && maxScreens) options.maxScreens = Number.parseInt(maxScreens, 10);
    if (command === "pilot" && maxSurveyScreens) options.maxSurveyScreens = Number.parseInt(maxSurveyScreens, 10);
    if (command === "pilot" && keepAliveMin.trim() !== "" && Number.isFinite(Number(keepAliveMin))) options.keepAliveMin = Number.parseInt(keepAliveMin, 10);
    if (command === "pilot" && anchorUrl.trim()) options.anchorUrl = anchorUrl.trim();
    if (command === "pilot" && focus.trim()) options.focus = focus.trim();
    if (command === "pilot" && context.trim()) options.context = context.trim();

    try {
      if (!(await checkSetup())) { setErr("Fix the failed setup checks in Settings before starting."); setBusy(false); return; }
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command, manifest, options, ...(apiSpec ? { spec } : {}) }),
      });
      const data = (await res.json()) as { id?: string; error?: string };
      if (!res.ok || !data.id) {
        setErr(data.error ?? `launch failed (${res.status})`);
        setBusy(false);
        return;
      }
      window.location.search = `?id=${encodeURIComponent(data.id)}`;
    } catch {
      setErr("Can't reach server");
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 pb-10">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h2 className="text-base font-semibold">{apiSpec ? "API specification assessment" : "New assessment"}</h2>
        <Button type="button" variant="ghost" onClick={onCancel}>
          <ArrowLeft /> Cancel
        </Button>
      </div>

      {!apiSpec ? <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
        <span>Command</span>
        <NativeSelect className="w-full" value={command} onChange={(e) => setCommand(e.target.value as "pilot" | "assess")}>
          <option value="pilot">pilot (AI-led)</option>
          <option value="assess">assess (deterministic)</option>
        </NativeSelect>
      </label> : (
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
          <span>OpenAPI 3.x / Swagger 2.0 JSON file *</span>
          <Input type="file" accept=".json,application/json" onChange={(e) => {
            const file = e.target.files?.[0];
            setSpecText(""); setSpecName("");
            if (!file) return;
            if (file.size > 2 * 1024 * 1024) { setErr("Specification must be 2 MB or smaller"); return; }
            void file.text().then((text) => { setSpecText(text); setSpecName(file.name); setErr(null); }).catch(() => setErr("Could not read the specification"));
          }} />
          <small>{specName || "Select a JSON file. YAML and external references are not supported."} The target URL overrides the specification server; scope and authentication below still apply. Diagnosis starts from the imported endpoints.</small>
        </label>
      )}

      <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
        <span>Target URL *</span>
        <Input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://app.example.com/" />
      </label>

      <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
        <span>Scope mode</span>
        <NativeSelect className="w-full" value={scopeMode} onChange={(e) => setScopeMode(e.target.value as "same-origin" | "etld" | "unrestricted")}>
          <option value="etld">eTLD+1 — seed domain + subdomains (private hosting boundaries respected)</option>
          <option value="same-origin">same-origin — exact host only (APIs on other subdomains blocked)</option>
          <option value="unrestricted">unrestricted — any host (⚠ may leave the program)</option>
        </NativeSelect>
        <small>Allowed hosts: {scopePreview.length ? scopePreview.join(", ") : "Enter target URLs to preview"}. Exclusions below still apply.</small>
      </label>

      <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
          <span>{command === "pilot" ? "Model (deep)" : "Model"}</span>
          {useDesktopSettings ? (
            // When running in the desktop app, the desktop Settings manage model choices; show a read-only hint.
            <Input readOnly value={model} />
          ) : (
            <NativeSelect className="w-full" value={model} onChange={(e) => setModel(e.target.value)}>
              {MODELS.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </NativeSelect>
          )}
        </label>
        {command === "pilot" ? (
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="model tiering: high-value screens use the deep model, survey/methodology/low-value screens use this fast model">
            <span>Fast model</span>
            {useDesktopSettings ? (
              <Input readOnly value={fastModel ?? ""} />
            ) : (
              <NativeSelect className="w-full" value={fastModel} onChange={(e) => setFastModel(e.target.value)}>
                <option value="">— none (single model)</option>
                {MODELS.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                  </option>
                ))}
              </NativeSelect>
            )}
          </label>
        ) : null}
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
          <span>Rate (ms)</span>
          <Input value={rate} onChange={(e) => setRate(e.target.value)} inputMode="numeric" />
        </label>
        {command === "pilot" ? (
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>Max turns</span>
            <Input value={maxTurns} onChange={(e) => setMaxTurns(e.target.value)} placeholder="(default)" inputMode="numeric" />
          </label>
        ) : null}
        {command === "pilot" ? (
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="how many screens to diagnose (default 40). raise for large apps.">
            <span>Max screens</span>
            <Input value={maxScreens} onChange={(e) => setMaxScreens(e.target.value)} placeholder="40" inputMode="numeric" />
          </label>
        ) : null}
        {command === "pilot" && !apiSpec ? (
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="cap how many screens the survey maps (empty = unlimited). bounds exploration on large sites.">
            <span>Max survey screens</span>
            <Input value={maxSurveyScreens} onChange={(e) => setMaxSurveyScreens(e.target.value)} placeholder="(unlimited)" inputMode="numeric" />
          </label>
        ) : null}
        {command === "pilot" ? (
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="keepalive interval (minutes). touches a safe authed page (never /) to keep the session warm. set 0 to turn off for sites whose session dies on a cold / hit or a full reload.">
            <span>Keepalive (min)</span>
            <Input value={keepAliveMin} onChange={(e) => setKeepAliveMin(e.target.value)} placeholder="4 · 0 = off" inputMode="numeric" />
          </label>
        ) : null}
      </div>
      {command === "pilot" ? (
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="goto-safe authed hub (the app menu). for sites where deep routes die on a direct/cold navigation: a route that bounces to an error page is reached by clicking its link from here instead, and this becomes the keepalive target. blank = off (unchanged).">
          <span>Anchor URL (menu hub)</span>
          <Input value={anchorUrl} onChange={(e) => setAnchorUrl(e.target.value)} placeholder="e.g. http://host/Account/AccountMenu  (blank = off)" autoComplete="off" />
        </label>
      ) : null}
      {command === "pilot" ? (
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="operator focus — injected as the TOP priority of the scenario (A04) stage, not per-screen diagnosis. emphasis, not exclusive (full coverage still runs).">
          <span>Focus (scenario emphasis)</span>
          <Textarea
            value={focus}
            onChange={(e) => setFocus(e.target.value)}
            placeholder="e.g. Focus on the checkout flow and IDOR in /api/orders. Also coupons / price tampering."
            rows={2}
          />
        </label>
      ) : null}
      {command === "pilot" ? (
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="operator context — standing FACTS about the target (auth shape, tenant model, where the API lives), appended to EVERY stage's system prompt so they inform the whole run. Additive only: it guides the agent, it does not override the safety / scope / evidence-discipline rules. Unlike Focus (a one-run priority for the scenario stage), this is knowledge about the target. In the desktop app, set a reusable default in Settings → Agent.">
          <span>Operator context (target facts — default in Settings → Agent)</span>
          <Textarea
            value={context}
            onChange={(e) => setContext(e.target.value)}
            placeholder="e.g. Auth is a JWT in the X-Auth header. Tenant id is the last path segment. The API is GraphQL at /graphql. Test accounts share org 42."
            rows={2}
          />
        </label>
      ) : null}

      <div className="my-3 flex flex-wrap items-center gap-4 [&_label]:inline-flex [&_label]:items-center [&_label]:gap-2">
        {!useDesktopSettings ? (
          <label title="show the automation browser window (headless off) — for debugging. In the desktop app, open the Live tab to watch the scan instead, so this is hidden.">
            <Checkbox checked={headed} onCheckedChange={(checked) => setHeaded(checked === true)} /> headed
          </label>
        ) : null}
        {command === "pilot" ? (
          <>
            {!apiSpec ? <>
            <label title="map only (screens + APIs + screenshots) — no methodology / diagnosis / findings. Cheap recon; resume later to diagnose.">
              <Checkbox disabled={apiSpec} checked={surveyOnly} onCheckedChange={(checked) => setSurveyOnly(checked === true)} /> survey-only
            </label>
            <label title="map EVERY screen — turns OFF the survey's auto-pruning of repetitive same-skeleton content pages (CMS article/news/category trees). Full coverage, but much slower/larger on content-heavy sites; leave off for a normal run.">
              <Checkbox disabled={apiSpec} checked={exhaustive} onCheckedChange={(checked) => setExhaustive(checked === true)} /> exhaustive
            </label>
            </> : null}
            <label title="active Burp scan after diagnosis (uses env BURP_API)">
              <Checkbox checked={burpScan} onCheckedChange={(checked) => setBurpScan(checked === true)} /> burp-scan
            </label>
            <label title="route all traffic through the Burp proxy (uses env BURP_PROXY)">
              <Checkbox checked={burpProxy} onCheckedChange={(checked) => setBurpProxy(checked === true)} /> burp-proxy
            </label>
          </>
        ) : null}
      </div>

      <Disclosure title="Scope (optional — blank derives from target + scope mode)">
        {!apiSpec ? <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
          <span>
            Target URLs — extra seeds, one per line (URL-list diagnosis){" "}
            <label className="ml-2 inline-flex cursor-pointer items-center gap-1 rounded border border-border px-2 py-0.5 text-primary hover:bg-accent" title="load a URL list from a file (CSV: first column, or one URL per line)">
              <Upload className="size-3" /> import list
              <Input
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                className="hidden"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (f) importUrlList(f);
                }}
              />
            </label>
          </span>
          <Textarea
            value={targetUrls}
            onChange={(e) => setTargetUrls(e.target.value)}
            placeholder={"https://app.example.com/a\nhttps://api.example.com/v1/x"}
          />
        </label> : null}
        {command === "pilot" && !apiSpec ? (
          <div className="my-3 flex flex-wrap items-center gap-4 [&_label]:inline-flex [&_label]:items-center [&_label]:gap-2">
            <label title="survey maps only the target + these URLs (no link-following); diagnosis is limited to the list + the APIs each screen calls">
              <Checkbox checked={lockToTargets} onCheckedChange={(checked) => setLockToTargets(checked === true)} /> <Lock className="size-3" /> lock to target URLs (no crawl — diagnose only the list + their APIs)
            </label>
          </div>
        ) : null}
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>In-scope hosts</span>
            <Textarea value={inHosts} onChange={(e) => setInHosts(e.target.value)} placeholder="one per line" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>Out-of-scope hosts</span>
            <Textarea value={outHosts} onChange={(e) => setOutHosts(e.target.value)} placeholder="one per line" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>In-scope path prefixes</span>
            <Textarea value={inPaths} onChange={(e) => setInPaths(e.target.value)} placeholder="/app" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>Out-of-scope path prefixes</span>
            <Textarea value={outPaths} onChange={(e) => setOutPaths(e.target.value)} placeholder="/logout" />
          </label>
        </div>
      </Disclosure>

      {!apiSpec ? (
      <Disclosure title="Crawl">
        <div className="my-3 flex flex-wrap items-center gap-4 [&_label]:inline-flex [&_label]:items-center [&_label]:gap-2">
          <label>
            <Checkbox checked={followLinks} onCheckedChange={(checked) => setFollowLinks(checked === true)} /> follow links
          </label>
          <label className="flex items-center gap-2 text-xs [&>input]:w-20">
            <span>max depth</span>
            <Input value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} placeholder="10" inputMode="numeric" />
          </label>
        </div>
      </Disclosure>
      ) : null}

      <Disclosure title="HTTP Basic auth (site-wide — the browser 401 dialog, before the app login)">
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>Basic user</span>
            <Input value={basicUser} onChange={(e) => setBasicUser(e.target.value)} placeholder="(leave blank if none)" autoComplete="off" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>Basic password</span>
            <Input type="password" value={basicPass} onChange={(e) => setBasicPass(e.target.value)} autoComplete="off" />
          </label>
        </div>
      </Disclosure>

      <Disclosure title={`Custom headers (${headersList.length}) — added to in-scope requests (WAF bypass / required headers)`}>
        {headersList.map((h, i) => (
          <div className="my-2 flex flex-wrap items-center gap-2 [&_input]:min-w-28 [&_input]:flex-1" key={i}>
            <Input placeholder="header name (e.g. X-Forwarded-For)" value={h.name} onChange={(e) => setHeader(i, { name: e.target.value })} autoComplete="off" />
            <Input placeholder="value" value={h.value} onChange={(e) => setHeader(i, { value: e.target.value })} autoComplete="off" />
            <Button type="button" size="icon-sm" aria-label="Remove header" onClick={() => rmHeader(i)}>
              <X />
            </Button>
          </div>
        ))}
        <Button type="button" variant="outline" size="sm" onClick={addHeader}>
          + add header
        </Button>
      </Disclosure>

      <Disclosure title={`Auth roles (${roles.length}) — a “manual” role makes the run attended (log in via the Sessions tab)`}>
        <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground" title="entry URL for manual login windows (attended). blank = target URL.">
          <span>Login URL (manual login entry — blank = target)</span>
          <Input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} placeholder="https://app.example.com/login" autoComplete="off" />
        </label>
        {roles.map((r, i) => (
          <div className="my-2 flex flex-wrap items-center gap-2 [&_input]:min-w-28 [&_input]:flex-1" key={i}>
            <Input placeholder="name" value={r.name} onChange={(e) => setRole(i, { name: e.target.value })} />
            <NativeSelect className="w-full" value={r.method} onChange={(e) => setRole(i, { method: e.target.value as AuthMethod })}>
              <option value="manual">manual (Sessions tab)</option>
              <option value="credentials">credentials</option>
              <option value="cookie">cookie file</option>
            </NativeSelect>
            {r.method === "credentials" ? (
              <Input placeholder="password" type="password" value={r.password} onChange={(e) => setRole(i, { password: e.target.value })} />
            ) : null}
            {r.method === "cookie" ? (
              <Input placeholder="cookieFile path" value={r.cookieFile} onChange={(e) => setRole(i, { cookieFile: e.target.value })} />
            ) : null}
            <Input placeholder="description (e.g. admin)" value={r.description} onChange={(e) => setRole(i, { description: e.target.value })} />
            <Input placeholder="login URL (optional — this role's own login page)" value={r.loginUrl} onChange={(e) => setRole(i, { loginUrl: e.target.value })} autoComplete="off" />
            <Button type="button" size="icon-sm" aria-label="Remove role" onClick={() => rmRole(i)}>
              <X />
            </Button>
          </div>
        ))}
        <Button type="button" variant="outline" size="sm" onClick={addRole}>
          + add role
        </Button>
      </Disclosure>

      {err ? <p role="alert" className="text-xs text-destructive">{err}</p> : null}
      <div className="mt-5 flex flex-wrap items-center gap-3">
        {desktopBridge?.settings?.check ? <div className="w-full">
          <Button type="button" disabled={busy || checking} onClick={() => void checkSetup()}>Check setup</Button>
          <p className="text-xs text-muted-foreground">Launch checks the selected models, automation browser, and enabled Burp connection. Short model test requests may use quota.</p>
          <div aria-live="polite">{checks.map((c) => <p key={c.name}><b>{c.name}: {c.status}</b> — {c.message}</p>)}</div>
        </div> : null}
        <Button type="button" disabled={busy || checking} onClick={() => void submit()}>
          {checking ? "Checking setup…" : busy ? "Launching…" : <><Play /> Launch {command}</>}
        </Button>
      </div>
    </div>
  );
}
