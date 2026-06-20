// "+ New" full manifest editor → POST /api/run → navigate to the launched run.
// Builds an AssessManifest JSON (target / scope / crawl / auth.roles) + run options.
import { useState } from "react";

type AuthMethod = "manual" | "credentials" | "cookie";
interface Role {
  name: string;
  method: AuthMethod;
  password: string;
  description: string;
  cookieFile: string;
}

// 選択できるモデル。今のところ Sonnet のみ(リストは将来の追加用)。
const MODELS = [{ id: "claude-sonnet-4-6", label: "Sonnet 4.6" }];

function lines(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

export function NewAssessment({ onCancel }: { onCancel: () => void }) {
  const [command, setCommand] = useState<"pilot" | "assess">("pilot");
  const [target, setTarget] = useState("");
  const [model, setModel] = useState("claude-sonnet-4-6");
  const [rate, setRate] = useState("250");
  const [maxTurns, setMaxTurns] = useState("");
  const [headed, setHeaded] = useState(false);
  const [surveyOnly, setSurveyOnly] = useState(false);
  const [exhaustive, setExhaustive] = useState(false);
  const [burpScan, setBurpScan] = useState(false);
  const [burpProxy, setBurpProxy] = useState(false);
  // attended は per-role の method=manual から導出する(下の Auth roles)。
  // scope overrides (blank = derive from target on the server)
  const [inHosts, setInHosts] = useState("");
  const [outHosts, setOutHosts] = useState("");
  const [inPaths, setInPaths] = useState("");
  const [outPaths, setOutPaths] = useState("");
  // crawl
  const [followLinks, setFollowLinks] = useState(true);
  const [maxDepth, setMaxDepth] = useState("");
  // auth roles
  const [roles, setRoles] = useState<Role[]>([]);

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const setRole = (i: number, patch: Partial<Role>): void =>
    setRoles((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  const addRole = (): void => setRoles((rs) => [...rs, { name: "", method: "manual", password: "", description: "", cookieFile: "" }]);
  const rmRole = (i: number): void => setRoles((rs) => rs.filter((_, j) => j !== i));

  const submit = async (): Promise<void> => {
    if (!target.trim()) {
      setErr("Target URL is required");
      return;
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
      const base = { name: r.name.trim(), ...(r.description ? { description: r.description } : {}) };
      if (r.method === "credentials") return { ...base, ...(r.password ? { pass: r.password } : {}) };
      if (r.method === "cookie") return { ...base, ...(r.cookieFile ? { cookieFile: r.cookieFile } : {}) };
      return base; // manual: name(+description) only → logged in via the Sessions tab
    });
    // manual ロールが1つでもあれば attended(= WebUI ログイン用の制御チャネルを張る)。
    const anyManual = named.some((r) => r.method === "manual");

    const manifest: Record<string, unknown> = { target: target.trim() };
    if (Object.keys(scope).length) manifest.scope = scope;
    const crawl: Record<string, unknown> = {};
    if (!followLinks) crawl.followLinks = false;
    if (maxDepth) crawl.maxDepth = Number.parseInt(maxDepth, 10);
    if (Object.keys(crawl).length) manifest.crawl = crawl;
    if (authRoles.length) manifest.auth = { roles: authRoles };

    const options: Record<string, unknown> = {};
    if (model) options.model = model;
    if (rate) options.rate = Number.parseInt(rate, 10);
    if (command === "pilot" && maxTurns) options.maxTurns = Number.parseInt(maxTurns, 10);
    if (headed) options.headed = true;
    if (command === "pilot" && surveyOnly) options.surveyOnly = true;
    if (command === "pilot" && exhaustive) options.exhaustive = true;
    if (command === "pilot" && burpScan) options.burpScan = true;
    if (command === "pilot" && burpProxy) options.burpProxy = true;
    if (command === "pilot" && anyManual) options.attended = true;

    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command, manifest, options }),
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
    <div className="newform">
      <div className="nf-row nf-head">
        <h2>New assessment</h2>
        <button type="button" className="nf-cancel" onClick={onCancel}>
          ← Cancel
        </button>
      </div>

      <label className="nf-field">
        <span>Command</span>
        <select value={command} onChange={(e) => setCommand(e.target.value as "pilot" | "assess")}>
          <option value="pilot">pilot (Claude-led)</option>
          <option value="assess">assess (deterministic)</option>
        </select>
      </label>

      <label className="nf-field">
        <span>Target URL *</span>
        <input value={target} onChange={(e) => setTarget(e.target.value)} placeholder="https://app.example.com/" />
      </label>

      <div className="nf-grid">
        <label className="nf-field">
          <span>Model</span>
          <select value={model} onChange={(e) => setModel(e.target.value)}>
            {MODELS.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        <label className="nf-field">
          <span>Rate (ms)</span>
          <input value={rate} onChange={(e) => setRate(e.target.value)} inputMode="numeric" />
        </label>
        {command === "pilot" ? (
          <label className="nf-field">
            <span>Max turns</span>
            <input value={maxTurns} onChange={(e) => setMaxTurns(e.target.value)} placeholder="(default)" inputMode="numeric" />
          </label>
        ) : null}
      </div>

      <div className="nf-checks">
        <label>
          <input type="checkbox" checked={headed} onChange={(e) => setHeaded(e.target.checked)} /> headed
        </label>
        {command === "pilot" ? (
          <>
            <label>
              <input type="checkbox" checked={surveyOnly} onChange={(e) => setSurveyOnly(e.target.checked)} /> survey-only
            </label>
            <label>
              <input type="checkbox" checked={exhaustive} onChange={(e) => setExhaustive(e.target.checked)} /> exhaustive
            </label>
            <label title="active Burp scan after diagnosis (uses env BURP_API)">
              <input type="checkbox" checked={burpScan} onChange={(e) => setBurpScan(e.target.checked)} /> burp-scan
            </label>
            <label title="route all traffic through the Burp proxy (uses env BURP_PROXY)">
              <input type="checkbox" checked={burpProxy} onChange={(e) => setBurpProxy(e.target.checked)} /> burp-proxy
            </label>
          </>
        ) : null}
      </div>

      <details className="nf-section">
        <summary>Scope (optional — blank derives from target)</summary>
        <div className="nf-grid">
          <label className="nf-field">
            <span>In-scope hosts</span>
            <textarea value={inHosts} onChange={(e) => setInHosts(e.target.value)} placeholder="one per line" />
          </label>
          <label className="nf-field">
            <span>Out-of-scope hosts</span>
            <textarea value={outHosts} onChange={(e) => setOutHosts(e.target.value)} placeholder="one per line" />
          </label>
          <label className="nf-field">
            <span>In-scope path prefixes</span>
            <textarea value={inPaths} onChange={(e) => setInPaths(e.target.value)} placeholder="/app" />
          </label>
          <label className="nf-field">
            <span>Out-of-scope path prefixes</span>
            <textarea value={outPaths} onChange={(e) => setOutPaths(e.target.value)} placeholder="/logout" />
          </label>
        </div>
      </details>

      <details className="nf-section">
        <summary>Crawl</summary>
        <div className="nf-checks">
          <label>
            <input type="checkbox" checked={followLinks} onChange={(e) => setFollowLinks(e.target.checked)} /> follow links
          </label>
          <label className="nf-field nf-inline">
            <span>max depth</span>
            <input value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} placeholder="3" inputMode="numeric" />
          </label>
        </div>
      </details>

      <details className="nf-section">
        <summary>Auth roles ({roles.length}) — a “manual” role makes the run attended (log in via the Sessions tab)</summary>
        {roles.map((r, i) => (
          <div className="nf-role" key={i}>
            <input placeholder="name" value={r.name} onChange={(e) => setRole(i, { name: e.target.value })} />
            <select value={r.method} onChange={(e) => setRole(i, { method: e.target.value as AuthMethod })}>
              <option value="manual">manual (Sessions tab)</option>
              <option value="credentials">credentials</option>
              <option value="cookie">cookie file</option>
            </select>
            {r.method === "credentials" ? (
              <input placeholder="password" type="password" value={r.password} onChange={(e) => setRole(i, { password: e.target.value })} />
            ) : null}
            {r.method === "cookie" ? (
              <input placeholder="cookieFile path" value={r.cookieFile} onChange={(e) => setRole(i, { cookieFile: e.target.value })} />
            ) : null}
            <input placeholder="description (e.g. admin)" value={r.description} onChange={(e) => setRole(i, { description: e.target.value })} />
            <button type="button" onClick={() => rmRole(i)}>
              ✕
            </button>
          </div>
        ))}
        <button type="button" className="nf-addrole" onClick={addRole}>
          + add role
        </button>
      </details>

      {err ? <p className="nf-err">{err}</p> : null}
      <div className="nf-row nf-actions">
        <button type="button" className="nf-launch" disabled={busy} onClick={() => void submit()}>
          {busy ? "Launching…" : `▶ Launch ${command}`}
        </button>
      </div>
    </div>
  );
}
