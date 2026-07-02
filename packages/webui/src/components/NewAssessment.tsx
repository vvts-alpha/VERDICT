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

// 選択できるモデル。deep(高価値画面) / fast(survey・低価値画面) の tiering に使う。
const MODELS = [
  { id: "claude-opus-4-8", label: "Opus 4.8" },
  { id: "claude-sonnet-4-6", label: "Sonnet 4.6" },
  { id: "claude-haiku-4-5-20251001", label: "Haiku 4.5" },
];

function lines(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter((x) => x.length > 0);
}

export function NewAssessment({ onCancel }: { onCancel: () => void }) {
  const [command, setCommand] = useState<"pilot" | "assess">("pilot");
  const [target, setTarget] = useState("");
  const [model, setModel] = useState("claude-opus-4-8"); // deep 既定 = Opus: 高価値画面/シナリオ/fingerprint
  const [fastModel, setFastModel] = useState("claude-sonnet-4-6"); // fast 既定 = Sonnet: survey/methodology/低価値画面(= tiering 既定 ON。"none" で単一モデル)
  const [rate, setRate] = useState("250");
  const [maxTurns, setMaxTurns] = useState("");
  const [focus, setFocus] = useState(""); // 操作者の重点ヒント → シナリオ段の最優先目的
  const [headed, setHeaded] = useState(false);
  const [surveyOnly, setSurveyOnly] = useState(false);
  const [exhaustive, setExhaustive] = useState(false);
  const [burpScan, setBurpScan] = useState(false);
  const [burpProxy, setBurpProxy] = useState(false);
  // attended は per-role の method=manual から導出する(下の Auth roles)。
  // scope breadth mode (host allow-set の作り方) + 複数シード(ハードリスト)
  const [scopeMode, setScopeMode] = useState<"same-origin" | "etld" | "unrestricted">("etld");
  const [targetUrls, setTargetUrls] = useState("");
  const [lockToTargets, setLockToTargets] = useState(false); // URL リスト固定(横断クロールしない)
  // scope overrides (blank = derive from target on the server)
  const [inHosts, setInHosts] = useState("");
  const [outHosts, setOutHosts] = useState("");
  const [inPaths, setInPaths] = useState("");
  const [outPaths, setOutPaths] = useState("");
  // crawl
  const [followLinks, setFollowLinks] = useState(true);
  const [maxDepth, setMaxDepth] = useState("10"); // crawl 既定深さ = 10
  // auth roles
  const [roles, setRoles] = useState<Role[]>([]);
  // サイト全体を覆う HTTP Basic/Digest(アプリのログイン以前の壁)
  const [basicUser, setBasicUser] = useState("");
  const [basicPass, setBasicPass] = useState("");
  // カスタムヘッダ(WAF 回避・案件指定の必須ヘッダ)。name/value 別入力で複数。
  const [headersList, setHeadersList] = useState<Array<{ name: string; value: string }>>([]);
  const [loginUrl, setLoginUrl] = useState(""); // 手動ログインの入口 URL(attended)
  const [maxScreens, setMaxScreens] = useState(""); // 診断する画面数の上限(空=既定 40)
  const [maxSurveyScreens, setMaxSurveyScreens] = useState(""); // survey が写像する画面数の上限(空=無制限)

  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const setHeader = (i: number, patch: Partial<{ name: string; value: string }>): void =>
    setHeadersList((hs) => hs.map((h, j) => (j === i ? { ...h, ...patch } : h)));
  const addHeader = (): void => setHeadersList((hs) => [...hs, { name: "", value: "" }]);
  const rmHeader = (i: number): void => setHeadersList((hs) => hs.filter((_, j) => j !== i));

  // URL リストのファイル読込(CSV / 単一リスト)→ Target URLs テキストエリアに展開。
  const importUrlList = (file: File): void => {
    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result ?? "");
      // 行ごと → 各行の最初のセル(カンマ/タブ/空白区切り)を URL とみなす。http(s) を含む行だけ採用。
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
    manifest.scopeMode = scopeMode; // host allow-set の広さ(same-origin / etld / unrestricted)
    const extraTargets = lines(targetUrls).filter((u) => u !== target.trim());
    if (extraTargets.length) manifest.targets = extraTargets; // 追加シード(複数 URL のハードリスト)
    if (command === "pilot" && lockToTargets) manifest.lockToTargets = true; // 横断クロールせずリストだけ診断
    if (Object.keys(scope).length) manifest.scope = scope;
    const crawl: Record<string, unknown> = {};
    if (!followLinks) crawl.followLinks = false;
    if (maxDepth) crawl.maxDepth = Number.parseInt(maxDepth, 10);
    if (Object.keys(crawl).length) manifest.crawl = crawl;
    const auth: Record<string, unknown> = {};
    if (authRoles.length) auth.roles = authRoles;
    if (basicUser.trim() && basicPass) auth.httpBasic = { user: basicUser.trim(), pass: basicPass }; // site-wide Basic/Digest
    if (Object.keys(auth).length) manifest.auth = auth;
    // カスタムヘッダ(name が入ってるものだけ)→ manifest.http.headers
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
    if (command === "pilot" && focus.trim()) options.focus = focus.trim();

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

      <label className="nf-field">
        <span>Scope mode</span>
        <select value={scopeMode} onChange={(e) => setScopeMode(e.target.value as "same-origin" | "etld" | "unrestricted")}>
          <option value="etld">eTLD+1 — seed domain + subdomains (incl. its APIs)</option>
          <option value="same-origin">same-origin — exact host only (APIs on other subdomains blocked)</option>
          <option value="unrestricted">unrestricted — any host (⚠ may leave the program)</option>
        </select>
      </label>

      <div className="nf-grid">
        <label className="nf-field">
          <span>{command === "pilot" ? "Model (deep)" : "Model"}</span>
          <select value={model} onChange={(e) => setModel(e.target.value)}>
            {MODELS.map((m) => (
              <option key={m.id} value={m.id}>
                {m.label}
              </option>
            ))}
          </select>
        </label>
        {command === "pilot" ? (
          <label className="nf-field" title="model tiering: high-value screens use the deep model, survey/methodology/low-value screens use this fast model">
            <span>Fast model</span>
            <select value={fastModel} onChange={(e) => setFastModel(e.target.value)}>
              <option value="">— none (single model)</option>
              {MODELS.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
          </label>
        ) : null}
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
        {command === "pilot" ? (
          <label className="nf-field" title="how many screens to diagnose (default 40). raise for large apps.">
            <span>Max screens</span>
            <input value={maxScreens} onChange={(e) => setMaxScreens(e.target.value)} placeholder="40" inputMode="numeric" />
          </label>
        ) : null}
        {command === "pilot" ? (
          <label className="nf-field" title="cap how many screens the survey maps (empty = unlimited). bounds exploration on large sites.">
            <span>Max survey screens</span>
            <input value={maxSurveyScreens} onChange={(e) => setMaxSurveyScreens(e.target.value)} placeholder="(unlimited)" inputMode="numeric" />
          </label>
        ) : null}
      </div>
      {command === "pilot" ? (
        <label className="nf-field nf-wide" title="operator focus — injected as the TOP priority of the scenario (A04) stage, not per-screen diagnosis. emphasis, not exclusive (full coverage still runs).">
          <span>Focus (scenario emphasis)</span>
          <textarea
            value={focus}
            onChange={(e) => setFocus(e.target.value)}
            placeholder="e.g. 決済フローと /api/orders の IDOR を重点的に。クーポン/価格改ざんも"
            rows={2}
          />
        </label>
      ) : null}

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
        <summary>Scope (optional — blank derives from target + scope mode)</summary>
        <label className="nf-field">
          <span>
            Target URLs — extra seeds, one per line (URL-list diagnosis){" "}
            <label className="nf-import" title="load a URL list from a file (CSV: first column, or one URL per line)">
              ⬆ import list
              <input
                type="file"
                accept=".csv,.txt,text/csv,text/plain"
                style={{ display: "none" }}
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  e.target.value = "";
                  if (f) importUrlList(f);
                }}
              />
            </label>
          </span>
          <textarea
            value={targetUrls}
            onChange={(e) => setTargetUrls(e.target.value)}
            placeholder={"https://app.example.com/a\nhttps://api.example.com/v1/x"}
          />
        </label>
        {command === "pilot" ? (
          <div className="nf-checks">
            <label title="survey maps only the target + these URLs (no link-following); diagnosis is limited to the list + the APIs each screen calls">
              <input type="checkbox" checked={lockToTargets} onChange={(e) => setLockToTargets(e.target.checked)} /> 🔒 lock to target URLs (no crawl — diagnose only the list + their APIs)
            </label>
          </div>
        ) : null}
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
            <input value={maxDepth} onChange={(e) => setMaxDepth(e.target.value)} placeholder="10" inputMode="numeric" />
          </label>
        </div>
      </details>

      <details className="nf-section">
        <summary>HTTP Basic auth (site-wide — the browser 401 dialog, before the app login)</summary>
        <div className="nf-grid">
          <label className="nf-field">
            <span>Basic user</span>
            <input value={basicUser} onChange={(e) => setBasicUser(e.target.value)} placeholder="(leave blank if none)" autoComplete="off" />
          </label>
          <label className="nf-field">
            <span>Basic password</span>
            <input type="password" value={basicPass} onChange={(e) => setBasicPass(e.target.value)} autoComplete="off" />
          </label>
        </div>
      </details>

      <details className="nf-section">
        <summary>Custom headers ({headersList.length}) — added to in-scope requests (WAF bypass / required headers)</summary>
        {headersList.map((h, i) => (
          <div className="nf-role" key={i}>
            <input placeholder="header name (e.g. X-Forwarded-For)" value={h.name} onChange={(e) => setHeader(i, { name: e.target.value })} autoComplete="off" />
            <input placeholder="value" value={h.value} onChange={(e) => setHeader(i, { value: e.target.value })} autoComplete="off" />
            <button type="button" onClick={() => rmHeader(i)}>
              ✕
            </button>
          </div>
        ))}
        <button type="button" className="nf-addrole" onClick={addHeader}>
          + add header
        </button>
      </details>

      <details className="nf-section">
        <summary>Auth roles ({roles.length}) — a “manual” role makes the run attended (log in via the Sessions tab)</summary>
        <label className="nf-field" title="entry URL for manual login windows (attended). blank = target URL.">
          <span>Login URL (manual login entry — blank = target)</span>
          <input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)} placeholder="https://app.example.com/login" autoComplete="off" />
        </label>
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
