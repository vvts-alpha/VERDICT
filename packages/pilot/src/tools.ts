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
import type { EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse } from "@veritas/scanner";
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
  done: boolean;
  doneSummary: string;
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
  // ── attended(手動マルチセッション認証)──
  /** 手動ログイン済みのロール別ライブセッション。未指定 = 通常(単一コンテキスト)モード。 */
  roleSessions?: Map<string, RoleSession>;
}

/** ステージごとに見せるツール(基底名)。run.ts が `mcp__veritas__` を付けて allowedTools に渡す。 */
export const STAGE_TOOLS = {
  survey: ["browser_navigate", "browser_fill", "browser_click", "login", "probe_paths", "ignore_paths", "survey_status", "survey_done"],
  methodology: ["get_inventory", "record_methodology", "methodology_done"],
  diagnose: ["get_screen", "login", "http_request", "probe_params", "analyze_session", "verify_access", "browser_navigate", "browser_fill", "browser_click", "record_finding", "screen_done"],
} as const;

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

export function stripHash(u: string): string {
  const i = u.indexOf("#");
  return i >= 0 ? u.slice(0, i) : u;
}

const SEV_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];
function maxSev(a: Severity, b: Severity): Severity {
  return SEV_ORDER.indexOf(a) >= SEV_ORDER.indexOf(b) ? a : b;
}

/** vulnClass の自由文 → 粗いカテゴリ(dedup キー用)。同じ穴の言い換えを1つに畳む。
 *  正準カテゴリ(CATEGORIES)を渡された場合はそのまま返す(冪等。xss-stored の誤畳み防止)。 */
export function coarseClass(vulnClass: string): string {
  const s = vulnClass.toLowerCase();
  if ((CATEGORIES as readonly string[]).includes(s)) return s;
  if (/stored xss|persistent xss/.test(s)) return "xss-stored";
  if (/xss|cross[\s-]?site script/.test(s)) return "xss-reflected";
  if (/path travers|arbitrary file|file read|\blfi\b|directory travers|cwe-22/.test(s)) return "path-traversal";
  if (/\bsqli\b|sql inj/.test(s)) return "sqli";
  if (/idor|bola|object[\s-]?level|broken access|broken object/.test(s))
    return /write|overwrite|update|modif|edit/.test(s) ? "idor-write" : "idor";
  if (/open redirect|unvalidated redirect/.test(s)) return "open-redirect";
  if (/\bssrf\b/.test(s)) return "ssrf";
  if (/\brce\b|command inj|remote code/.test(s)) return "rce";
  if (/rate limit|lockout|brute[\s-]?force/.test(s)) return "rate-limit";
  if (/security header|missing header|response header/.test(s)) return "headers";
  if (/\bcsrf\b|cross[\s-]?site request/.test(s)) return "csrf";
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
  "other",
] as const;

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

function cookieHeader(s: PilotSession): Record<string, string> {
  return s.currentCookie ? { cookie: s.currentCookie } : {};
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
  o: Pick<Observation, "finalUrl" | "links">,
  s: Pick<PilotSession, "scope" | "lockToSeeds" | "visited" | "ignorePaths" | "targetUrl">,
): string[] {
  if (s.lockToSeeds) return [];
  const out: string[] = [];
  for (const link of o.links) {
    let abs: string;
    try {
      abs = stripHash(new URL(link, o.finalUrl).toString());
    } catch {
      continue;
    }
    if (!isInScope(abs, s.scope)) continue;
    if (isSessionDestroyingPath(abs)) continue; // logout/signout リンクは frontier に積まない(踏むと自滅)
    if (pathIsIgnored(abs, s.ignorePaths, s.targetUrl)) continue; // モデルが間引いた低価値パスは積まない
    if (!s.visited.has(abs)) out.push(abs);
  }
  return out;
}

/** 診断プローブの応答ステータスを集計(認証壁サーキットブレーカ用)。401=壁、2xx=通過。 */
function bumpHttp(s: PilotSession, status: number): void {
  s.httpProbes += 1;
  if (status === 401) s.httpAuthWall += 1;
  else if (status >= 200 && status < 300) s.httpThrough += 1;
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
          headers: { ...(s.currentCookie ? { cookie: s.currentCookie } : {}), ...(headers ?? {}) },
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
          s.currentRole = role;
          return txt(`switched to live attended session for role '${role}'${tag} (manual login; cookie ${live.cookie ? "present" : "empty"}).`);
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
            s.currentRole = role;
            return txt(`logged in as '${role}'${tag}; now at ${s.driver.currentUrl()}`);
          }
          return txt(`login as '${role}' did not complete: ${r.reason}`);
        } catch (e) {
          return txt(`login error: ${String(e).slice(0, 200)}`);
        }
      },
    ),
    tool(
      "record_finding",
      "Record a CONFIRMED vulnerability. Only after evidence discipline (a negative control that fails + >=2 positive replays that succeed). Cite the evidenceIds. Pick the canonical `category`, and pass the vulnerable `endpoint` (URL or path template, e.g. /search or /orders/{id}) and `param` (e.g. q) — findings are DEDUPED by (category, endpoint, param): re-confirming the same hole MERGES into the existing finding instead of creating a duplicate.",
      {
        title: z.string(),
        severity: z.enum(["info", "low", "medium", "high", "critical"]),
        category: z.enum(CATEGORIES),
        endpoint: z.string(),
        param: z.string().optional(),
        description: z.string(),
        reproSteps: z.string(),
        evidenceIds: z.array(z.string()).min(1),
      },
      async ({ title, severity, category, endpoint, param, description, reproSteps, evidenceIds }) => {
        // auth-bypass は verify_access の機械判定を通った時だけ記録できる(CRM の 302/401 誤検知を硬く封じる)。
        if (category === "auth-bypass") {
          const av = s.accessVerdicts.get(normEndpoint(endpoint, s.targetUrl));
          if (av === "not_bypass")
            return txt(`REJECTED: verify_access on ${endpoint} returned 'not_bypass' (redirect→login / 401 / 403 = auth is enforced). Mechanical veto, cannot record.`);
          if (!av) return txt(`REQUIRED: run verify_access(${endpoint}) before recording auth-bypass (302→login / 401 / 403 is not a bypass).`);
        }
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
      "Finish diagnosing the current screen. verdict 'finding' if at least one confirmed vulnerability was recorded for it, else 'clean'.",
      { verdict: z.enum(["finding", "clean"]), note: z.string().optional() },
      async ({ verdict, note }) => {
        s.screenVerdict = verdict;
        s.screenDone = true;
        if (note) s.store.appendEvent(s.assessmentId, { type: "note", payload: { message: `✓ ${s.currentScreenId}: ${note.slice(0, 200)}` } });
        return txt(`screen ${s.currentScreenId} → ${verdict}`);
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
          const r = await s.http.send({ method: "GET", url: new URL(`/veritas-404-${Date.now()}`, s.targetUrl).toString(), headers: cookieHeader(s), body: null });
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
            res = await s.http.send({ method: "GET", url, headers: cookieHeader(s), body: null });
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
          base = await s.http.send({ method: "GET", url, headers: cookieHeader(s), body: null });
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
            res = await s.http.send({ method: "GET", url: u, headers: cookieHeader(s), body: null });
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
            request: { method: "GET", url: u, headers: s.http.effectiveHeaders(cookieHeader(s)), body: null },
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
        if (s.currentCookie) {
          try {
            rAuth = await s.http.send({ method: "GET", url, headers: { cookie: s.currentCookie }, body: null });
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
              request: { method: "GET", url, headers: s.http.effectiveHeaders(cookieHeader(s)), body: null },
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
