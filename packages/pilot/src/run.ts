// Claude 主導の 3 ステージ・オーケストレータ。
//
// 一度に全部投げると AI は省略するので、調査 → 方法論 → 診断 に分節して query() を分けて回す。
// 各ステージは allowedTools でツールを絞り、phase を進める。診断は screens を 1 枚ずつバウンドした
// 文脈で回す(= カバレッジ台帳の queued を全部 terminal にする)ので、画面の取りこぼしが構造的に出ない。

import { createSdkMcpServer, query } from "@anthropic-ai/claude-agent-sdk";
import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import type { AssessmentStore, Screen, ScopePolicy } from "@veritas/core";
import { isInScope, isScannable, recordTokens } from "@veritas/core";
import type { LoginCreds } from "@veritas/crawler";
import { InventoryBuilder, PlaywrightDriver, smartLogin } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import type { BurpAuditConn } from "@veritas/scanner";
import { join } from "node:path";
import { buildTools, STAGE_TOOLS, dedupKey, isAuthWalled, loadCookieFile, sessionLooksDead, stripHash } from "./tools.js";
import type { PilotSession, RoleSession } from "./tools.js";
import { LiveControl } from "./live-control.js";
import { DEFAULT_SCENARIOS, DIAGNOSE_PROMPT, FINGERPRINT_PROMPT, METHODOLOGY_PROMPT, SCENARIO_PROMPT, SURVEY_PROMPT } from "./system.js";

export interface RunPilotOptions {
  store: AssessmentStore;
  assessmentId: string;
  targetUrl: string;
  scope: ScopePolicy;
  /** 複数シード(診断対象 URL のリスト)。survey はこれら全てを起点にする。未指定なら [targetUrl] 相当。 */
  seedUrls?: string[];
  /** URL リストのハードロック: survey はシードだけをマップし、発見リンクを辿らない(横断クロールしない)。
   *  診断はマップされた画面 = シード + 各画面が叩く API に限定される。「対象がガッチガチに URL 固定」用。 */
  lockToSeeds?: boolean;
  /** サイト全体を覆う HTTP Basic/Digest 認証(operator 提供)。ブラウザは httpCredentials で自動応答、
   *  raw http(FetchHttpClient)には Authorization: Basic を注入(Digest はブラウザ経路のみ)。 */
  httpBasic?: { user: string; pass: string };
  /** operator 提供のカスタムヘッダ(WAF 回避・案件指定の必須ヘッダ等)。ブラウザ(同一オリジンのみ)+
   *  raw http 経路の両方に付与する。 */
  customHeaders?: Record<string, string>;
  profileDir: string;
  artifactsDir: string;
  roleCreds: Map<string, LoginCreds>;
  /** ロール名 → 事前取得 Cookie ファイルのパス(資格情報の代わり。自動ログイン不能な壁向け)。 */
  roleCookieFiles?: Map<string, string>;
  /** ロール名 → 権限の自由記述(例: "全権管理者" / "一般ユーザ(読取のみ)")。
   *  エージェントが auth-diff で高/低権限を見分けるための文脈。秘密ではないが state には永続しない。 */
  roleDescriptions?: Map<string, string>;
  /** 診断の「深い」モデル(創発が要る高価値画面)。例 claude-opus-4-8。未指定なら SDK 既定。 */
  model?: string;
  /** survey/methodology/login と低価値画面の「速い」モデル(例 claude-sonnet-4-6)。
   *  未指定なら model と同じ(= モデル使い分け無し・挙動不変)。指定すると Opus/Sonnet を tier 化。 */
  fastModel?: string;
  /** 診断後の A04 シナリオ(画面横断の多段ロジック濫用)ステージを実行するか。既定 true。
   *  取引面(カート/注文/決済/クーポン/送金/権限変更)が無ければ自動スキップ。deep モデル固定。 */
  scenarioPass?: boolean;
  /** シナリオ段に常駐の既定シナリオ(資格情報ハント等の横断目的)を注入するか。既定 true。--no-default-scenarios で off。 */
  defaultScenarios?: boolean;
  /** A06 フィンガープリント(版収集→既知 CVE 評価)ステージを実行するか。既定 true。--no-fingerprint で off。 */
  fingerprintPass?: boolean;
  /** A06 で検出版をオンライン CVE DB(OSV/NVD)へ照会するか。既定 false(第三者への egress = opt-in)。--cve-lookup で on。 */
  cveLookup?: boolean;
  maxTurns?: number;
  rateMs?: number;
  headless?: boolean;
  browserPath?: string;
  noSandbox?: boolean;
  /** 診断する画面数の上限(既定 40)。 */
  maxScreens?: number;
  /** 既存 run の再開: survey/methodology をスキップし、未診断(非 terminal)画面だけ診断する。 */
  resume?: boolean;
  /** 全量抽出(画面調査): survey の動的間引き(ignore_paths)を無効化し、全画面をマップする。
   *  未指定なら ignore_paths が有効(モデルが低価値な CMS コンテンツ木などを自分で間引いて frontier 爆発を抑える)。 */
  exhaustiveSurvey?: boolean;
  /** 調査のみ: survey ステージだけ実行し、methodology/診断をしない(screens/スクショ/API は出す、finding は出さない)。
   *  後で `resume` で診断に繋げられる(map now / diagnose later)。 */
  surveyOnly?: boolean;
  /** Burp 等の上流プロキシ(例 http://127.0.0.1:8080)。指定時のみ HTTP+ブラウザを経由。未指定=現状通り。 */
  burpProxy?: string;
  /** 認証セッション維持: 診断中、この分数を超えて間が空いたら画面の合間にトップへ navigate して
   *  cookie を再同期する(0 で無効)。sliding/短命トークンの stale 化対策。既定 4 分。 */
  keepAliveMinutes?: number;
  /** attended(手動マルチセッション認証): ロールごとに headed 永続コンテキストを 1 つ起動し、
   *  人手でログイン(CAPTCHA/MFA/Arkose も突破)させてから調査・診断を回す。診断はロール別ライブ
   *  Cookie を使う。CAPTCHA/MFA・絶対TTL 失効など 自動ログイン/Cookieファイルで越えられない壁向け。 */
  attended?: boolean;
  /** attended で窓を開くロール名の全集合(manifest の auth.roles[].name)。資格情報も Cookie ファイルも
   *  持たない「純手動」ロールもここに含めれば窓が開く(手動 N アカウント)。未指定なら creds/cookie のキーから導出。 */
  attendedRoles?: string[];
  /** attended のロール別プロファイルの親ディレクトリ(各ロールは <dir>/<role>)。既定は profileDir の隣 `profiles/`。 */
  attendedProfilesDir?: string;
  /** attended で各ロール窓を最初に開く URL(手動ログインの入口)。未指定なら targetUrl。 */
  loginUrl?: string;
  /** attended の人手操作待ち: メッセージを表示し、operator が Enter を押したら解決する。
   *  CLI が readline で供給(pilot パッケージは TTY を仮定しない)。attended では必須(controlUrl 指定時は不要)。 */
  promptOperator?: (message: string) => Promise<void>;
  /** attended×LiveHands: serve に逆接続して role セッションを WebUI に screencast する。
   *  指定時は headless で起動し、手動ログイン完了は操作者の「Done」で解決(ターミナル Enter 不要)。 */
  controlUrl?: string;
  onText?: (text: string) => void;
  onTool?: (name: string, input: unknown) => void;
  /** 診断/シナリオの後、**セッションを保ったまま**実行する追加スキャンのフック(Burp 能動スキャン等)。
   *  指定時のみ phase2_burpscan を report の前に挟む。keepWarm() を定期的に呼べば authed セッションを維持できる
   *  (長い Burp スキャン中にトークン/Cookie が stale 化しないように)。driver はこの時点でまだ生きている。 */
  onBurpScanPhase?: (ctx: { keepWarm: () => Promise<void>; cookie: string; bearer: string }) => Promise<void>;
  /** OOB(Burp Collaborator)接続。設定すると診断中に probe_oob が使える(ブラインド SSRF/XXE/SQLi の確証)。
   *  CLI が BURP_AUDIT_API/BURP_AUDIT_TOKEN から解決して渡す。未設定なら probe_oob は not-available。 */
  oob?: BurpAuditConn;
  /** 操作者の重点ヒント(自由文)。**シナリオ段の最優先目的**として注入する(per-screen 診断には混ぜない)。
   *  例 "決済フローと /api/orders の IDOR を重点的に。クーポン/価格改ざんも"。emphasis であって排他ではない。 */
  focus?: string;
  /** 入力欄スイープ: browser_navigate のたびにフォーム/検索を benign 値で送信して新ルート/API を発見(既定 on）。 */
  inputSweep?: boolean;
  /** 入力スイープで POST フォームも送信する(=標的にデータを書く)。既定 true。false なら GET/検索のみ。 */
  aggressiveForms?: boolean;
}

export interface PilotResult {
  findings: PilotSession["findings"];
  summary: string;
  turns: number;
  /** この run で使ったトークン(input+output+cache の合計)。 */
  tokensUsed: number;
  /** この run の概算コスト(USD。サブスクなら API 換算の目安)。 */
  costUsd: number;
}

// disallowedTools は「モデルに見せない」リスト。onlyVeritasToolsHook が真の境界(全 non-veritas を deny)だが、
// ここに **挙げていない組み込みツールは claude_code preset がモデルに提示する** → モデルが ToolSearch/TodoWrite/Task
// 等を叩いて PreToolUse 拒否され、ターンとログを浪費する(実 run で頻発)。なので preset の組み込み系を網羅して隠す。
const DISALLOWED = [
  // file / exec / web
  "Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "WebFetch", "WebSearch",
  // agentic / meta(これが「tools search が使えない」の犯人。隠せばモデルは叩きに行かない)
  "Task", "Agent", "ToolSearch", "TodoWrite", "Skill", "Monitor", "Workflow", "EnterPlanMode", "ExitPlanMode", "SendMessage",
  "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskStop", "TaskOutput", "CronCreate", "CronList", "CronDelete",
];

/** pilot は veritas の MCP ツールだけで回す(bounded 設計)。だが SDK は Bash/Read 以外にも Task/Agent/
 *  Monitor/Skill/ToolSearch/TaskCreate… を公開しており、bypassPermissions 下ではモデルがそれらを呼べてしまう
 *  (Monitor/Skill は実質 shell 実行 = Bash 禁止のすり抜け、Agent は無制限サブエージェント生成)。
 *  PreToolUse フックで mcp__veritas__* 以外を一律 deny する。disallowedTools の列挙に依存しない allowlist で、
 *  bypassPermissions 下でも PreToolUse の deny は効く(SDK 仕様)。新ツールが増えても自動で塞がる。 */
/** pilot で呼んでよいツールか(veritas の MCP ツールのみ許可)。Task/Agent/Monitor/Skill/ToolSearch 等は false。 */
export function isPilotAllowedTool(name: string): boolean {
  return name.startsWith("mcp__veritas__");
}

const onlyVeritasToolsHook: HookCallback = async (input) => {
  const name = (input as { tool_name?: string }).tool_name ?? "";
  if (isPilotAllowedTool(name)) return { continue: true };
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `pilot only permits veritas tools. '${name}' is denied (process get_inventory results directly with record_methodology; do not offload to external tools).`,
    },
  };
};

/** 診断のモデル使い分け: 認証下 / object-ref・id param / idor-candidate 等ラベル / 認証付き API を持つ
 *  「高価値画面」は deep(例 opus)で診断、入力の無い静的画面は fast(例 sonnet)。 */
function screenIsHighValue(sc: Screen): boolean {
  if (sc.authState === "post-login") return true;
  if (sc.labels.some((l) => /idor|pii|upload|admin|payment|auth/i.test(l))) return true;
  if (sc.params.some((p) => p.guessedType === "object_ref" || p.guessedType === "id")) return true;
  if (sc.apis.some((a) => a.auth !== "none")) return true;
  return false;
}

/** resume 時に「前回 run で survey / methodology がどこまで終わったか」を判定する純関数。
 *  survey_done マーカーはモデルが呼ばず出ないことがある(maxTurns で stage 終了)ので、
 *  phase(recon を越えている=phase1_label 以降)と methodology の 📋 PLAN イベントも OR で見る。 */
export function resumeStageState(
  prev: { phase: string; events: ReadonlyArray<{ type: string; payload: unknown }> } | null,
): { surveyDone: boolean; methodologyDone: boolean } {
  if (!prev) return { surveyDone: false, methodologyDone: false };
  const notes = prev.events
    .filter((e) => e.type === "note")
    .map((e) => {
      const m = (e.payload as { message?: unknown }).message;
      return typeof m === "string" ? m : "";
    });
  const methodologyDone = notes.some((m) => /📋 PLAN s-\d+/.test(m));
  const DONE_PHASES = new Set(["phase1_label", "phase2_scan", "report", "done"]);
  const surveyDone = DONE_PHASES.has(prev.phase) || methodologyDone || notes.some((m) => m.includes("SURVEY done"));
  return { surveyDone, methodologyDone };
}

/** Claude(サブスク CLI / SDK)の利用上限・トークン枯渇エラーかを判定する純関数。
 *  該当したら「スキップして次へ」ではなく run を一時停止(resume 可能)させる。
 *  ネットワーク先(診断対象)由来の 429 はこの経路(LLM 呼び出しの失敗)には来ないので誤検知しない。
 *  一過性の overloaded(529)は含めない — リトライで回復するので止めるべきではない。 */
export function isClaudeUsageLimit(text: string): boolean {
  const s = (text || "").toLowerCase();
  return (
    /usage limit|usage_limit/.test(s) ||
    /session limit/.test(s) || // 「You've hit your session limit …」(claude CLI のサブスク上限)
    /limit reached/.test(s) ||
    /hit your\b[\s\S]{0,30}\blimit/.test(s) || // 「(you've) hit your session/usage limit」
    /\blimit\b[\s\S]{0,40}\bresets?\b/.test(s) || // 「… limit · resets 12:50am」(limit と resets の共起)
    /rate.?limit/.test(s) ||
    /too many requests/.test(s) ||
    /\b429\b/.test(s) ||
    /quota/.test(s) ||
    /resets?\s+(at\b|\d)/.test(s) || // 「reset at …」/「resets 12:50am」両方
    /insufficient (credit|quota|balance|funds)/.test(s) ||
    /out of (credit|tokens)/.test(s)
  );
}

/** epoch(秒 or ミリ秒)を「(resets <ISO>)」に整形。判別不能なら空文字。 */
function fmtReset(epoch: unknown): string {
  if (typeof epoch !== "number" || !Number.isFinite(epoch) || epoch <= 0) return "";
  const ms = epoch < 1e12 ? epoch * 1000 : epoch; // 秒なら ms に正規化
  try {
    return ` (resets ${new Date(ms).toISOString()})`;
  } catch {
    return "";
  }
}

/**
 * SDK メッセージの**構造化フィールド**から利用上限を判定する一次シグナル(文字列マッチより堅い)。
 * 該当時は pause 理由文字列を、非該当は null を返す。順に強い順:
 *  1. `rate_limit_event` … 専用イベント。`status==='rejected'` = 今まさに弾かれている(+ 復帰時刻)。
 *  2. `assistant.error` …  `'rate_limit' | 'billing_error'`(`'overloaded'` は一過性なので**含めない**)。
 *  3. `result.api_error_status` … HTTP 429。
 * これで「You've hit your session limit …」のような文言ゆれに依存せず確定できる。throw 経路だけは
 * 文字列しか無いので isClaudeUsageLimit() をフォールバックに残す。
 */
export function usageLimitFromMessage(msg: unknown): string | null {
  const m = msg as { type?: string; error?: string; rate_limit_info?: Record<string, unknown>; api_error_status?: number | null };
  if (!m || typeof m !== "object") return null;
  if (m.type === "rate_limit_event") {
    const info = m.rate_limit_info ?? {};
    if (info.status === "rejected") {
      return `rate_limit_event: ${String(info.rateLimitType ?? "rate limit")} rejected${fmtReset(info.resetsAt)}`;
    }
    return null; // allowed / allowed_warning は止めない
  }
  if (m.type === "assistant" && (m.error === "rate_limit" || m.error === "billing_error")) {
    return `assistant error: ${m.error}`;
  }
  if (m.type === "result" && m.api_error_status === 429) {
    return "result api_error_status 429";
  }
  return null;
}

/** SDK usage(assistant/result どちらの形でも)を input+output+cache の合計トークンに畳む。 */
export function usageTokens(u: Record<string, number> | undefined): number {
  return u ? (u.input_tokens ?? 0) + (u.output_tokens ?? 0) + (u.cache_read_input_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) : 0;
}

/** 1 ステージのトークン計上値。result(cumulative)を読めたらそれを採用し、読めなければ(done ツールでの
 *  早期 break / maxTurns)assistant 各ターンの積算でフォールバックする。max を取るのは取りこぼし保険。 */
export function stageTokenDelta(assistantTokens: number, resultTokens: number, sawResult: boolean): number {
  return sawResult ? Math.max(resultTokens, assistantTokens) : assistantTokens;
}

/** operator 向け表示用のロールラベル。description があれば 「role」(説明) の形にして、
 *  手動ログイン窓で「どのアカウントでログインすべきか(管理者/一般 等)」が分かるようにする。 */
export function roleLabel(role: string, descriptions?: Map<string, string>): string {
  const d = descriptions?.get(role);
  return d ? `'${role}' (${d})` : `'${role}'`;
}

export async function runPilot(opts: RunPilotOptions): Promise<PilotResult> {
  const launchBase = {
    headless: opts.headless ?? true,
    // x-amraam マーカーは driver 側で「同一オリジンのみ」に付く(クロスオリジンは付けない=第三者を壊さない)。
    // スコープは別概念で、別ドメイン/API を含めて広げてよい(診断は http 経路で in-scope なら何でも叩ける)。
    ...(opts.browserPath ? { executablePath: opts.browserPath } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
    // サイト全体の Basic/Digest: Playwright が 401 を自動応答(全 driver 起動=attended ロール窓含む)。
    ...(opts.httpBasic ? { httpCredentials: { username: opts.httpBasic.user, password: opts.httpBasic.pass } } : {}),
    // operator のカスタムヘッダ(WAF 回避等)。同一オリジンのみに付く(driver 側でゲート)。
    ...(opts.customHeaders && Object.keys(opts.customHeaders).length ? { extraHeaders: opts.customHeaders } : {}),
  };

  // ── attended: ロールごとに headed 永続コンテキストを 1 つ起動し、人手でログインさせる ──
  //    生きたセッションをロール別に保持し、診断は login() で driver/cookie を swap して使う。
  let driver: PlaywrightDriver;
  let roleSessions: Map<string, RoleSession> | undefined;
  let primaryRole = "";
  let primaryCookie = "";
  let liveControl: LiveControl | undefined;
  if (opts.attended) {
    if (!opts.promptOperator && !opts.controlUrl)
      throw new Error("attended mode requires promptOperator (Enter-confirm) or controlUrl (WebUI login)");
    // 窓を開くロール: 明示の attendedRoles を最優先(純手動ロールも含む)。無ければ creds/cookie のキーから。
    const roles = [
      ...new Set([...(opts.attendedRoles ?? []), ...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])]),
    ];
    if (roles.length === 0) roles.push("primary"); // ロール未設定でも単一の手動セッションは張れる
    const baseDir = opts.attendedProfilesDir ?? join(opts.profileDir, "..", "profiles");
    roleSessions = new Map();
    // controlUrl 指定時は WebUI でログインするので headless(サーバに画面不要)。
    const viaWeb = !!opts.controlUrl;
    if (viaWeb) liveControl = new LiveControl(opts.controlUrl!, opts.onText);
    opts.onText?.(
      viaWeb
        ? `👤 attended (WebUI): ${roles.length} session(s) — log in via the Sessions tab`
        : `👤 attended: launching ${roles.length} headed session(s) per role (manual login)`,
    );
    // 各 role を起動し認証を解決する。cookie→注入 / creds→smartLogin(失敗時 manual へ) / 無材料→manual。
    // viaWeb の manual は後でまとめて登録し Done を並行待ち(N タブ同時)。CLI(非 viaWeb)は従来どおり順次 Enter。
    const manual: Array<{ role: string; driver: PlaywrightDriver }> = [];
    const earlyLlm = viaWeb ? new ClaudeCliClient({ defaultModel: opts.fastModel ?? "claude-sonnet-4-6" }) : undefined;
    for (const role of roles) {
      const d = await PlaywrightDriver.launch({ ...launchBase, userDataDir: join(baseDir, role), headless: viaWeb });
      const cookieFile = opts.roleCookieFiles?.get(role);
      const creds = opts.roleCreds.get(role);
      let deferred = false;
      if (cookieFile) {
        try {
          const { browserCookies } = loadCookieFile(cookieFile, opts.targetUrl);
          await d.clearSession();
          await d.addCookies(browserCookies);
          await d.gotoUrl(opts.targetUrl);
          opts.onText?.(`🍪 role ${roleLabel(role, opts.roleDescriptions)}: injected ${browserCookies.length} pre-captured cookie(s) (no manual login needed)`);
        } catch (e) {
          opts.onText?.(`⚠ role '${role}' cookie file error: ${String(e).slice(0, 120)}`);
        }
      } else if (viaWeb && creds && earlyLlm) {
        // 資格情報あり → 自動ログイン。失敗(CAPTCHA/MFA)時は manual タブにフォールバック。
        await d.gotoUrl(opts.loginUrl ?? opts.targetUrl);
        let ok = false;
        try {
          await d.clearSession();
          const r = await smartLogin(d, earlyLlm, creds, { targetUrl: opts.targetUrl, ...(opts.model ? { model: opts.model } : {}) });
          ok = r.ok;
          opts.onText?.(
            ok
              ? `🔑 role ${roleLabel(role, opts.roleDescriptions)}: auto-logged in`
              : `↪ role ${roleLabel(role, opts.roleDescriptions)}: auto-login failed (${r.reason}) → manual`,
          );
        } catch (e) {
          opts.onText?.(`↪ role ${roleLabel(role, opts.roleDescriptions)}: auto-login error → manual (${String(e).slice(0, 80)})`);
        }
        if (!ok) {
          manual.push({ role, driver: d });
          deferred = true;
        }
      } else if (viaWeb) {
        await d.gotoUrl(opts.loginUrl ?? opts.targetUrl);
        manual.push({ role, driver: d });
        deferred = true;
      } else {
        // CLI attended: 従来どおり 1 ロールずつ Enter で確認。
        await d.gotoUrl(opts.loginUrl ?? opts.targetUrl);
        await opts.promptOperator!(`▶ Please log in manually in the browser window for role ${roleLabel(role, opts.roleDescriptions)} (clear CAPTCHA/MFA too). Press Enter when done…`);
      }
      if (!deferred) {
        const cookie = await d.sessionCookieHeader();
        roleSessions.set(role, { driver: d, cookie });
        opts.onText?.(`✅ role ${roleLabel(role, opts.roleDescriptions)} session established (cookie ${cookie ? "present" : "absent"})`);
      }
    }
    // viaWeb の manual ロールを全部登録 → Done を**並行**待ち(N タブが一斉に出る) → セッション確定。
    if (liveControl && manual.length > 0) {
      opts.onText?.(`🖥 ${manual.length} session(s) need manual login — open the Sessions tab, log in each, then press Done.`);
      for (const m of manual) await liveControl.register(m.role, m.driver);
      await Promise.all(manual.map((m) => liveControl!.waitForDone(m.role)));
      for (const m of manual) {
        const cookie = await m.driver.sessionCookieHeader();
        roleSessions.set(m.role, { driver: m.driver, cookie });
        opts.onText?.(`✅ role ${roleLabel(m.role, opts.roleDescriptions)} session established (cookie ${cookie ? "present" : "absent"})`);
      }
    }
    primaryRole = roles[0]!;
    const prim = roleSessions.get(primaryRole)!;
    driver = prim.driver;
    primaryCookie = prim.cookie;
  } else {
    driver = await PlaywrightDriver.launch({ ...launchBase, userDataDir: opts.profileDir });
  }

  const http = new FetchHttpClient({
    allow: (u) => isInScope(u, opts.scope),
    minDelayMs: opts.rateMs ?? 250,
    headers: {
      "x-amraam": "assessment",
      // サイト全体の Basic: raw http 経路にも Authorization を注入(Digest はブラウザ経路のみ対応)。
      ...(opts.httpBasic ? { authorization: `Basic ${Buffer.from(`${opts.httpBasic.user}:${opts.httpBasic.pass}`, "utf8").toString("base64")}` } : {}),
      ...(opts.customHeaders ?? {}), // operator のカスタムヘッダ(WAF 回避等)を raw http 経路にも付与
    },
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
  });

  // モデル使い分け: deep = 診断の高価値画面(opus 等)、fast = survey/methodology/login/低価値画面(sonnet 等)。
  // fastModel 未指定なら deep と同じ = tier 無し(挙動不変)。
  const deepModel = opts.model;
  const fastModel = opts.fastModel ?? opts.model;

  const session: PilotSession = {
    driver,
    http,
    evidence: new EvidenceStore(opts.artifactsDir),
    store: opts.store,
    assessmentId: opts.assessmentId,
    artifactsDir: opts.artifactsDir,
    scope: opts.scope,
    targetUrl: opts.targetUrl,
    roleCreds: opts.roleCreds,
    roleCookieFiles: opts.roleCookieFiles ?? new Map(),
    roleDescriptions: opts.roleDescriptions ?? new Map(),
    loginLlm: new ClaudeCliClient({ defaultModel: fastModel ?? "claude-sonnet-4-6" }),
    currentCookie: primaryCookie, // attended は primary ロールの生 Cookie で開始(通常は "")
    currentBearer: "", // login() がロールごとに localStorage の Bearer JWT を載せる
    currentRole: primaryRole,
    findings: [],
    findCounter: 0,
    findingsByKey: new Map(),
    accessVerdicts: new Map(),
    recordCalls: 0,
    httpProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    screenProbes: 0,
    done: false,
    doneSummary: "",
    paused: false,
    model: fastModel, // login ツール(smartLogin)は機械的 → fast モデル
    inv: new InventoryBuilder(),
    visited: new Set(),
    frontier: new Set(),
    ignorePaths: [],
    exhaustive: !!opts.exhaustiveSurvey,
    lockToSeeds: !!opts.lockToSeeds,
    inputSweep: opts.inputSweep ?? true,
    aggressiveForms: opts.aggressiveForms ?? true,
    cveLookup: opts.cveLookup ?? false, // opt-in: 第三者 CVE DB への egress は明示 on の時だけ
    plans: new Map(),
    currentScreenId: null,
    screenVerdict: null,
    surveyDone: false,
    methodologyDone: false,
    screenDone: false,
    scenarioDone: false,
    fingerprintDone: false,
    ...(opts.oob ? { oob: opts.oob } : {}),
    ...(roleSessions ? { roleSessions } : {}),
  };

  // 複数シード: target 以外のシード URL を frontier に積んで survey の起点にする
  // (ハードロックでも初期シードは積む。以降の発見リンク拡張だけ recordObservation が抑止する)。
  const seedList = [...new Set([opts.targetUrl, ...(opts.seedUrls ?? [])])];
  for (const u of seedList) {
    if (stripHash(u) !== stripHash(opts.targetUrl)) session.frontier.add(stripHash(u));
  }

  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: buildTools(session) });
  const rolesLine =
    [...new Set([...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])])]
      .map((r) => {
        const d = opts.roleDescriptions?.get(r);
        return d ? `${r} (${d})` : r;
      })
      .join(", ") || "none";
  const maxTurns = opts.maxTurns ?? 80; // CLI 既定と一致(main.ts も 80)。WebUI 空欄→CLI 既定で 80 に揃う。

  // ── resume: 既存 run から再シード(survey/methodology はスキップ、未診断画面だけ診断) ──
  const prev = opts.resume ? opts.store.loadAssessment(opts.assessmentId) : null;
  const resumeStatus = prev ? new Map(prev.screenScans.map((s) => [s.screenId, s.status] as const)) : null;
  if (prev) {
    session.inv.seed(prev.screens); // screenId 採番 + dedup を継続
    session.currentCookie = await driver.sessionCookieHeader(); // run の認証セッション(browser-profile)を再利用
    session.currentBearer = (await driver.bearerToken().catch(() => null)) ?? ""; // SPA の Bearer JWT も再利用
    session.currentRole = [...opts.roleCreds.keys()][0] ?? "";
    // 方法論プランをイベントログ(📋 PLAN <id>: …)から復元
    for (const e of prev.events) {
      if (e.type === "note") {
        const m = /📋 PLAN (s-\d+): (.+)/.exec(e.payload.message);
        if (m && m[1] && m[2]) session.plans.set(m[1], m[2]);
      }
    }
    // 既存 findings を引き継ぎ(id 採番継続 + dedup キー best-effort で二重報告を抑止)
    for (const f of prev.findings) {
      session.findings.push(f);
      const num = Number.parseInt(f.id.replace(/^f-/, ""), 10);
      if (Number.isFinite(num)) session.findCounter = Math.max(session.findCounter, num);
      const cat = /^\[([a-z0-9-]+)\]/.exec(f.title)?.[1] ?? "other";
      const ep = /(\/[A-Za-z0-9_{}/.-]+)/.exec(f.title)?.[1] ?? "";
      session.findingsByKey.set(dedupKey(cat, ep, undefined, opts.targetUrl), f);
      session.recordCalls += 1;
    }
    opts.store.appendEvent(opts.assessmentId, {
      type: "note",
      payload: { message: `↺ resume: ${prev.screens.length} screens / ${prev.findings.length} findings carried over` },
    });
  }

  // トークン使用量: 各 query() の result からトークンを拾い、run の budget(累計)に貯めて永続化。
  let budget = (prev ?? opts.store.loadAssessment(opts.assessmentId))?.budget ?? null;
  let runTokens = 0; // この run の増分(サマリ表示用)
  let costUsd = 0;

  // トークン/利用上限の枯渇でステージが落ちたら、スキップして次画面へ進めず run を一時停止する。
  //   done=true で以降の全ステージ/画面を止め、paused=true で最終処理が report に落とさない(resume 可能)。
  //   利用枠が回復したら `pilot --resume --id <id>`(WebUI の ▶ resume)で未診断の queued 画面から続けられる。
  const pauseRun = (detail: string): void => {
    if (session.paused) return; // 二重計上しない
    session.done = true;
    session.paused = true;
    session.doneSummary = `⏸ paused — Claude usage/token limit reached. Resume when it resets: pilot --resume --id ${opts.assessmentId}`;
    opts.onText?.(`${session.doneSummary}${detail ? ` (${detail})` : ""}`);
    opts.store.appendEvent(opts.assessmentId, {
      type: "note",
      payload: { message: `${session.doneSummary}${detail ? ` — ${detail}` : ""}` },
    });
    opts.store.setPaused(opts.assessmentId, true, "Claude usage/token limit reached");
  };

  // 1 ステージ = 1 query()。stage の done フラグが立つか、Claude が手を止めたら抜ける。
  const runStage = async (p: {
    system: string;
    goal: string;
    allowed: readonly string[];
    maxTurns: number;
    model?: string;
    shouldStop: () => boolean;
  }): Promise<number> => {
    let turns = 0;
    // トークン計上: result メッセージ(query 終了時の cumulative usage)は shouldStop の早期 break より
    // 後に来るため、done ツールで stage を畳むとほぼ毎回読めず 0 のままだった。そこで assistant 各ターンの
    // usage を積算しておき(早期 break でも残る)、result を読めた場合だけ authoritative な合計で上書きする。
    const tally = usageTokens;
    let assistantTokens = 0;
    let resultTokens = 0;
    let sawResult = false;
    const q = query({
      prompt: p.goal,
      options: {
        mcpServers: { veritas: server },
        allowedTools: p.allowed.map((n) => `mcp__veritas__${n}`),
        disallowedTools: DISALLOWED,
        permissionMode: "bypassPermissions",
        // veritas MCP ツール以外(Task/Agent/Monitor/Skill/ToolSearch/… 含む)を PreToolUse で全拒否する allowlist。
        hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
        ...(p.model ? { model: p.model } : {}),
        systemPrompt: { type: "preset", preset: "claude_code", append: p.system },
        maxTurns: p.maxTurns,
      },
    });
    try {
      for await (const msg of q) {
        // 構造化フィールドを一次シグナルに(rate_limit_event / assistant.error / api_error_status 429)。
        // 検出したら pauseRun が done=true を立て、下の `session.done` チェックでこの stage を抜ける。
        const structuredLimit = usageLimitFromMessage(msg);
        if (structuredLimit) pauseRun(structuredLimit.slice(0, 160));
        if (msg.type === "assistant") {
          assistantTokens += tally((msg.message as unknown as { usage?: Record<string, number> }).usage);
          for (const block of msg.message.content) {
            if (block.type === "text" && block.text.trim()) {
              turns += 1;
              const t = block.text.trim();
              opts.onText?.(t);
              opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: t.slice(0, 400) } });
            } else if (block.type === "tool_use") {
              opts.onTool?.(block.name, block.input);
            }
          }
        } else if (msg.type === "result") {
          const r = msg as unknown as { usage?: Record<string, number>; total_cost_usd?: number; subtype?: string; is_error?: boolean; result?: string };
          sawResult = true;
          resultTokens = tally(r.usage);
          costUsd += r.total_cost_usd ?? 0;
          // エラー結果(throw ではなく result で返るケース)。error_max_turns は正常な打ち切りなので除外。
          if ((r.is_error || (r.subtype && r.subtype !== "success")) && r.subtype !== "error_max_turns") {
            const detail = `${r.subtype ?? "error"} ${r.result ?? ""}`.trim();
            if (isClaudeUsageLimit(detail)) pauseRun(detail.slice(0, 160));
          }
        }
        if (p.shouldStop() || session.done) break;
      }
    } catch (err) {
      // ステージが throw で落ちた場合。トークン/利用上限の枯渇なら **スキップせず一時停止**(resume 可能)。
      // それ以外(maxTurns / 一過性 SDK エラー)は従来どおり best-effort で次の画面/ステージへ。
      // この時点で発火済みのツール(record_finding 等)は既に store に反映されているので finding は失われない。
      const m = String(err instanceof Error ? err.message : err).slice(0, 160);
      if (isClaudeUsageLimit(m)) {
        pauseRun(m);
      } else {
        opts.onText?.(`⚠ stage ended early: ${m}`);
        opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ stage ended early: ${m}` } });
      }
    }
    try {
      await q.return?.(undefined as never);
    } catch {
      /* generator already done */
    }
    // stage 終了後に 1 回だけ計上(早期 break / maxTurns / 正常終了 のどれでも漏らさない)。
    // result を読めたらその cumulative を採用、無ければ assistant 積算でフォールバック。
    const delta = stageTokenDelta(assistantTokens, resultTokens, sawResult);
    if (delta > 0) {
      runTokens += delta;
      if (budget) {
        budget = recordTokens(budget, delta);
        opts.store.updateBudget(opts.assessmentId, budget); // WebUI/status にライブ反映
      }
    }
    return turns;
  };

  let turns = 0;
  try {
    // resume = いま走り始めた = もう停止中ではない。前回トークン枯渇で立てた「⏸ paused」を解除する
    //   (これが残っていると WebUI が稼働中なのに paused 表示のままになる)。
    if (opts.resume && opts.store.isPaused(opts.assessmentId)) {
      opts.store.setPaused(opts.assessmentId, false, "resumed");
    }
    // resume 時に survey/methodology が前回どこまで進んだかを events から判定する。
    // ※ survey-only も「完了」だが phase は phase1_recon のままなので phase では中断と区別できない。
    //   survey_done が出す "SURVEY done" マーカーと、methodology の "📋 PLAN" イベントで判定する。
    const { surveyDone: surveyDonePrev, methodologyDone: methodologyDonePrev } = resumeStageState(prev);
    const doSurvey = !opts.resume || !surveyDonePrev; // resume でも survey 未完なら調査から
    const doMethodology = !opts.surveyOnly && (!surveyDonePrev || !methodologyDonePrev);

    if (doSurvey) {
      // ── STAGE 1: 調査(写像のみ) ── resume で survey 未完なら既存 screens を seed したまま継続。
      if (opts.resume) opts.onText?.("↻ survey was incomplete, resuming from recon");
      opts.store.setPhase(opts.assessmentId, "phase1_recon");
      // ロールがあるなら「フロンティアが空 ≠ 完了」— 認証後サーフェスを必ずマップさせる(survey_done は認証ゲート付き)。
      const authClause =
        rolesLine === "none"
          ? ""
          : ` CRITICAL: an empty frontier is NOT a reason to call survey_done while roles are still unauthenticated. After mapping the public surface you MUST login(role) for EACH role (${rolesLine}), confirm the response shows a cookie/bearer is present, and navigate the authenticated pages it unlocks (orders / basket / wallet / admin / settings / etc.) so they enter the inventory. survey_done is GATED on having an active authenticated session and will be refused otherwise.`;
      const surveyGoal = opts.lockToSeeds
        ? // URL リスト固定: シードだけをマップし、横断クロールしない。
          `URL-list mode — LOCKED. Diagnose ONLY these exact URLs; do NOT follow links or explore beyond this list:\n${seedList.map((u, i) => `  ${i + 1}. ${u}`).join("\n")}\nFor EACH url: browser_navigate to it (its screen and the APIs it calls are recorded automatically). Log in as needed — roles for login(): ${rolesLine}. When survey_status shows the frontier empty (all ${seedList.length} mapped), call survey_done.${authClause}`
        : seedList.length > 1
          ? // 複数シード(横断あり): 各シードを起点にスコープ面をマップ。
            `Map the in-scope surface starting from these ${seedList.length} seed URLs:\n${seedList.map((u) => `  - ${u}`).join("\n")}\nIn-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Visit each seed, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.${authClause}`
          : `Map the entire in-scope surface of ${opts.targetUrl}. In-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Start at the target, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.${authClause}`;
      turns += await runStage({
        system: SURVEY_PROMPT,
        goal: surveyGoal,
        allowed: STAGE_TOOLS.survey,
        maxTurns,
        model: fastModel, // 調査は機械的 → fast
        shouldStop: () => session.surveyDone || session.done,
      });
    }

    // ── STAGE 2: 方法論(全画面の攻撃計画) ── survey-only はスキップ。resume は未完のときだけ実行。
    if (doMethodology && !session.done) {
      opts.store.setPhase(opts.assessmentId, "phase1_label");
      turns += await runStage({
        system: METHODOLOGY_PROMPT,
        goal: `${session.inv.screens().length} screens were mapped. Call get_inventory, then record_methodology for EVERY screen, then methodology_done.`,
        allowed: STAGE_TOOLS.methodology,
        maxTurns: Math.min(maxTurns, 30),
        model: fastModel, // 方法論も fast(構造化された計画立案)
        shouldStop: () => session.methodologyDone || session.done,
      });
    }

    // ── STAGE 3: 診断(1 画面ずつ。台帳の queued を潰し切る) ── ※ survey-only ならスキップ
    if (!opts.surveyOnly && !session.done) {
      opts.store.setPhase(opts.assessmentId, "phase2_scan");
      // resume 時は terminal(clean/finding/excluded)を**先に**飛ばし、未診断だけを maxScreens まで回す。
      // ※ slice を先にすると先頭が全部 terminal の場合に queued を見ずに 0 件で終わる(バグだった)。
      const TERMINAL = new Set(["clean", "finding", "suspected", "excluded"]);
      const candidates = resumeStatus
        ? session.inv.screens().filter((sc) => !TERMINAL.has(resumeStatus.get(sc.screenId) ?? "queued"))
        : session.inv.screens();
      const screens = candidates.slice(0, opts.maxScreens ?? 40);
      opts.onText?.(
        `🔬 diagnosing ${screens.length} screen(s)${resumeStatus ? ` of ${candidates.length} queued` : ""}${candidates.length > screens.length ? ` (capped at ${opts.maxScreens ?? 40}; resume again or raise --max-screens for the rest)` : ""}`,
      );
      // 複数エンドポイントの画面は IDOR 確定までに >25 turn 要る。25 だと記録直前で頭打ちしていた。
      const perScreen = Math.min(maxTurns, 40);

      // ── 認証セッション維持(A) ── 画面の合間に間が空いたらトップへ navigate して cookie を再同期。
      //   sliding/短命トークンが生 HTTP 経路で stale 化するのを防ぐ。currentCookie が無い(unauth)なら何もしない。
      //   attended は 1 ロールごとに生コンテキストを保持しているので、全ロールを巡回して再同期し、
      //   ログイン画面に戻された(失効)ロールは operator に再ログインを求める(死活検知 → handoff)。
      const keepAliveMs = (opts.keepAliveMinutes ?? (opts.attended ? 1 : 4)) * 60_000;
      let lastTouch = Date.now();
      const keepAttendedWarm = async (): Promise<void> => {
        if (!roleSessions) return;
        for (const [role, rs] of roleSessions) {
          try {
            await rs.driver.gotoUrl(opts.targetUrl); // 各ロールの生コンテキストをトップへ(Set-Cookie 追従)
            const snap = await rs.driver.snapshot();
            if (sessionLooksDead(snap) && opts.promptOperator) {
              opts.onText?.(`🔴 role ${roleLabel(role, opts.roleDescriptions)} session appears to have expired (bounced back to the login page)`);
              await opts.promptOperator(`▶ Please log in again in the browser window for role ${roleLabel(role, opts.roleDescriptions)}. Press Enter when done…`);
            }
            const fresh = await rs.driver.sessionCookieHeader();
            if (fresh) {
              rs.cookie = fresh;
              if (role === session.currentRole) session.currentCookie = fresh; // アクティブロールは http 経路も更新
            }
          } catch (e) {
            opts.onText?.(`⚠ keepalive '${role}' failed: ${String(e).slice(0, 100)}`);
          }
        }
        opts.store.appendEvent(opts.assessmentId, {
          type: "note",
          payload: { message: `🫀 keepalive (attended): re-synced ${roleSessions.size} role(s) (keep session alive)` },
        });
      };
      const keepSessionWarm = async (): Promise<void> => {
        if (keepAliveMs <= 0) return;
        if (Date.now() - lastTouch < keepAliveMs) return;
        if (opts.attended) {
          await keepAttendedWarm();
          lastTouch = Date.now();
          return;
        }
        if (!session.currentCookie) return;
        try {
          await driver.gotoUrl(opts.targetUrl); // browser 経路でトップへ(Set-Cookie ローテーションに追従)
          const fresh = await driver.sessionCookieHeader(); // 生 HTTP 経路の cookie も再同期
          if (fresh) session.currentCookie = fresh;
          opts.store.appendEvent(opts.assessmentId, {
            type: "note",
            payload: { message: "🫀 keepalive: navigate to top + re-sync cookies (keep session alive)" },
          });
        } catch (e) {
          opts.onText?.(`⚠ keepalive failed: ${String(e).slice(0, 120)}`);
        }
        lastTouch = Date.now();
      };

      // 1 画面を診断する(primary パスとドレインの両方から呼ぶ共通本体)。"break" で外側ループを止める。
      const diagnoseOne = async (sc: Screen): Promise<"continue" | "break"> => {
        await keepSessionWarm();
        session.currentScreenId = sc.screenId;
        session.screenDone = false;
        session.screenVerdict = null;
        session.screenProbes = 0; // カバレッジ・ゲートの裏取り用に画面ごとリセット
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, "scanning");
        turns += await runStage({
          system: DIAGNOSE_PROMPT,
          goal: `Diagnose screen ${sc.screenId} (${sc.urlTemplate}). Call get_screen for its detail and plan, test that plan with evidence discipline, then screen_done.`,
          allowed: STAGE_TOOLS.diagnose,
          maxTurns: perScreen,
          model: screenIsHighValue(sc) ? deepModel : fastModel, // 高価値画面だけ deep(opus)
          shouldStop: () => session.screenDone || session.done,
        });
        // トークン/利用上限の枯渇で中断した場合: この画面は **未診断のまま** queued に戻し(clean にしない)、
        // 一時停止して抜ける。resume すれば queued の画面(この画面と未着手の残り)から再開できる。
        if (session.paused) {
          opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, "queued");
          return "break";
        }
        // 台帳は **実際に記録された finding の確度** で terminal を決める(confirmed→finding / suspected→suspected /
        //   無し→clean)。screenVerdict は record_finding が維持する権威値(upgrade-only、モデルの screen_done 自己申告では上書きしない)。
        const status = session.screenVerdict === "finding" ? "finding" : session.screenVerdict === "suspected" ? "suspected" : "clean";
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, status);

        // ── 認証壁サーキットブレーカ ── 全プローブが 401 で何も通らない(2xx ゼロ・finding ゼロ)なら、
        //    これ以上画面を回しても無駄。止めて operator に認証設定(httpBasic/creds/cookie)を促す。
        if (isAuthWalled(session)) {
          const msg = `🛑 auth wall: ${session.httpAuthWall}/${session.httpProbes} probes returned 401 and 0 got through — stopping. Set auth (httpBasic / credentials / cookie) and resume.`;
          opts.onText?.(msg);
          opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: msg } });
          opts.store.upsertHandoff(opts.assessmentId, {
            id: "ho-authwall",
            reason: "auth",
            url: opts.targetUrl,
            message: `Diagnosis is fully behind an auth wall (${session.httpAuthWall}/${session.httpProbes} probes 401, none authenticated). Configure site auth (httpBasic / credentials / cookie) and resume.`,
            status: "pending",
            createdAt: new Date().toISOString(),
            resolvedAt: null,
          });
          session.done = true;
          session.doneSummary = msg;
          return "break";
        }
        return "continue";
      };

      const handled = new Set<string>();
      const maxScan = opts.maxScreens ?? 40;
      // primary パス: 開始時スナップショット(優先度順)を回す。
      for (const sc of screens) {
        if (session.done) break;
        handled.add(sc.screenId);
        if ((await diagnoseOne(sc)) === "break") break;
      }
      // ── ドレイン(再利用可能) ── input sweep / browser_navigate / **後段の scenario・fingerprint** が新規 enroll
      //    した queued 画面を拾い切る。for(screens) は開始時スナップショットなので、その後に台帳へ積まれた画面は
      //    固定リストから漏れ queued のまま残る(= 「scanned 2/5」の正体)。設計意図「台帳の queued を全部 terminal に」
      //    を満たすため、台帳を都度引き直して scannable かつ未処理の画面を maxScan / pause まで潰し切る。段ごとに呼ぶ。
      const drainQueued = async (): Promise<void> => {
        let drained = 0;
        while (!session.done && handled.size < maxScan) {
          const live = opts.store.loadAssessment(opts.assessmentId);
          if (!live) break;
          const scanById = new Map(live.screenScans.map((s) => [s.screenId, s] as const));
          const next = live.screens.find((s) => {
            if (handled.has(s.screenId)) return false;
            const scan = scanById.get(s.screenId);
            return !!scan && isScannable(scan);
          });
          if (!next) break;
          if (drained === 0) opts.onText?.("🔁 draining screens discovered mid-run (input sweep / new routes / scenario navigation) so coverage closes");
          drained += 1;
          handled.add(next.screenId);
          if ((await diagnoseOne(next)) === "break") break;
        }
        if (drained > 0)
          opts.store.appendEvent(opts.assessmentId, {
            type: "note",
            payload: { message: `🔁 drained ${drained} screen(s) discovered during the run (coverage closed: no queued screens stranded)` },
          });
      };
      await drainQueued();
      session.currentScreenId = null;

      // ── STAGE 4: シナリオ(A04 横断ロジック) ── 画面診断の後に1回。real id・auth 確証・実挙動を継承して
      //    多段の workflow 濫用(クーポン/価格・数量改ざん/手順スキップ/権限昇格)を狙う。deep モデル固定。
      //    「取引フローがあるか」の文脈判断は **LLM に委ねる**(脆い語彙正規表現を置かない): get_inventory を
      //    見てモデルが workflow を見つけ、無ければ即 scenario_done で締める。--no-scenario で無効化可。
      if (opts.scenarioPass !== false && !session.done) {
        session.scenarioDone = false;
        // 操作者の重点ヒント(--focus)は **このシナリオ段で実行**する(横断・目的志向なので per-screen 診断ではなくここが適切)。
        const focusClause = opts.focus
          ? `OPERATOR FOCUS (highest priority): ${opts.focus}\nTreat this as the PRIMARY objective of THIS stage. Build and test the scenario(s) it implies FIRST, and do NOT call scenario_done until you have ACTIVELY attempted the focus (log in, probe the relevant endpoints, build probe_scenario control/exploit flows for it). After the focus is covered, also handle any other obvious multi-step workflows. `
          : "";
        // 既定シナリオ(standing objectives): --focus とは別に毎回必ず追う横断目的(資格情報ハント等)。
        const defaultsOn = opts.defaultScenarios !== false && DEFAULT_SCENARIOS.length > 0;
        const defaultClause = defaultsOn
          ? `STANDING OBJECTIVES — pursue every one of these THIS stage, regardless of operator focus or whether any workflow exists:\n${DEFAULT_SCENARIOS.map((s, i) => `  ${i + 1}. [${s.key}] ${s.directive}`).join("\n")}\n\n`
          : "";
        opts.onText?.(
          opts.focus
            ? `🧩 scenario stage: operator focus → ${opts.focus.slice(0, 120)}${defaultsOn ? ` (+ ${DEFAULT_SCENARIOS.length} default scenario(s))` : ""}`
            : `🧩 scenario stage: ${defaultsOn ? `${DEFAULT_SCENARIOS.length} default scenario(s) + ` : ""}surveying the inventory for multi-step (A04) workflows`,
        );
        turns += await runStage({
          system: SCENARIO_PROMPT,
          goal: `${focusClause}${defaultClause}Per-screen diagnosis is done. Call get_inventory, then (a) carry out the STANDING OBJECTIVES above, and (b) decide FROM THE INVENTORY whether this app has any multi-step / state-changing workflow worth abusing (e.g. a cart→checkout→order flow, a coupon/voucher redemption, a fund/points transfer, a multi-step registration/approval, a role/privilege change). For each workflow: log in, walk the legitimate flow once, then build probe_scenario(control, exploit, effectMarker) threading captured ids via {{var}}, and record_finding only on a confirmed verdict. Call scenario_done ONLY after the standing objectives AND every workflow have been covered${defaultsOn ? " (if there are no workflows, still finish the standing objectives before scenario_done)" : opts.focus ? " (if there is none beyond the operator focus, finish the focus first)" : " — if there is no workflow and nothing else to do, call scenario_done"}.`,
          allowed: STAGE_TOOLS.scenario,
          maxTurns: Math.min(maxTurns, 40),
          model: deepModel, // workflow の発見・構築は最難の推論 → deep 固定
          shouldStop: () => session.scenarioDone || session.done,
        });
      }

      // ── STAGE: フィンガープリント(A06 既知脆弱コンポーネント) ── 技術スタックの版を集め、既知 CVE/EOL を当てる。
      //    収集は決定的(fingerprint_scan がヘッダ/Cookie/meta/script から版抽出)、CVE 評価は deep モデルの知識依存。
      //    WebFetch 禁止なので外部 CVE DB は引かず、findings は「version-based・要確認」として正直に記録する。
      if (opts.fingerprintPass !== false && !session.done) {
        session.fingerprintDone = false;
        opts.onText?.(`🔎 fingerprint stage: collecting tech/version banners → ${session.cveLookup ? "online CVE-DB (OSV/NVD)" : "model-knowledge"} CVE assessment (A06)`);
        // CVE DB 照会が off のときは cve_lookup を提示しない(無駄ターン防止)。
        const fpTools = session.cveLookup ? STAGE_TOOLS.fingerprint : STAGE_TOOLS.fingerprint.filter((t) => t !== "cve_lookup");
        const cveClause = session.cveLookup
          ? "After fingerprint_scan, call cve_lookup with the detected components to get AUTHORITATIVE CVE ids from OSV/NVD, and cite those ids. "
          : "Assess each (component, version) against your own CVE/EOL knowledge (online CVE-DB lookup is off). ";
        turns += await runStage({
          system: FINGERPRINT_PROMPT,
          goal: `Per-screen diagnosis and scenarios are done. Inventory the technology stack: call fingerprint_scan on ${opts.targetUrl} (plus a couple of representative in-scope URLs / the main JS bundle). ${cveClause}record_finding(category vulnerable-component) for every component with a real known issue — name the CVE, cite the version evidence (the banner/script that revealed it), set severity by the worst known issue, and state plainly it is version-based unless actively confirmed. Skip patched/current versions. Call fingerprint_done when every detected component has been assessed.`,
          allowed: fpTools,
          maxTurns: Math.min(maxTurns, 25),
          model: deepModel, // 版↔CVE の対応付けは知識集約的 → deep 固定
          shouldStop: () => session.fingerprintDone || session.done,
        });
      }

      // ── 最終ドレイン ── scenario / fingerprint 段が新規 enroll した queued 画面を report 前に診断し切る。
      //    (診断段後のドレインは、後段のナビゲーションが掘った画面を捕捉できないため。例: --focus の TOCTOU 探索が
      //     /admin_panel 等を発見 → queued のまま report に落ちて「scanned 2/5」になっていた。)
      await drainQueued();
      session.currentScreenId = null;
    }

    // ── Burp スキャン・フェーズ ── 診断/シナリオの後、report に落とす前に、**セッション生存中**に実行する。
    //    (従来は runPilot 返却 → driver 破棄 → cmdPilot で Burp、だったので authed 面が取れなかった)。
    //    keepWarm でトップへ navigate + Cookie 再同期し、長いスキャン中もセッションを維持する。
    if (!opts.surveyOnly && !session.done && opts.onBurpScanPhase) {
      opts.store.setPhase(opts.assessmentId, "phase2_burpscan");
      opts.onText?.("🐝 burp scan phase — active scan with the auth session kept warm");
      const keepWarm = async (): Promise<void> => {
        try {
          if (roleSessions) {
            for (const rs of roleSessions.values()) await rs.driver.gotoUrl(opts.targetUrl).catch(() => {});
          } else if (session.currentCookie) {
            await driver.gotoUrl(opts.targetUrl);
            const fresh = await driver.sessionCookieHeader();
            if (fresh) session.currentCookie = fresh;
          }
        } catch {
          /* best-effort keepalive */
        }
      };
      try {
        await opts.onBurpScanPhase({ keepWarm, cookie: session.currentCookie, bearer: session.currentBearer });
      } catch (e) {
        const m = String(e instanceof Error ? e.message : e).slice(0, 160);
        opts.onText?.(`⚠ burp scan phase error: ${m}`);
        opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ burp scan phase error: ${m}` } });
      }
    }

    // survey-only は phase1_recon のまま(全 screen queued=未診断)→ 後で resume できる。
    if (session.paused) {
      // トークン枯渇で一時停止 = まだ未完。phase を report に落とさず(診断フェーズのまま)残し、
      // queued 画面を resume で続けられるようにする。WebUI は control_changed で「⏸ paused」を表示。
      opts.store.appendEvent(opts.assessmentId, {
        type: "note",
        payload: { message: `⏸ run paused (token/usage limit) — ${session.inv.screens().length} screens mapped; resume to finish diagnosis` },
      });
    } else if (!opts.surveyOnly) {
      opts.store.setPhase(opts.assessmentId, "report");
    } else {
      // survey-only が(クラッシュせず)正常終了 = 調査は完了扱い。resume が recon ではなく診断へ進めるよう印を残す。
      opts.store.appendEvent(opts.assessmentId, {
        type: "note",
        payload: { message: `🗺  SURVEY done (survey-only): ${session.inv.screens().length} screens` },
      });
    }
  } finally {
    liveControl?.close();
    if (roleSessions) {
      // attended は各ロールのコンテキストを閉じる(primary は roleSessions に含まれるので二重 close しない)。
      for (const rs of roleSessions.values()) await rs.driver.close().catch(() => {});
    } else {
      await driver.close();
    }
  }

  const summary = opts.surveyOnly
    ? `survey only: ${session.inv.screens().length} screen(s) mapped (not diagnosed; resume to diagnose).`
    : session.doneSummary ||
      `${session.findings.length} finding(s) across ${session.inv.screens().length} screen(s).`;
  return { findings: session.findings, summary, turns, tokensUsed: runTokens, costUsd };
}
