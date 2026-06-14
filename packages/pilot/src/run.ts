// Claude 主導の 3 ステージ・オーケストレータ。
//
// 一度に全部投げると AI は省略するので、調査 → 方法論 → 診断 に分節して query() を分けて回す。
// 各ステージは allowedTools でツールを絞り、phase を進める。診断は screens を 1 枚ずつバウンドした
// 文脈で回す(= カバレッジ台帳の queued を全部 terminal にする)ので、画面の取りこぼしが構造的に出ない。

import { createSdkMcpServer, query } from "@anthropic-ai/claude-agent-sdk";
import type { AssessmentStore, Screen, ScopePolicy } from "@veritas/core";
import { isInScope, recordTokens } from "@veritas/core";
import type { LoginCreds } from "@veritas/crawler";
import { InventoryBuilder, PlaywrightDriver } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { join } from "node:path";
import { buildTools, STAGE_TOOLS, dedupKey, loadCookieFile, sessionLooksDead } from "./tools.js";
import type { PilotSession, RoleSession } from "./tools.js";
import { DIAGNOSE_PROMPT, METHODOLOGY_PROMPT, SURVEY_PROMPT } from "./system.js";

export interface RunPilotOptions {
  store: AssessmentStore;
  assessmentId: string;
  targetUrl: string;
  scope: ScopePolicy;
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
  maxTurns?: number;
  rateMs?: number;
  headless?: boolean;
  browserPath?: string;
  noSandbox?: boolean;
  /** 診断する画面数の上限(既定 40)。 */
  maxScreens?: number;
  /** 既存 run の再開: survey/methodology をスキップし、未診断(非 terminal)画面だけ診断する。 */
  resume?: boolean;
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
   *  CLI が readline で供給(pilot パッケージは TTY を仮定しない)。attended では必須。 */
  promptOperator?: (message: string) => Promise<void>;
  onText?: (text: string) => void;
  onTool?: (name: string, input: unknown) => void;
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

const DISALLOWED = ["Bash", "Read", "Write", "Edit", "NotebookEdit", "WebFetch", "WebSearch", "Glob", "Grep"];

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
  return d ? `「${role}」(${d})` : `「${role}」`;
}

export async function runPilot(opts: RunPilotOptions): Promise<PilotResult> {
  const launchBase = {
    headless: opts.headless ?? true,
    // x-umbra-hands マーカーは driver 側で「同一オリジンのみ」に付く(クロスオリジンは付けない=第三者を壊さない)。
    // スコープは別概念で、別ドメイン/API を含めて広げてよい(診断は http 経路で in-scope なら何でも叩ける)。
    ...(opts.browserPath ? { executablePath: opts.browserPath } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
  };

  // ── attended: ロールごとに headed 永続コンテキストを 1 つ起動し、人手でログインさせる ──
  //    生きたセッションをロール別に保持し、診断は login() で driver/cookie を swap して使う。
  let driver: PlaywrightDriver;
  let roleSessions: Map<string, RoleSession> | undefined;
  let primaryRole = "";
  let primaryCookie = "";
  if (opts.attended) {
    if (!opts.promptOperator) throw new Error("attended mode requires promptOperator (Enter 確認のコールバック)");
    // 窓を開くロール: 明示の attendedRoles を最優先(純手動ロールも含む)。無ければ creds/cookie のキーから。
    const roles = [
      ...new Set([...(opts.attendedRoles ?? []), ...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])]),
    ];
    if (roles.length === 0) roles.push("primary"); // ロール未設定でも単一の手動セッションは張れる
    const baseDir = opts.attendedProfilesDir ?? join(opts.profileDir, "..", "profiles");
    roleSessions = new Map();
    opts.onText?.(`👤 attended: ${roles.length} ロールの headed セッションを起動します（手動ログイン）`);
    for (const role of roles) {
      const d = await PlaywrightDriver.launch({ ...launchBase, userDataDir: join(baseDir, role), headless: false });
      const cookieFile = opts.roleCookieFiles?.get(role);
      if (cookieFile) {
        // Cookie ファイルのロールは手動ログイン不要 — 注入だけ。
        try {
          const { browserCookies } = loadCookieFile(cookieFile, opts.targetUrl);
          await d.clearSession();
          await d.addCookies(browserCookies);
          await d.gotoUrl(opts.targetUrl);
          opts.onText?.(`🍪 ロール${roleLabel(role, opts.roleDescriptions)}: ${browserCookies.length} 件の事前 Cookie を注入（手動ログイン不要）`);
        } catch (e) {
          opts.onText?.(`⚠ role '${role}' cookie file error: ${String(e).slice(0, 120)}`);
        }
      } else {
        await d.gotoUrl(opts.loginUrl ?? opts.targetUrl);
        await opts.promptOperator(`▶ ロール${roleLabel(role, opts.roleDescriptions)}のブラウザ窓で手動ログインしてください（CAPTCHA/MFA も突破）。完了したら Enter…`);
      }
      const cookie = await d.sessionCookieHeader();
      roleSessions.set(role, { driver: d, cookie });
      opts.onText?.(`✅ ロール${roleLabel(role, opts.roleDescriptions)} セッション確立（cookie ${cookie ? "あり" : "なし"}）`);
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
    headers: { "x-umbra-hands": "assessment" },
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
    currentRole: primaryRole,
    findings: [],
    findCounter: 0,
    findingsByKey: new Map(),
    accessVerdicts: new Map(),
    recordCalls: 0,
    done: false,
    doneSummary: "",
    model: fastModel, // login ツール(smartLogin)は機械的 → fast モデル
    inv: new InventoryBuilder(),
    visited: new Set(),
    frontier: new Set(),
    plans: new Map(),
    currentScreenId: null,
    screenVerdict: null,
    surveyDone: false,
    methodologyDone: false,
    screenDone: false,
    ...(roleSessions ? { roleSessions } : {}),
  };

  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: buildTools(session) });
  const rolesLine =
    [...new Set([...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])])]
      .map((r) => {
        const d = opts.roleDescriptions?.get(r);
        return d ? `${r} (${d})` : r;
      })
      .join(", ") || "none";
  const maxTurns = opts.maxTurns ?? 60;

  // ── resume: 既存 run から再シード(survey/methodology はスキップ、未診断画面だけ診断) ──
  const prev = opts.resume ? opts.store.loadAssessment(opts.assessmentId) : null;
  const resumeStatus = prev ? new Map(prev.screenScans.map((s) => [s.screenId, s.status] as const)) : null;
  if (prev) {
    session.inv.seed(prev.screens); // screenId 採番 + dedup を継続
    session.currentCookie = await driver.sessionCookieHeader(); // run の認証セッション(browser-profile)を再利用
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
      payload: { message: `↺ resume: ${prev.screens.length} screens / ${prev.findings.length} findings 引継ぎ` },
    });
  }

  // トークン使用量: 各 query() の result からトークンを拾い、run の budget(累計)に貯めて永続化。
  let budget = (prev ?? opts.store.loadAssessment(opts.assessmentId))?.budget ?? null;
  let runTokens = 0; // この run の増分(サマリ表示用)
  let costUsd = 0;

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
        ...(p.model ? { model: p.model } : {}),
        systemPrompt: { type: "preset", preset: "claude_code", append: p.system },
        maxTurns: p.maxTurns,
      },
    });
    try {
      for await (const msg of q) {
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
          const r = msg as unknown as { usage?: Record<string, number>; total_cost_usd?: number };
          sawResult = true;
          resultTokens = tally(r.usage);
          costUsd += r.total_cost_usd ?? 0;
        }
        if (p.shouldStop()) break;
      }
    } catch (err) {
      // maxTurns 到達や SDK エラーでステージが落ちても run 全体は止めない(best-effort で次の画面/ステージへ)。
      // この時点で発火済みのツール(record_finding 等)は既に store に反映されているので finding は失われない。
      const m = String(err instanceof Error ? err.message : err).slice(0, 160);
      opts.onText?.(`⚠ stage ended early: ${m}`);
      opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ stage ended early: ${m}` } });
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
    // resume 時に survey/methodology が前回どこまで進んだかを events から判定する。
    // ※ survey-only も「完了」だが phase は phase1_recon のままなので phase では中断と区別できない。
    //   survey_done が出す "SURVEY done" マーカーと、methodology の "📋 PLAN" イベントで判定する。
    const { surveyDone: surveyDonePrev, methodologyDone: methodologyDonePrev } = resumeStageState(prev);
    const doSurvey = !opts.resume || !surveyDonePrev; // resume でも survey 未完なら調査から
    const doMethodology = !opts.surveyOnly && (!surveyDonePrev || !methodologyDonePrev);

    if (doSurvey) {
      // ── STAGE 1: 調査(写像のみ) ── resume で survey 未完なら既存 screens を seed したまま継続。
      if (opts.resume) opts.onText?.("↻ survey が未完だったので調査(recon)から再開します");
      opts.store.setPhase(opts.assessmentId, "phase1_recon");
      turns += await runStage({
        system: SURVEY_PROMPT,
        goal: `Map the entire in-scope surface of ${opts.targetUrl}. In-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Start at the target, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.`,
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
      const TERMINAL = new Set(["clean", "finding", "excluded"]);
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
              opts.onText?.(`🔴 ロール${roleLabel(role, opts.roleDescriptions)} のセッションが切れた様子（ログイン画面に戻されました）`);
              await opts.promptOperator(`▶ ロール${roleLabel(role, opts.roleDescriptions)}のブラウザ窓で再ログインしてください。完了したら Enter…`);
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
          payload: { message: `🫀 keepalive(attended): ${roleSessions.size} ロールを再同期（セッション維持）` },
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
            payload: { message: "🫀 keepalive: トップへ navigate + cookie 再同期(セッション維持)" },
          });
        } catch (e) {
          opts.onText?.(`⚠ keepalive failed: ${String(e).slice(0, 120)}`);
        }
        lastTouch = Date.now();
      };

      for (const sc of screens) {
        if (session.done) break;
        await keepSessionWarm();
        session.currentScreenId = sc.screenId;
        session.screenDone = false;
        session.screenVerdict = null;
        const recordsBefore = session.recordCalls;
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, "scanning");
        turns += await runStage({
          system: DIAGNOSE_PROMPT,
          goal: `Diagnose screen ${sc.screenId} (${sc.urlTemplate}). Call get_screen for its detail and plan, test that plan with evidence discipline, then screen_done.`,
          allowed: STAGE_TOOLS.diagnose,
          maxTurns: perScreen,
          model: screenIsHighValue(sc) ? deepModel : fastModel, // 高価値画面だけ deep(opus)
          shouldStop: () => session.screenDone || session.done,
        });
        // 台帳は実際に finding を記録(新規 or マージ)できたかで terminal を決める。
        const found = session.recordCalls > recordsBefore;
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, found ? "finding" : "clean");
      }
      session.currentScreenId = null;
    }

    // survey-only は phase1_recon のまま(全 screen queued=未診断)→ 後で resume できる。
    if (!opts.surveyOnly) {
      opts.store.setPhase(opts.assessmentId, "report");
    } else {
      // survey-only が(クラッシュせず)正常終了 = 調査は完了扱い。resume が recon ではなく診断へ進めるよう印を残す。
      opts.store.appendEvent(opts.assessmentId, {
        type: "note",
        payload: { message: `🗺  SURVEY done (survey-only): ${session.inv.screens().length} screens` },
      });
    }
  } finally {
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
