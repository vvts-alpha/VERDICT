// Claude 主導の 3 ステージ・オーケストレータ。
//
// 一度に全部投げると AI は省略するので、調査 → 方法論 → 診断 に分節して query() を分けて回す。
// 各ステージは allowedTools でツールを絞り、phase を進める。診断は screens を 1 枚ずつバウンドした
// 文脈で回す(= カバレッジ台帳の queued を全部 terminal にする)ので、画面の取りこぼしが構造的に出ない。

import { createSdkMcpServer, query } from "@anthropic-ai/claude-agent-sdk";
import type { AssessmentStore, Screen, ScopePolicy } from "@veritas/core";
import { isInScope } from "@veritas/core";
import type { LoginCreds } from "@veritas/crawler";
import { InventoryBuilder, PlaywrightDriver } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { buildTools, STAGE_TOOLS, dedupKey } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { DIAGNOSE_PROMPT, METHODOLOGY_PROMPT, SURVEY_PROMPT } from "./system.js";

export interface RunPilotOptions {
  store: AssessmentStore;
  assessmentId: string;
  targetUrl: string;
  scope: ScopePolicy;
  profileDir: string;
  artifactsDir: string;
  roleCreds: Map<string, LoginCreds>;
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
  onText?: (text: string) => void;
  onTool?: (name: string, input: unknown) => void;
}

export interface PilotResult {
  findings: PilotSession["findings"];
  summary: string;
  turns: number;
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

export async function runPilot(opts: RunPilotOptions): Promise<PilotResult> {
  const driver = await PlaywrightDriver.launch({
    userDataDir: opts.profileDir,
    headless: opts.headless ?? true,
    ...(opts.browserPath ? { executablePath: opts.browserPath } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
  });
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
    loginLlm: new ClaudeCliClient({ defaultModel: fastModel ?? "claude-sonnet-4-6" }),
    currentCookie: "",
    currentRole: "",
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
  };

  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: buildTools(session) });
  const rolesLine = [...opts.roleCreds.keys()].join(", ") || "none";
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
      payload: { message: `↺ resume: ${prev.screens.length} screens / ${prev.findings.length} findings 引継ぎ、残り未診断画面を診断` },
    });
  }

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
          for (const block of msg.message.content) {
            if (block.type === "text" && block.text.trim()) {
              turns += 1;
              const t = block.text.trim();
              opts.onText?.(t);
              opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `🤖 ${t.slice(0, 400)}` } });
            } else if (block.type === "tool_use") {
              opts.onTool?.(block.name, block.input);
            }
          }
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
    return turns;
  };

  let turns = 0;
  try {
    if (!opts.resume) {
      // ── STAGE 1: 調査(写像のみ) ──
      opts.store.setPhase(opts.assessmentId, "phase1_recon");
      turns += await runStage({
        system: SURVEY_PROMPT,
        goal: `Map the entire in-scope surface of ${opts.targetUrl}. In-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Start at the target, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.`,
        allowed: STAGE_TOOLS.survey,
        maxTurns,
        model: fastModel, // 調査は機械的 → fast
        shouldStop: () => session.surveyDone || session.done,
      });

      // ── STAGE 2: 方法論(全画面の攻撃計画) ── ※ survey-only ならスキップ
      if (!opts.surveyOnly && !session.done) {
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
    }

    // ── STAGE 3: 診断(1 画面ずつ。台帳の queued を潰し切る) ── ※ survey-only ならスキップ
    if (!opts.surveyOnly && !session.done) {
      opts.store.setPhase(opts.assessmentId, "phase2_scan");
      const all = session.inv.screens().slice(0, opts.maxScreens ?? 40);
      // resume 時は terminal(clean/finding/excluded)を飛ばし、未診断だけ回す。
      const TERMINAL = new Set(["clean", "finding", "excluded"]);
      const screens = resumeStatus
        ? all.filter((sc) => !TERMINAL.has(resumeStatus.get(sc.screenId) ?? "queued"))
        : all;
      // 複数エンドポイントの画面は IDOR 確定までに >25 turn 要る。25 だと記録直前で頭打ちしていた。
      const perScreen = Math.min(maxTurns, 40);
      for (const sc of screens) {
        if (session.done) break;
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
    if (!opts.surveyOnly) opts.store.setPhase(opts.assessmentId, "report");
  } finally {
    await driver.close();
  }

  const summary = opts.surveyOnly
    ? `survey only: ${session.inv.screens().length} screen(s) mapped (not diagnosed; resume to diagnose).`
    : session.doneSummary ||
      `${session.findings.length} finding(s) across ${session.inv.screens().length} screen(s).`;
  return { findings: session.findings, summary, turns };
}
