#!/usr/bin/env node
// @veritas/cli — DESIGN §11 / §12 M0。
// アセスメントを生成し runs/<id>/state.sqlite を書く(+ status / list で観測)。
// クロール/スキャン本体は後続マイルストン。ここは状態ストアの薄いフロント。

import { parseArgs } from "node:util";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import {
  AssessmentStore,
  buildReport,
  coverage,
  deriveScopeFromSingleUrl,
  evaluateStop,
  isInScope,
  newAssessmentId,
  type AssessmentState,
  type ScopePolicy,
  type TargetInput,
} from "@veritas/core";
import { PlaywrightDriver, buildInventory, crawl, exploreScreen, labelInventory, normalizePath, smartLogin, writeScreenInventory } from "@veritas/crawler";
import type { LoginCreds } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient, SECURITY_HEADERS, auditHeaders, coarseCategory, parseBurpReport, burpSeverity, scanInventory, startBurpScan, getBurpScan } from "@veritas/scanner";
import type { BurpIssue } from "@veritas/scanner";
import { assessLogicInventory, assessScreenLogic, authDiffScreen } from "@veritas/agent";
import type { RoleContext } from "@veritas/agent";
import { runPilot } from "@veritas/pilot";
import { startServer } from "@veritas/server";

const RUNS_DIR_DEFAULT = "runs";

const USAGE = `veritas <command> [options]

commands:
  manifest [--out <file.json>] [--force]   (別名: init)
            対話型 scope-manifest ジェネレータ: 質問に答えると pilot/assess が読む JSON を生成
            (target / in・out-of-scope hosts・path / rate / crawl / model / 認証ロール。password はエコー伏字)
  pilot   --manifest <file.json> | --url <url> [--model <m>] [--fast-model <m>] [--max-turns <n>] [--rate <ms>] [--headed] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            ★Claude 主導: Claude がツール(browser/http/login/record)を操縦して自律的に探索・検証・記録
            manifest の auth.roles を login(role) ツールで使う。決定論パイプラインより柔軟(従量API無し/Maxサブスク)
            --fast-model 指定でモデル使い分け: survey/methodology/login と低価値画面を fast、高価値画面の診断だけ --model(例 --model opus --fast-model sonnet)
  pilot --survey-only --manifest <file.json> | --url <url> [...]
            調査のみ: 画面マップ+スクショ+API 抽出だけ実行し、診断/finding はしない(安い recon。後で --resume で診断)
            ※ 既定では survey 中にモデルが低価値な CMS コンテンツ木などを ignore_paths で動的に間引く(frontier 爆発の抑制)。
              [--exhaustive] を付けると間引きを無効化し全画面を抽出(=画面調査の全量モード)。
  pilot --resume --id <id> [--manifest <file.json>] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            既存 run の続きから: survey/methodology を飛ばし、未診断(queued)画面だけ診断(落ちた run の仕上げ)
  pilot --attended[ a,b,c] (--manifest <file.json> | --url <url>) [--login-url <u>] [--keepalive-min <n>] [...]
            手動マルチセッション認証(headed 必須): ロールごとに永続コンテキストを開き、人手でログイン(CAPTCHA/MFA/Arkose 突破)
            → Enter 確認 → 生きたセッションで調査・診断。診断はロール別ライブ Cookie を使い、合間にセッションを維持(失効時は再ログイン要求)
            ロールは --attended admin,userA,userB でCLI直指定も可(manifest 不要・上書き)。単体 --attended は manifest の auth.roles を使用
            ※ Burp 連携(基本は env、引数で上書き): [--burp-proxy [url]] 全通信を Burp 経由(値なしなら env BURP_PROXY)。
              [--burp-scan [--burp-api url]] 診断後に同じ run へ Burp 能動スキャンも実施→結果マージ(接続は env BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL)。どちらも既定オフ。
  burp-scan --id <id> [--burp-api <url>] [--api-key <key>] [--config "<named config>"]... [--resource-pool <name>] [--manifest <m.json>] [--max-min <n>] [--poll <sec>] [--out <dir>]
            Burp Pro の REST API で能動スキャンを起動→完了までポーリング→issue を取り込む(XML export 不要)。接続は env(BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL)→引数で上書き。
            対象URL = その run の AI がマップした in-scope 画面(=対象は AI が決める)。検査内容/速度 = Burp の named config。
            --config は複数指定可(クロール速度 + 監査内容を重ねる)。スキャン速度は Burp のクロール戦略プリセットで決まる:
              例) --config "Crawl strategy - fastest" --config "Audit checks - critical issues only"  (速い)
                  --config "Crawl strategy - most complete" --config "Audit checks - all except time-based detection methods"  (網羅・遅い)
              無指定なら "Audit checks - all except time-based detection methods"。
            速度/throttle = Burp の Resource pool(最大同時リクエスト数・リクエスト間ディレイ)。REST は ms を数値で持てず名前参照のみ。
              既定は "250ms" プールを使う(Burp で要作成: Settings → Resource pool → Add → 同時1/Delay 250ms)。
              無ければ Burp 既定プールで自動続行(作り方を案内)。--resource-pool <name> で上書き、--resource-pool "" で Burp 既定。
            --manifest の資格情報を渡すと認証スキャン。API キーは --api-key か環境変数 BURP_API_KEY。Burp Pro 側で REST API 有効化が必要。
  burp-import --id <id> --report <burp.xml> [--out <dir>]
            Burp Pro の XML レポートを取り込み、既存 finding と重複しない net-new だけ追加(連携はフラグ式・任意)
  assess  --manifest <file.json> | --url <url> [--login-url <u>] [--login-wait <s>] [--no-label] [--no-logic] [--no-explore] [--browser-path <bin>] [--no-sandbox] [--model <m>] [--out <dir>]
            一括起動(決定論パイプライン): crawl → label → scan → logic → report を 1 コマンドで実行
            --login-url 指定で headed ブラウザを開きログイン待ち(パスワードは人手入力、注入しない)
  run     --url <url> [--follow] [--max-depth <n>] [--out <dir>]
            認可済みターゲットの空アセスメントを生成し runs/<id>/state.sqlite を書く
  crawl   --url <url> | --id <id> [--follow] [--max-depth <n>] [--headed] [--login-url <u>] [--login-wait <s>] [--out <dir>]
            Phase1: Playwright でクロール+傍受 → screen_inventory.json + カバレッジ台帳
  label   --id <id> [--model <model>] [--out <dir>]
            Phase1 ラベリング: 各画面を LLM で分類(claude サブスク認証、従量 API なし)
  scan    --id <id> [--rate <ms>] [--out <dir>]
            Phase2: 汎用 validator + 証拠規律(neg+2replay)。confirmed を findings に
  logic   --id <id> [--screen <sid>] [--model <model>] [--rate <ms>] [--out <dir>]
            Phase2 ビジネスロジック: 仮説生成(LLM)→ IDOR 等を証拠規律で検証
  serve   [--port <n>] [--host <h>] [--out <dir>] [--web-root <dir>] [--no-web]
            観測 WebUI + 状態API/WS を起動(既定 127.0.0.1:4317。LAN 公開は --host 0.0.0.0)
  report  --id <id> [--out <dir>]
            findings から report.md を生成(重大度順 + 再現 + 証拠 + スコープ根拠)
  shots   --id <id> [--headed] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            既存 run の各画面を撮り直し WebUI 用スクショを backfill(run の認証済プロファイル再利用・ナビゲートのみ)
  header-audit --id <id> [--headers csp,hsts,xfo,xcto,refpol,permpol] [--rate <ms>] [--out <dir>]
            Info系: 各画面のレスポンスヘッダを監査し欠落ヘッダ毎に finding(deterministic/トグル=走らせる走らせない)
  status  --id <assessment-id> [--out <dir>]
            フェーズ・カバレッジ・findings を表示
  list    [--out <dir>]
            runs/ 配下のアセスメント一覧

注意: スコープ外は禁止。--url は同一オリジン + 配下が既定スコープ(DESIGN §4.2 / §5)。
`;

function fail(msg: string): never {
  console.error(`error: ${msg}\n`);
  console.error(USAGE);
  process.exit(1);
}

function describeTarget(t: TargetInput): string {
  return t.kind === "single_url"
    ? `single_url ${t.url} (depth ${t.maxDepth}, follow=${t.followLinks})`
    : `scope_manifest ${t.path}`;
}

function dbPathFor(runsDir: string, id: string): string {
  return join(runsDir, id, "state.sqlite");
}

function cmdRun(args: string[]): void {
  const { values } = parseArgs({
    args,
    options: {
      url: { type: "string" },
      scope: { type: "string" },
      follow: { type: "boolean" },
      "max-depth": { type: "string" },
      out: { type: "string" },
    },
  });

  if (values.scope) {
    fail("--scope (scope_manifest) parsing is not implemented yet (M-future); use --url for now");
  }
  if (!values.url) fail("run requires --url <url>");

  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const maxDepth = values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3;
  if (!Number.isFinite(maxDepth) || maxDepth < 0) fail("--max-depth must be a non-negative integer");

  const id = newAssessmentId();
  mkdirSync(join(runsDir, id), { recursive: true });
  const dbPath = dbPathFor(runsDir, id);

  const target: TargetInput = {
    kind: "single_url",
    url: values.url,
    followLinks: values.follow ?? false,
    maxDepth,
  };

  const store = AssessmentStore.open(dbPath);
  const state = store.createAssessment({ id, target, scope: deriveScopeFromSingleUrl(values.url) });
  store.close();

  console.log(`created assessment ${state.id}`);
  console.log(`  phase:  ${state.phase}`);
  console.log(`  target: ${describeTarget(state.target)}`);
  console.log(
    `  scope:  hosts=${state.scope.inScopeHosts.join(",")} rate=${state.scope.rate.requestsPerMinute}/min`,
  );
  console.log(`  state:  ${dbPath}`);
}

function cmdStatus(args: string[]): void {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" } },
  });
  if (!values.id) fail("status requires --id <assessment-id>");

  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found in ${dbPath}`);

  const cov = coverage(state);
  const pending = state.handoffs.filter((h) => h.status === "pending").length;
  console.log(`assessment ${state.id}`);
  console.log(`  phase:    ${state.phase}`);
  console.log(`  target:   ${describeTarget(state.target)}`);
  console.log(
    `  coverage: ${cov.terminal}/${cov.total} terminal, ${cov.remaining} remaining, ${cov.scannable} scannable${cov.complete ? " (complete)" : ""}`,
  );
  console.log(`  findings: ${state.findings.length}`);
  console.log(`  tokens:   ${state.budget.tokensUsed.toLocaleString()} / ${state.budget.limits.maxTokens.toLocaleString()}`);
  console.log(`  handoffs: ${pending} pending`);
  console.log(`  events:   ${state.events.length}`);
  const stop = evaluateStop(state);
  console.log(`  stop:     ${stop.stop ? `${stop.reason} (${stop.detail})` : "continue"}`);
}

function cmdReport(args: string[]): void {
  const { values } = parseArgs({ args, options: { id: { type: "string" }, out: { type: "string" } } });
  if (!values.id) fail("report requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found`);

  const path = join(runsDir, values.id, "report.md");
  writeFileSync(path, buildReport(state));
  console.log(`report written: ${path}`);
  console.log(`  ${state.findings.length} finding(s), phase ${state.phase}`);
}

function cmdList(args: string[]): void {
  const { values } = parseArgs({ args, options: { out: { type: "string" } } });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  if (!existsSync(runsDir)) {
    console.log("(no runs yet)");
    return;
  }
  const ids = readdirSync(runsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((id) => existsSync(dbPathFor(runsDir, id)));
  if (ids.length === 0) {
    console.log("(no runs yet)");
    return;
  }
  for (const id of ids) {
    const store = AssessmentStore.open(dbPathFor(runsDir, id));
    const state = store.loadAssessment(id);
    store.close();
    if (!state) continue;
    const cov = coverage(state);
    const tk = state.budget.tokensUsed;
    const tkStr = tk >= 1000 ? `${(tk / 1000).toFixed(1)}k` : `${tk}`;
    console.log(
      `${state.id}  ${state.phase.padEnd(13)} screens=${state.screens.length} cov=${cov.terminal}/${cov.total} findings=${state.findings.length} tok=${tkStr}  ${describeTarget(state.target)}`,
    );
  }
}

async function cmdCrawl(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      url: { type: "string" },
      id: { type: "string" },
      out: { type: "string" },
      "max-depth": { type: "string" },
      follow: { type: "boolean" },
      headed: { type: "boolean" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      "login-url": { type: "string" },
      "login-wait": { type: "string" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;

  // 対象アセスメントを解決(--url で新規作成、--id で既存を使用)
  let id: string;
  if (values.url) {
    id = newAssessmentId();
    mkdirSync(join(runsDir, id), { recursive: true });
    const maxDepth = values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3;
    const seedStore = AssessmentStore.open(dbPathFor(runsDir, id));
    seedStore.createAssessment({
      id,
      target: { kind: "single_url", url: values.url, followLinks: values.follow ?? true, maxDepth },
      scope: deriveScopeFromSingleUrl(values.url),
    });
    seedStore.close();
  } else if (values.id) {
    id = values.id;
    if (!existsSync(dbPathFor(runsDir, id))) fail(`no state.sqlite at ${dbPathFor(runsDir, id)}`);
  } else {
    fail("crawl requires --url <url> (new) or --id <id> (existing)");
  }

  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found`);
  }
  if (state.target.kind !== "single_url") {
    store.close();
    fail("crawl supports single_url targets only (M1)");
  }

  const profileDir = join(runsDir, id, "browser-profile");
  mkdirSync(profileDir, { recursive: true });

  console.log(`crawling ${state.target.url} (depth ${state.target.maxDepth}, follow=${state.target.followLinks})`);
  const loginUrl = values["login-url"];
  const driver = await PlaywrightDriver.launch({
    userDataDir: profileDir,
    headless: !values.headed && !loginUrl,
    executablePath: values["browser-path"] ?? process.env.VERITAS_BROWSER_PATH,
    args: values["no-sandbox"] ? ["--no-sandbox"] : undefined,
  });

  try {
    if (loginUrl) {
      const waitSec = values["login-wait"] ? Number.parseInt(values["login-wait"], 10) : 60;
      console.log(`🔐 ログイン待ち: 開いたブラウザで ${loginUrl} にログインしてください(${waitSec}s)…`);
      await driver.interactiveLogin(loginUrl, waitSec * 1000);
      console.log("   続行(認証状態は browser-profile に保持)");
    }
    const result = await crawl(
      {
        startUrl: state.target.url,
        scope: state.scope,
        followLinks: state.target.followLinks,
        maxDepth: state.target.maxDepth,
      },
      driver,
      {
        store,
        assessmentId: id,
        onScreen: (s, isNew) => {
          if (isNew) {
            const labels = s.labels.length ? ` [${s.labels.join(",")}]` : "";
            console.log(`  + ${s.screenId} ${s.screenType.padEnd(9)} ${s.urlTemplate}  apis=${s.apis.length}${labels}`);
          }
        },
      },
    );
    const invPath = join(runsDir, id, "screen_inventory.json");
    writeScreenInventory(invPath, buildInventory(result.startUrl, result.screens));
    console.log(
      `\ncrawl done: ${result.stats.screens} screens, ${result.stats.apis} apis, visited ${result.stats.visited}, stop=${result.stats.stopReason} (${result.stats.elapsedMs}ms)`,
    );
    console.log(`  inventory: ${invPath}`);
    console.log(`  state:     ${dbPathFor(runsDir, id)}`);
  } finally {
    await driver.close();
    store.close();
  }
}

async function cmdLabel(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, model: { type: "string" } },
  });
  if (!values.id) fail("label requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens to label — run `crawl` first");
  }

  const model = values.model ?? "claude-sonnet-4-6";
  const client = new ClaudeCliClient({ defaultModel: model });
  console.log(`labeling ${state.screens.length} screens with ${model} ...`);
  try {
    const result = await labelInventory(state.screens, client, {
      store,
      assessmentId: values.id,
      model,
      onLabeled: (s, usedFallback) => {
        const mark = usedFallback ? "~" : "✓";
        console.log(`  ${mark} ${s.screenId} ${s.screenType.padEnd(9)} ${s.urlTemplate} [${s.labels.join(",")}]`);
      },
    });
    const startUrl = state.target.kind === "single_url" ? state.target.url : values.id;
    const invPath = join(runsDir, values.id, "screen_inventory.json");
    writeScreenInventory(invPath, buildInventory(startUrl, result.screens));
    console.log(`\nlabeled ${result.labeled}, fallback(rule) ${result.fallback}  →  phase1_label`);
    console.log(`  inventory: ${invPath}`);
  } finally {
    store.close();
  }
}

interface AssessManifest {
  /** 起点(seed)URL。必須 */
  target: string;
  /** 明示スコープ(部分指定可。未指定フィールドは target から導出した既定で補完) */
  scope?: Partial<ScopePolicy>;
  crawl?: { followLinks?: boolean; maxDepth?: number };
  model?: string;
  /** 認証(DESIGN §6.3)。資格情報だけでよい — ログインURL/項目はエージェントが自動発見。
   *  state.sqlite には書かれない。manifest は gitignore。 */
  auth?: {
    note?: string;
    /** 主ログインの資格情報(任意。roles[0] でも可) */
    login?: { username?: string; password: string };
    /** ロール(name=ユーザー名, pass/password=パスワード)。[0]=主ログイン, 全部=auth-diff */
    roles?: Array<{
      name: string;
      /** 権限レベルの自由記述(例: "全権管理者" / "一般ユーザ(読取のみ)")。auth-diff の高/低権限判断に使う。 */
      description?: string;
      desc?: string;
      username?: string;
      pass?: string;
      password?: string;
      /** 事前取得した Cookie ファイルのパス(pass の代わり。自動ログイン不能な壁向け)。 */
      cookieFile?: string;
      cookie_file?: string;
      cookie_file_path?: string;
      headers?: Record<string, string>;
    }>;
  };
}

function manifestPrimaryCreds(m: AssessManifest | null): LoginCreds | null {
  if (m?.auth?.login?.password) return { username: m.auth.login.username ?? "", password: m.auth.login.password };
  for (const role of m?.auth?.roles ?? []) {
    const password = role.password ?? role.pass;
    if (password) return { username: role.username ?? role.name, password };
  }
  return null;
}

function manifestRoleCreds(m: AssessManifest | null): Array<{ name: string; creds: LoginCreds }> {
  const out: Array<{ name: string; creds: LoginCreds }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const password = role.password ?? role.pass;
    if (password) out.push({ name: role.name, creds: { username: role.username ?? role.name, password } });
  }
  return out;
}

/** ロール名 → 権限説明(任意)。auth-diff で高/低権限を見分ける材料としてエージェントに渡す。 */
function manifestRoleDescriptions(m: AssessManifest | null): Array<{ name: string; description: string }> {
  const out: Array<{ name: string; description: string }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const description = (role.description ?? role.desc ?? "").trim();
    if (description) out.push({ name: role.name, description });
  }
  return out;
}

/** ロール名 → 事前取得 Cookie ファイル(pass の代わりに指定可能)。 */
function manifestRoleCookies(m: AssessManifest | null): Array<{ name: string; file: string }> {
  const out: Array<{ name: string; file: string }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const file = role.cookieFile ?? role.cookie_file ?? role.cookie_file_path;
    if (file) out.push({ name: role.name, file });
  }
  return out;
}

function loadManifest(path: string): AssessManifest {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    fail(`cannot read manifest ${path}: ${(e as Error).message}`);
  }
  const m = raw as AssessManifest;
  if (!m || typeof m.target !== "string") fail('manifest must include a string "target" (seed URL)');
  return m;
}

// 一括起動: ① crawl → ②(label)→ ③ scan → ④(logic)→ ⑤ report。manifest か --url で起動。
async function cmdAssess(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      manifest: { type: "string" },
      url: { type: "string" },
      out: { type: "string" },
      model: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
      rate: { type: "string" },
      "max-depth": { type: "string" },
      "no-label": { type: "boolean" },
      "no-logic": { type: "boolean" },
      "no-explore": { type: "boolean" },
      "login-url": { type: "string" },
      "login-wait": { type: "string" },
      headless: { type: "boolean" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const seedUrl = manifest?.target ?? values.url;
  if (!seedUrl) fail("assess requires --manifest <file.json> or --url <url>");

  const scope: ScopePolicy = { ...deriveScopeFromSingleUrl(seedUrl), ...(manifest?.scope ?? {}) };
  const followLinks = manifest?.crawl?.followLinks ?? true;
  const maxDepth = manifest?.crawl?.maxDepth ?? (values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3);
  const model = values.model ?? manifest?.model ?? "claude-sonnet-4-6";
  const rate = values.rate ? Number.parseInt(values.rate, 10) : 250;

  const id = newAssessmentId();
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  store.createAssessment({ id, target: { kind: "single_url", url: seedUrl, followLinks, maxDepth }, scope });

  console.log(`▶ assessment ${id}`);
  console.log(`  target ${seedUrl} | scope hosts=[${scope.inScopeHosts.join(",")}] | rate ${rate}ms`);
  if (manifest?.auth?.roles?.length) {
    console.log(`  auth roles: ${manifest.auth.roles.map((r) => r.name).join(", ")} (auth-diff 用 / state には保存しない)`);
  }

  const screensNow = () => store.loadAssessment(id)?.screens ?? [];
  const claude = new ClaudeCliClient({ defaultModel: model });
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, scope), minDelayMs: rate });
  const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));

  // ① unauth crawl → ② login(資格情報 or 人手)→ ③ post-login crawl →(⑤ role セッション取得)
  const profileDir = join(runsDir, id, "browser-profile");
  mkdirSync(profileDir, { recursive: true });
  const primaryCreds = manifestPrimaryCreds(manifest);
  const roleCredsList = manifestRoleCreds(manifest);
  const interactiveUrl = values["login-url"];
  // 既定 headless(自動ログインはヘッドレスで動く)。--headed / --login-url 明示時のみ headed。
  // creds だけでは headed を強制しない(ヘッドレス VM/CI でも creds 自動ログインが回る)。
  const headed = !values.headless && (values.headed || !!interactiveUrl);
  const waitSec = values["login-wait"] ? Number.parseInt(values["login-wait"], 10) : 60;
  const roleSessions: RoleContext[] = [];
  let primaryCookie = "";

  const driver = await PlaywrightDriver.launch({
    userDataDir: profileDir,
    headless: !headed,
    executablePath: values["browser-path"] ?? process.env.VERITAS_BROWSER_PATH,
    args: values["no-sandbox"] ? ["--no-sandbox"] : undefined,
  });

  // 能動探索フック(完全自動): 各新規画面でブラウザを操作し、発火 API/新 URL を引き出す(§7.2)
  const exploreHook = values["no-explore"]
    ? undefined
    : async (): Promise<{ apis: Awaited<ReturnType<typeof exploreScreen>>["firedApis"]; urls: string[] }> => {
        const r = await exploreScreen(driver, claude, { model });
        return { apis: r.firedApis, urls: r.newUrls };
      };

  try {
    console.log("① crawl unauth (Playwright) …");
    const unauth = await crawl(
      { startUrl: seedUrl, scope, followLinks, maxDepth, authState: "unauth" },
      driver,
      { store, assessmentId: id, ...(exploreHook ? { explore: exploreHook } : {}) },
    );
    console.log(`   ${unauth.stats.screens} screens, ${unauth.stats.apis} apis, ${unauth.stats.handoffs} handoff(s)`);
    const unauthScreens = screensNow();
    const unauthIds = new Set(unauthScreens.map((s) => s.screenId));

    if (primaryCreds || interactiveUrl) {
      const loginScreenUrl = screensNow().find((s) => s.screenType === "auth")?.observedUrls[0];
      let loggedIn = false;
      if (primaryCreds) {
        console.log("② login (資格情報でログイン画面/項目を自動発見) …");
        const r = await smartLogin(driver, claude, primaryCreds, {
          targetUrl: seedUrl,
          ...(loginScreenUrl ? { loginScreenUrl } : {}),
          model,
        });
        if (r.ok) {
          console.log(`   ✓ ${r.reason}`);
          loggedIn = true;
        } else if (r.needsHuman && headed) {
          const u = interactiveUrl ?? r.loginUrl ?? seedUrl;
          console.log(`🔐 ${r.reason} → 人手ログインに切替: ${u}(${waitSec}s)…`);
          await driver.interactiveLogin(u, waitSec * 1000);
          loggedIn = true;
        } else if (r.needsHuman) {
          console.log(`   ${r.reason} — MFA/CAPTCHA は表示環境で --headed を付けて再実行(未認証で続行)`);
        } else {
          console.log(`   自動ログイン不可: ${r.reason}(未認証で続行)`);
        }
      } else if (interactiveUrl) {
        console.log(`🔐 ログイン待ち: ${interactiveUrl}(${waitSec}s)…`);
        await driver.interactiveLogin(interactiveUrl, waitSec * 1000);
        loggedIn = true;
      }
      if (loggedIn) {
        // ログイン後の着地点(例 /dashboard)を起点に再クロール(seed からは届かない認証後画面を辿る)
        const postLoginUrl = driver.currentUrl();
        const authStart = isInScope(postLoginUrl, scope) ? postLoginUrl : seedUrl;
        console.log(`③ crawl post-login (from ${authStart}) …`);
        await crawl(
          { startUrl: authStart, scope, followLinks, maxDepth, authState: "post-login" },
          driver,
          { store, assessmentId: id, seedScreens: unauthScreens, ...(exploreHook ? { explore: exploreHook } : {}) },
        );
        const authOnly = screensNow().filter((s) => !unauthIds.has(s.screenId));
        console.log(`   +${authOnly.length} auth-only screens: ${authOnly.slice(0, 8).map((s) => s.urlTemplate).join(", ")}`);
        if (authOnly.length > 0) {
          store.appendEvent(id, { type: "note", payload: { message: `auth-only screens: ${authOnly.map((s) => s.screenId).join(",")}` } });
        }
        primaryCookie = await driver.sessionCookieHeader(); // 認証後検証(IDOR 等)に使う
      }
    }
    writeScreenInventory(join(runsDir, id, "screen_inventory.json"), buildInventory(seedUrl, screensNow()));

    // ⑤(前半)各 role でログインしてセッション cookie を取得
    if (roleCredsList.length >= 2) {
      console.log("⑤ auth-diff: 各 role でログインしてセッション取得 …");
      for (const rc of roleCredsList) {
        await driver.clearSession();
        const r = await smartLogin(driver, claude, rc.creds, { targetUrl: seedUrl, model });
        if (r.ok) {
          const cookie = await driver.sessionCookieHeader();
          roleSessions.push({ name: rc.name, headers: cookie ? { cookie } : {} });
          console.log(`   ✓ ${rc.name}`);
        } else {
          console.log(`   ✗ ${rc.name}: ${r.reason}`);
        }
      }
    }
  } finally {
    await driver.close();
  }

  // ② label
  if (!values["no-label"]) {
    console.log(`② label (LLM ${model}) …`);
    const lr = await labelInventory(screensNow(), claude, { store, assessmentId: id, model });
    console.log(`   labeled ${lr.labeled}, fallback ${lr.fallback}`);
  }

  // ③ scan
  console.log("③ scan (validators + 証拠規律) …");
  const sr = await scanInventory(screensNow(), http, evidence, { store, assessmentId: id });
  console.log(`   ${sr.confirmed} confirmed`);

  // ④ logic(認証後の画面/API は主ロールのセッションで検証 = IDOR を認証下で叩く)
  if (!values["no-logic"]) {
    console.log("④ logic (business logic) …");
    const logicHttp = primaryCookie
      ? new FetchHttpClient({ allow: (url) => isInScope(url, scope), minDelayMs: rate, headers: { cookie: primaryCookie } })
      : http;
    const lr = await assessLogicInventory(screensNow(), claude, logicHttp, evidence, { store, assessmentId: id }, { model });
    console.log(`   ${lr.hypotheses} hypotheses, ${lr.confirmed} confirmed`);
  }

  // ⑤(後半)auth-diff: role 間で同一 API を比較(HTTP 層、ブラウザ不要)
  if (roleSessions.length >= 2) {
    const high = roleSessions[0];
    const low = roleSessions[1];
    if (high && low) {
      console.log(`⑤ auth-diff (${high.name} vs ${low.name}) …`);
      let confirmed = 0;
      for (const screen of screensNow()) {
        if (!screen.apis.some((a) => a.auth !== "none")) continue;
        const r = await authDiffScreen(screen, http, evidence, high, low);
        if (r.status === "confirmed") {
          confirmed += 1;
          store.upsertFinding(id, {
            id: `adf-${screen.screenId}`,
            screenId: screen.screenId,
            title: `Authorization boundary crossed on ${screen.urlTemplate}`,
            severity: "high",
            source: { kind: "validator", validatorName: "auth_diff" },
            description: r.reason,
            reproSteps: `compared roles '${high.name}' vs '${low.name}' on the screen's authenticated API`,
            evidenceIds: r.evidenceIds,
            scopeBasis: "same origin as a crawled in-scope screen",
          });
        }
      }
      console.log(`   ${confirmed} auth-diff confirmed`);
    }
  }

  // ⑥ report
  const finalState = store.loadAssessment(id);
  if (finalState) writeFileSync(join(runsDir, id, "report.md"), buildReport(finalState));
  store.close();
  console.log(`⑥ report → ${join(runsDir, id, "report.md")}`);
  console.log(`\n✓ done. 観測: serve 済みなら http://127.0.0.1:4317/?id=${id}`);
}

/** `--attended admin,userA,userB` のインライン CSV を切り出す前処理。
 *  `--attended` の直後がフラグでない(=ロール CSV)ときだけ値として拾い、`--attended` 自体は boolean のまま残す。
 *  `--attended=admin,userA` 形 / 単体 `--attended`(manifest 由来) も両立。 */
export function extractAttendedRoles(args: string[]): { args: string[]; roles?: string[] } {
  const out: string[] = [];
  let roles: string[] | undefined;
  const csv = (s: string): string[] => s.split(",").map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "--attended") {
      out.push("--attended");
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        roles = csv(next);
        i++; // CSV 値を消費(positional として残さない)
      }
    } else if (a.startsWith("--attended=")) {
      out.push("--attended");
      roles = csv(a.slice("--attended=".length));
    } else {
      out.push(a);
    }
  }
  return roles ? { args: out, roles } : { args: out };
}

/** `--flag [value]` の任意値フラグを argv から切り出す。`--flag` の次がフラグでなければ値、フラグ/末尾なら bare。
 *  `--flag=value` 形も可。bare(present かつ value 無し)は env 既定にフォールバックさせる用途。 */
export function extractOptValueFlag(args: string[], flag: string): { args: string[]; present: boolean; value?: string } {
  const out: string[] = [];
  let present = false;
  let value: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) {
      present = true;
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        value = next;
        i++;
      }
    } else if (a.startsWith(`${flag}=`)) {
      present = true;
      value = a.slice(flag.length + 1);
    } else {
      out.push(a);
    }
  }
  return value !== undefined ? { args: out, present, value } : { args: out, present };
}

// Claude 主導アセスメント: Claude がツールを操縦して自律的に探索・検証・記録(@veritas/pilot)。
async function cmdPilot(rawArgs: string[]): Promise<void> {
  const a1 = extractAttendedRoles(rawArgs);
  const inlineAttendedRoles = a1.roles;
  // --burp-proxy は任意値フラグ: bare なら env BURP_PROXY、値ありならそれを使う(基本 env、引数で上書き)。
  const bp = extractOptValueFlag(a1.args, "--burp-proxy");
  const { values } = parseArgs({
    args: bp.args,
    options: {
      manifest: { type: "string" },
      url: { type: "string" },
      id: { type: "string" },
      resume: { type: "boolean" },
      "survey-only": { type: "boolean" },
      out: { type: "string" },
      model: { type: "string" },
      "fast-model": { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
      headless: { type: "boolean" },
      attended: { type: "boolean" },
      exhaustive: { type: "boolean" },
      "login-url": { type: "string" },
      rate: { type: "string" },
      "max-turns": { type: "string" },
      "max-screens": { type: "string" },
      "burp-scan": { type: "boolean" },
      "burp-api": { type: "string" },
      "keepalive-min": { type: "string" },
    },
  });
  // --burp-proxy: 指定時のみ有効。アドレスは引数値 → env BURP_PROXY。
  const burpProxy = bp.present ? (bp.value ?? process.env.BURP_PROXY) : undefined;
  if (bp.present && !burpProxy) console.log("⚠ --burp-proxy が指定されましたが値も BURP_PROXY env もありません(プロキシ無効で続行)");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const model = values.model ?? manifest?.model ?? "claude-sonnet-4-6";
  const rate = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const maxTurns = values["max-turns"] ? Number.parseInt(values["max-turns"], 10) : 80;
  const attended = !!values.attended; // 手動マルチセッション認証(必ず headed)
  const headed = attended || (!values.headless && !!values.headed);
  if (attended && values.headless) console.log("⚠ --attended は手動ログインのため headed 必須です(--headless は無視)");
  const browserPath = values["browser-path"] ?? process.env.VERITAS_BROWSER_PATH;
  const resume = !!values.resume;
  const surveyOnly = !!values["survey-only"];

  let id: string;
  let store: AssessmentStore;
  let scope: ScopePolicy;
  let seedUrl: string;

  if (resume) {
    if (!values.id) fail("pilot --resume requires --id <assessment-id>");
    id = values.id;
    const dbPath = dbPathFor(runsDir, id);
    if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
    store = AssessmentStore.open(dbPath);
    const state = store.loadAssessment(id);
    if (!state) {
      store.close();
      fail(`assessment ${id} not found in ${dbPath}`);
    }
    scope = state.scope;
    seedUrl = "url" in state.target ? state.target.url : "";
  } else {
    seedUrl = manifest?.target ?? values.url ?? "";
    if (!seedUrl) fail("pilot requires --manifest <file.json> or --url <url> (or --resume --id <id>)");
    scope = { ...deriveScopeFromSingleUrl(seedUrl), ...(manifest?.scope ?? {}) };
    id = newAssessmentId();
    mkdirSync(join(runsDir, id), { recursive: true });
    store = AssessmentStore.open(dbPathFor(runsDir, id));
    store.createAssessment({
      id,
      target: { kind: "single_url", url: seedUrl, followLinks: true, maxDepth: manifest?.crawl?.maxDepth ?? 6 },
      scope,
    });
  }

  const roleCreds = new Map<string, LoginCreds>();
  for (const rc of manifestRoleCreds(manifest)) roleCreds.set(rc.name, rc.creds);
  const primary = manifestPrimaryCreds(manifest);
  if (roleCreds.size === 0 && primary) roleCreds.set(primary.username || "user", primary);
  const roleCookieFiles = new Map<string, string>();
  for (const rc of manifestRoleCookies(manifest)) roleCookieFiles.set(rc.name, rc.file);
  const roleDescriptions = new Map<string, string>();
  for (const rc of manifestRoleDescriptions(manifest)) roleDescriptions.set(rc.name, rc.description);

  const mode = `${surveyOnly ? " · survey-only" : resume ? " · resume" : ""}${attended ? " · attended(手動マルチセッション)" : ""}`;
  console.log(`▶ pilot ${id}  (Claude 主導${mode})`);
  console.log(`  target ${seedUrl} | scope hosts=[${scope.inScopeHosts.join(",")}] | model ${model}${values["fast-model"] ? ` (deep) / ${values["fast-model"]} (fast)` : ""} | rate ${rate}ms`);
  // attended で窓を開くロール: インライン CSV(--attended a,b,c)が最優先、無ければ manifest の全ロール名
  // (creds/cookie が無い純手動ロールも含む)。一覧表示にも使う。
  const attendedRoles = attended ? (inlineAttendedRoles ?? (manifest?.auth?.roles ?? []).map((r) => r.name)) : [];
  const allRoles = [...new Set([...attendedRoles, ...roleCreds.keys(), ...roleCookieFiles.keys()])];
  const roleLabel = (r: string): string => {
    const kind = roleCookieFiles.has(r) ? `${r}(cookie)` : roleCreds.has(r) ? r : attended ? `${r}(manual)` : r;
    const d = roleDescriptions.get(r);
    return d ? `${kind} — ${d}` : kind;
  };
  console.log(`  roles: ${allRoles.map(roleLabel).join(", ") || "none"} | max-turns ${maxTurns}${surveyOnly ? " | 調査のみ(診断なし)" : resume ? " | 未診断画面だけ再開" : ""}\n`);

  // attended の人手操作待ち: メッセージを出して Enter で解決する(手動ログイン/再ログインの同期点)。
  const { createInterface } = await import("node:readline");
  const rl = attended ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  const promptOperator = (message: string): Promise<void> =>
    new Promise((resolve) => {
      if (!rl) return resolve();
      rl.question(`\n${message} `, () => resolve());
    });

  try {
    const res = await runPilot({
      store,
      assessmentId: id,
      targetUrl: seedUrl,
      scope,
      profileDir: join(runsDir, id, "browser-profile"),
      artifactsDir: join(runsDir, id, "artifacts"),
      roleCreds,
      model,
      maxTurns,
      rateMs: rate,
      headless: !headed,
      ...(resume ? { resume: true } : {}),
      ...(surveyOnly ? { surveyOnly: true } : {}),
      ...(values.exhaustive ? { exhaustiveSurvey: true } : {}),
      ...(attended
        ? {
            attended: true,
            attendedProfilesDir: join(runsDir, id, "profiles"),
            promptOperator,
            // インライン CSV か manifest 由来のロール名で窓を開く(pass/cookieFile が無い純手動ロールも含む)。
            ...(attendedRoles.length ? { attendedRoles } : {}),
          }
        : {}),
      ...(values["login-url"] ? { loginUrl: values["login-url"] } : {}),
      ...(values["max-screens"] ? { maxScreens: Number.parseInt(values["max-screens"], 10) } : {}),
      ...(roleCookieFiles.size ? { roleCookieFiles } : {}),
      ...(roleDescriptions.size ? { roleDescriptions } : {}),
      ...(values["fast-model"] ? { fastModel: values["fast-model"] } : {}),
      ...(burpProxy ? { burpProxy } : {}),
      ...(values["keepalive-min"] ? { keepAliveMinutes: Number.parseInt(values["keepalive-min"], 10) } : {}),
      ...(browserPath ? { browserPath } : {}),
      ...(values["no-sandbox"] ? { noSandbox: true } : {}),
      onText: (t) => console.log(`\n${t}`),
      onTool: (n, i) => console.log(`  ⚙ ${n.replace("mcp__veritas__", "")} ${JSON.stringify(i).slice(0, 160)}`),
    });
    // --burp-scan: pilot のスキャンが終わったら、同じ run の in-scope 面に対して Burp 能動スキャンも実施。
    // 接続は env(BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL)→ 既定、--burp-api で上書き。失敗しても run は落とさない。
    if (values["burp-scan"] && !surveyOnly) {
      const burpState = store.loadAssessment(id);
      if (burpState) {
        const burpLogins = manifestRoleCreds(manifest).map((rc) => ({ username: rc.creds.username, password: rc.creds.password }));
        await runBurpScanOnRun(store, id, burpState, runsDir, {
          conn: resolveBurpRest({ ...(values["burp-api"] ? { "burp-api": values["burp-api"] } : {}) }),
          configs: ["Audit checks - all except time-based detection methods"],
          logins: burpLogins,
          pollSec: 10,
          maxMin: 30,
        });
      }
    }
    const finalState = store.loadAssessment(id);
    if (finalState) writeFileSync(join(runsDir, id, "report.md"), buildReport(finalState));
    const tk = res.tokensUsed >= 1000 ? `${(res.tokensUsed / 1000).toFixed(1)}k` : `${res.tokensUsed}`;
    console.log(`\n=== ${res.findings.length} finding(s) in ${res.turns} turns · ${tk} tokens${res.costUsd > 0 ? ` · ~$${res.costUsd.toFixed(2)}` : ""} ===`);
    for (const f of res.findings) console.log(`  - [${f.severity}] ${f.title}`);
    console.log(`\nreport → ${join(runsDir, id, "report.md")}`);
    console.log(`観測: serve 済みなら http://127.0.0.1:4317/?id=${id}`);
  } finally {
    rl?.close();
    store.close();
  }
}

function resolveWebRoot(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    return join(dirname(require.resolve("@veritas/webui/package.json")), "dist");
  } catch {
    return undefined;
  }
}

async function cmdScan(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, rate: { type: "string" } },
  });
  if (!values.id) fail("scan requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens to scan — run `crawl` first");
  }

  const minDelayMs = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const http = new FetchHttpClient({ allow: (url) => isInScope(url, state.scope), minDelayMs });
  const evidence = new EvidenceStore(join(runsDir, values.id, "artifacts"));
  console.log(`scanning ${state.screens.length} screens (scope-gated, rate ${minDelayMs}ms) ...`);
  try {
    const result = await scanInventory(state.screens, http, evidence, {
      store,
      assessmentId: values.id,
      onScreen: (r) => {
        for (const o of r.outcomes) {
          if (o.status === "confirmed") {
            console.log(`  ⚠ [${o.severity}] ${r.screenId} ${o.validator}/${o.probeId}: ${o.title}`);
          }
        }
      },
    });
    console.log(`\nscan done: ${result.confirmed} confirmed finding(s) → phase2_scan`);
    console.log(`  evidence: ${join(runsDir, values.id, "artifacts")}`);
    console.log(`  state:    ${dbPath}`);
  } finally {
    store.close();
  }
}

async function cmdLogic(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      model: { type: "string" },
      screen: { type: "string" },
      rate: { type: "string" },
    },
  });
  if (!values.id) fail("logic requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens — run `crawl` first");
  }

  const minDelayMs = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const llm = new ClaudeCliClient(values.model ? { defaultModel: values.model } : {});
  const http = new FetchHttpClient({ allow: (url) => isInScope(url, state.scope), minDelayMs });
  const evidence = new EvidenceStore(join(runsDir, values.id, "artifacts"));
  const hypoOpts = values.model ? { model: values.model } : {};
  const onHypothesis = (h: { screenId: string; class: string; statement: string }, o: { status: string }): void => {
    const mark = o.status === "confirmed" ? "⚠" : o.status === "blocked" ? "·" : "○";
    console.log(`  ${mark} ${h.screenId} [${h.class}] ${h.statement.slice(0, 72)} → ${o.status}`);
  };

  try {
    if (values.screen) {
      const screen = state.screens.find((s) => s.screenId === values.screen);
      if (!screen) {
        store.close();
        fail(`screen ${values.screen} not found`);
      }
      console.log(`assessing business logic on ${screen.screenId} ...`);
      const r = await assessScreenLogic(screen, llm, http, evidence, { store, assessmentId: values.id, onHypothesis }, hypoOpts);
      console.log(`\nlogic done: ${r.hypotheses.length} hypotheses, ${r.findings.length} confirmed`);
    } else {
      console.log("assessing business logic on idor-candidate / object_ref screens ...");
      const r = await assessLogicInventory(state.screens, llm, http, evidence, { store, assessmentId: values.id, onHypothesis }, hypoOpts);
      console.log(`\nlogic done: ${r.hypotheses} hypotheses across ${r.results.length} screens, ${r.confirmed} confirmed`);
    }
    console.log(`  evidence: ${join(runsDir, values.id, "artifacts")}`);
  } finally {
    store.close();
  }
}

async function cmdServe(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      out: { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      "web-root": { type: "string" },
      "no-web": { type: "boolean" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const port = values.port ? Number.parseInt(values.port, 10) : 4317;
  const host = values.host ?? "127.0.0.1";
  const webRoot = values["no-web"] ? undefined : (values["web-root"] ?? resolveWebRoot());
  if (!values["no-web"] && !webRoot) {
    console.error("warning: webui dist not found (build @veritas/webui first); serving API/WS only");
  }

  const srv = await startServer({
    runsDir,
    port,
    host,
    ...(webRoot ? { webRoot } : {}),
    onLog: (m) => console.log(`  ${m}`),
  });
  console.log(`veritas server: http://${host}:${srv.port}  (runs: ${runsDir}${webRoot ? "" : ", API/WS only"})`);
  if (host === "0.0.0.0") {
    console.log("  ⚠ 全インターフェースで待受中。LAN からは http://<this-machine-ip>:" + srv.port + "/");
  }
  console.log("Ctrl-C to stop");
  let stopping = false;
  const shutdown = (): void => {
    if (stopping) return; // 連打しても二重 close しない(MaxListeners 警告を防ぐ)
    stopping = true;
    console.log("\nshutting down …");
    const force = setTimeout(() => process.exit(0), 2000); // 接続が残っても確実に抜ける
    void srv.close().then(() => {
      clearTimeout(force);
      process.exit(0);
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// 既存 run の各画面スクショを backfill(WebUI 表示用)。assessment は回し直さず、screen.observedUrls を
// 1 つだけ開いて撮る。run の browser-profile を再利用するので認証済み画面も(セッションが生きていれば)撮れる。
async function cmdShots(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
    },
  });
  if (!values.id) fail("shots requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const browserPath = values["browser-path"] ?? process.env.VERITAS_BROWSER_PATH;
  const artifactsDir = join(runsDir, id, "artifacts");
  console.log(`▶ shots ${id}: ${state.screens.length} screens (run の browser-profile を再利用)`);
  const driver = await PlaywrightDriver.launch({
    userDataDir: join(runsDir, id, "browser-profile"),
    headless: !values.headed,
    ...(browserPath ? { executablePath: browserPath } : {}),
    ...(values["no-sandbox"] ? { args: ["--no-sandbox"] } : {}),
  });

  let n = 0;
  try {
    for (const screen of state.screens) {
      const url = screen.observedUrls.find((u) => isInScope(u, state.scope));
      if (!url) continue;
      try {
        await driver.visit(url);
        const rel = `screens/${screen.screenId}.png`;
        if (await driver.saveScreenshot(join(artifactsDir, rel))) {
          store.upsertScreen(id, { ...screen, screenshot: rel });
          n += 1;
          console.log(`  ✓ ${screen.screenId}  ${screen.urlTemplate}`);
        }
      } catch (e) {
        console.log(`  ✗ ${screen.screenId}  ${screen.urlTemplate} — ${String(e).slice(0, 80)}`);
      }
    }
  } finally {
    await driver.close();
    store.close();
  }
  console.log(`\n${n}/${state.screens.length} screenshots captured → reload the WebUI (serve)`);
}

// Info レベルのセキュリティヘッダ監査(deterministic, LLM 不使用)。既存 run の各画面の
// レスポンスヘッダを当て、欠落ヘッダ毎に 1 finding(集約)を記録。トグル = 走らせる/走らせない。
// --headers csp,hsts,… で対象を絞れる(カスタムリスト)。
async function cmdHeaderAudit(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, headers: { type: "string" }, rate: { type: "string" } },
  });
  if (!values.id) fail("header-audit requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const wanted = values.headers ? new Set(values.headers.split(",").map((s) => s.trim().toLowerCase())) : null;
  const rules = wanted ? SECURITY_HEADERS.filter((r) => wanted.has(r.key)) : SECURITY_HEADERS;
  const minDelay = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, state.scope), minDelayMs: minDelay });
  const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));
  console.log(`▶ header-audit ${id}: ${state.screens.length} screens × [${rules.map((r) => r.key).join(",")}]`);

  // ルール毎に「欠落していた画面/URL」を集約。最初の例で証拠を1つ記録。
  const missing = new Map<string, { rule: (typeof rules)[number]; urls: string[]; evId: string | null }>();
  for (const screen of state.screens) {
    const url = screen.observedUrls.find((u) => isInScope(u, state.scope));
    if (!url) continue;
    let res;
    try {
      res = await http.send({ method: "GET", url, headers: {}, body: null });
    } catch {
      continue;
    }
    for (const r of auditHeaders(res.headers, url, rules)) {
      const e = missing.get(r.key) ?? { rule: r, urls: [], evId: null };
      e.urls.push(url);
      if (!e.evId) {
        const ev = evidence.record({
          screenId: screen.screenId,
          validator: "header-audit",
          kind: "positive_replay",
          request: { method: "GET", url, headers: {}, body: null },
          response: res,
          note: `missing ${r.header}`,
        });
        e.evId = ev.id;
      }
      missing.set(r.key, e);
    }
  }

  for (const [, e] of missing) {
    store.upsertFinding(id, {
      id: `h-${e.rule.key}`, // 安定 id → 再実行は上書き(冪等)
      screenId: null,
      title: `[headers] ${e.rule.title}`,
      severity: e.rule.severity,
      source: { kind: "validator", validatorName: "header-audit" },
      description: `${e.rule.note} ${e.urls.length} ページで欠落。例: ${e.urls.slice(0, 5).join(", ")}`,
      reproSteps: `GET 対象 URL → レスポンスに '${e.rule.header}' ヘッダが無いことを確認。`,
      evidenceIds: e.evId ? [e.evId] : [],
      scopeBasis: "authorized in-scope screens",
    });
    console.log(`  + h-${e.rule.key} [${e.rule.severity}] ${e.rule.title} (${e.urls.length} pages)`);
  }
  store.close();
  console.log(`\n${missing.size} header finding(s) recorded → reload the WebUI (severity フィルタで info を出し入れ可)`);
}

// Burp issue(XML or REST 由来)を run にマージ。既存 finding と (粗カテゴリ × 正規化エンドポイント) で
// 重複排除し、スコープ外は捨てる。burp-import / burp-scan の両方が使う共通ロジック。
function mergeBurpIssues(
  store: AssessmentStore,
  id: string,
  state: AssessmentState,
  runsDir: string,
  issues: ReadonlyArray<BurpIssue>,
  prefix = "b",
): { added: number; skipped: number; oos: number } {
  const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));
  const keyOf = (cat: string, path: string): string => {
    try {
      return `${cat}::${normalizePath(path).template}`;
    } catch {
      return `${cat}::${path}`;
    }
  };
  const existing = new Set<string>();
  for (const f of state.findings) {
    const ep = /(\/[A-Za-z0-9_{}/.-]+)/.exec(f.title)?.[1] ?? "/";
    existing.add(keyOf(coarseCategory(f.title), ep));
  }
  let added = 0;
  let skipped = 0;
  let oos = 0;
  for (const issue of issues) {
    let url: string;
    try {
      url = new URL(issue.path || "/", issue.host).toString();
    } catch {
      url = issue.host;
    }
    if (!isInScope(url, state.scope)) {
      oos += 1;
      continue;
    }
    let path: string;
    try {
      path = new URL(url).pathname;
    } catch {
      path = issue.path || "/";
    }
    const key = keyOf(coarseCategory(issue.name), path);
    if (existing.has(key)) {
      skipped += 1;
      continue;
    }
    existing.add(key);
    added += 1;
    const ev = evidence.record({
      screenId: "burp",
      validator: "burp",
      kind: "positive_replay",
      request: { method: "GET", url, headers: {}, body: issue.request || null },
      response: { status: 0, finalUrl: url, durationMs: 0, headers: {}, body: issue.response },
      note: issue.name,
    });
    store.upsertFinding(id, {
      id: `${prefix}-${String(added).padStart(3, "0")}`,
      screenId: null,
      title: `[burp] ${issue.name}`,
      severity: burpSeverity(issue.severity),
      source: { kind: "validator", validatorName: "burp" },
      description: `${(issue.detail || issue.background).slice(0, 600)} @ ${url}`,
      reproSteps: "Burp が検出。証拠に request/response(Cookie/Authorization は伏字)。",
      evidenceIds: [ev.id],
      scopeBasis: "burp scan (in-scope)",
    });
    console.log(`  + ${prefix}-${String(added).padStart(3, "0")} [${burpSeverity(issue.severity)}] ${issue.name}`);
  }
  return { added, skipped, oos };
}

// Burp Pro の XML レポートを取り込み、既存 finding と重複しない net-new だけを追加する。
// 連携の流れ: pilot --burp-proxy <burp> で全トラフィックを Burp 経由 → Burp でスキャン → レポート XML
// を export → このコマンドで取り込み。重複排除は (粗カテゴリ × 正規化エンドポイント) で行う。
async function cmdBurpImport(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, report: { type: "string" }, out: { type: "string" } },
  });
  if (!values.id) fail("burp-import requires --id <assessment-id>");
  if (!values.report) fail("burp-import requires --report <burp-report.xml>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  if (!existsSync(values.report)) fail(`no report at ${values.report}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const issues = parseBurpReport(readFileSync(values.report, "utf8"));
  const { added, skipped, oos } = mergeBurpIssues(store, id, state, runsDir, issues);
  store.close();
  console.log(`\nburp-import ${id}: ${issues.length} issue(s) → +${added} net-new(dup ${skipped} / out-of-scope ${oos})`);
}

// Burp REST 接続情報を「引数 → env → 既定」で解決する。env: BURP_API / BURP_API_KEY / BURP_RESOURCE_POOL。
interface BurpRestConn {
  base: string;
  apiKey?: string;
  resourcePool: string; // "" = Burp 既定プール
}
function resolveBurpRest(v: { "burp-api"?: string; "api-key"?: string; "resource-pool"?: string }): BurpRestConn {
  const base = v["burp-api"] ?? process.env.BURP_API ?? "http://127.0.0.1:1337";
  const apiKey = v["api-key"] ?? process.env.BURP_API_KEY;
  const resourcePool = v["resource-pool"] !== undefined ? v["resource-pool"] : (process.env.BURP_RESOURCE_POOL ?? "250ms");
  return { base, ...(apiKey ? { apiKey } : {}), resourcePool };
}

// Burp 能動スキャンを 1 つの run に対して実行(start→poll→merge→report)。store の open/close は呼び出し側が管理。
// 非致命: Burp が無い/失敗しても例外で run を落とさず、ログして added=0 を返す(pilot --burp-scan から呼ぶため)。
async function runBurpScanOnRun(
  store: AssessmentStore,
  id: string,
  state: AssessmentState,
  runsDir: string,
  o: { conn: BurpRestConn; configs: string[]; logins: Array<{ username: string; password: string }>; pollSec: number; maxMin: number },
): Promise<number> {
  const { base, apiKey, resourcePool } = o.conn;
  const usePool = resourcePool !== "";
  const seeds = new Set<string>();
  if ("url" in state.target && state.target.url) seeds.add(state.target.url);
  for (const sc of state.screens) {
    for (const u of sc.observedUrls ?? []) {
      if (isInScope(u, state.scope)) seeds.add(u.split("#")[0] ?? u);
    }
  }
  const urls = [...seeds].slice(0, 300);
  if (urls.length === 0) {
    console.log("⚠ burp-scan: in-scope URL が無いのでスキップ(先に survey/pilot を)");
    return 0;
  }
  console.log(`▶ burp-scan ${id} → ${base}`);
  console.log(`  config: ${o.configs.join(" + ")}${usePool ? ` | pool: ${resourcePool}` : " | pool: (Burp 既定)"} | seeds: ${urls.length}${o.logins.length ? ` | auth: ${o.logins.length}` : ""}`);

  const startScan = (pool: string | undefined): Promise<string> =>
    startBurpScan({ base, ...(apiKey ? { apiKey } : {}), urls, configs: o.configs, ...(pool ? { resourcePool: pool } : {}), ...(o.logins.length ? { logins: o.logins } : {}) });

  let taskId: string;
  try {
    taskId = await startScan(usePool ? resourcePool : undefined);
  } catch (e) {
    if (usePool && /resource pool/i.test(String(e))) {
      console.log(`⚠ resource pool "${resourcePool}" が Burp に無いため既定プールで続行(同時1/Delay 250ms のプールを作ると throttle されます)。`);
      try {
        taskId = await startScan(undefined);
      } catch (e2) {
        console.log(`⚠ burp-scan start failed: ${String(e2).slice(0, 160)} — スキップ`);
        return 0;
      }
    } else {
      console.log(`⚠ burp-scan start failed: ${String(e).slice(0, 160)}\n  → Burp Pro REST 有効? base=${base} / key? — スキップ`);
      return 0;
    }
  }
  console.log(`  scan task ${taskId} started; polling every ${o.pollSec}s (timeout ${o.maxMin}m)…`);

  const deadline = Date.now() + o.maxMin * 60_000;
  let last: Awaited<ReturnType<typeof getBurpScan>> | null = null;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, o.pollSec * 1000));
    try {
      last = await getBurpScan(base, apiKey, taskId);
    } catch (e) {
      console.log(`  ⚠ poll error: ${String(e).slice(0, 120)}`);
      continue;
    }
    console.log(`  [${last.status}] progress ${last.progress}% · ${last.issueEvents} issue event(s)`);
    if (last.status === "succeeded" || last.status === "failed") break;
  }
  if (!last) {
    console.log("⚠ burp-scan: scan status 取得できず(timeout) — スキップ");
    return 0;
  }
  if (last.status !== "succeeded") console.log(`⚠ scan ended status=${last.status} — 現時点の issue を取り込みます`);

  const { added, skipped, oos } = mergeBurpIssues(store, id, state, runsDir, last.issues, "bs");
  if (added > 0) {
    const fs2 = store.loadAssessment(id);
    if (fs2) writeFileSync(join(runsDir, id, "report.md"), buildReport(fs2));
  }
  console.log(`\nburp-scan ${id}: ${last.issues.length} issue(s) → +${added} net-new(dup ${skipped} / out-of-scope ${oos})`);
  return added;
}

// Burp Pro の REST API を叩いて能動スキャンを起動 → 完了までポーリング → issue を取り込む(XML export 不要のライブ版)。
// 対象URL = AI がマップした in-scope の具体URL(=実質 AI が対象を決める)。検査内容 = Burp の named config(--config)。
// 接続情報は引数 → env(BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL)→ 既定 で解決。
async function cmdBurpScan(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      "burp-api": { type: "string" },
      "api-key": { type: "string" },
      config: { type: "string", multiple: true },
      "resource-pool": { type: "string" },
      manifest: { type: "string" },
      "max-min": { type: "string" },
      poll: { type: "string" },
    },
  });
  if (!values.id) fail("burp-scan requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const conn = resolveBurpRest(values);
  // --config は複数指定可(クロール速度 + 監査内容を別プリセットで重ねる)。無指定なら時間ベース除く全 audit。
  const configs = values.config?.length ? values.config : ["Audit checks - all except time-based detection methods"];
  const pollSec = values.poll ? Number.parseInt(values.poll, 10) : 10;
  const maxMin = values["max-min"] ? Number.parseInt(values["max-min"], 10) : 30;
  // 認証スキャン(任意): manifest の資格情報を Burp の application_logins に渡す。
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const logins = manifestRoleCreds(manifest).map((rc) => ({ username: rc.creds.username, password: rc.creds.password }));

  try {
    await runBurpScanOnRun(store, id, state, runsDir, { conn, configs, logins, pollSec, maxMin });
  } finally {
    store.close();
  }
}

// 対話型 scope-manifest ジェネレータ(独立して使える。pilot/assess が読む JSON を組み立てる)。
async function cmdManifest(args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { out: { type: "string" }, force: { type: "boolean" } } });
  const { createInterface } = await import("node:readline/promises");
  const isTty = process.stdin.isTTY === true;
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: isTty });

  // 行キュー(readline/promises の question はパイプ入力で 2 問目以降ハングするので 'line' イベントで読む)。
  const queue: string[] = [];
  const waiters: Array<{ res: (v: string) => void; rej: (e: Error) => void }> = [];
  let closed = false;
  rl.on("line", (l) => {
    const w = waiters.shift();
    if (w) w.res(l);
    else queue.push(l);
  });
  rl.on("close", () => {
    closed = true;
    while (waiters.length) waiters.shift()?.rej(new Error("input closed"));
  });
  // パスワードのエコーを伏せる(端末スクロールバック/肩越し対策)。readline の出力フックを mute フラグで制御。
  let muted = false;
  const ri = rl as unknown as { _writeToOutput?: (s: string) => void };
  const baseWrite = ri._writeToOutput?.bind(ri);
  if (baseWrite) ri._writeToOutput = (s: string): void => { if (!muted) baseWrite(s); };

  const readLine = (): Promise<string> => {
    const q = queue.shift();
    if (q !== undefined) return Promise.resolve(q);
    if (closed) return Promise.reject(new Error("input closed"));
    return new Promise((res, rej) => waiters.push({ res, rej }));
  };
  const ask = async (q: string, def?: string): Promise<string> => {
    process.stdout.write(def ? `${q} [${def}]: ` : `${q}: `);
    const a = (await readLine()).trim();
    return a || def || "";
  };
  const askBool = async (q: string, def: boolean): Promise<boolean> =>
    (await ask(`${q} (y/n)`, def ? "y" : "n")).toLowerCase().startsWith("y");
  const askInt = async (q: string, def: number): Promise<number> => {
    const n = Number.parseInt(await ask(q, String(def)), 10);
    return Number.isFinite(n) ? n : def;
  };
  const askList = async (q: string): Promise<string[]> => {
    const a = await ask(q);
    return a ? a.split(",").map((s) => s.trim()).filter(Boolean) : [];
  };
  const askSecret = async (q: string): Promise<string> => {
    process.stdout.write(`${q}: `);
    muted = true;
    try {
      return (await readLine()).trim();
    } finally {
      muted = false;
      process.stdout.write("\n");
    }
  };

  type Role = { name: string; description?: string; username?: string; password?: string; cookieFile?: string };

  try {
    console.log("\n=== Umbra Hands scope-manifest generator ===");
    console.log("認可済みターゲットのみ。各項目は Enter で既定値。\n");

    let target = "";
    while (!target) {
      target = await ask("Target seed URL (例 https://app.example.com/)");
      try {
        new URL(target);
      } catch {
        console.log("  ↳ 有効な URL を入力してください");
        target = "";
      }
    }
    const host = new URL(target).host;

    console.log(`\n--- スコープ(既定 in-scope: ${host}) ---`);
    const extraHosts = await askList("追加 in-scope hosts (カンマ区切り, 任意)");
    const inScopeHosts = [...new Set([host, ...extraHosts])];
    const outOfScopeHosts = await askList("Out-of-scope hosts (任意)");
    const outOfScopePathPrefixes = await askList("Out-of-scope path prefixes (例 /logout,/signout)");
    const approvalPathPrefixes = await askList("承認が要る path prefixes (機微領域。例 /admin)");
    const requestsPerMinute = await askInt("Rate: requests / minute", 30);
    const maxConcurrent = await askInt("Rate: max concurrent", 2);

    console.log("\n--- クロール ---");
    const followLinks = await askBool("リンクを辿る?", true);
    const maxDepth = await askInt("最大深さ", 8);

    const model = await ask("\nModel", "claude-sonnet-4-6");

    console.log("\n--- 認証ロール(名前を空 Enter で終了) ---");
    console.log("  資格情報 か 事前取得 Cookie ファイルのどちらか。[0]=主ログイン、複数指定で auth-diff。");
    const roles: Role[] = [];
    for (;;) {
      const name = await ask(`\nRole #${roles.length + 1} name (空で終了)`);
      if (!name) break;
      // 権限レベルの説明(任意)。auth-diff で「どれが高権限/低権限か」をエージェントが判断する材料。
      const description = await ask("  説明/権限 (任意。例: 全権管理者 / 一般ユーザ(読取のみ))");
      const kind = (await ask("  種別: (c)資格情報 / (k)Cookie ファイル", "c")).toLowerCase();
      if (kind.startsWith("k")) {
        const cookieFile = await ask("  cookie ファイルのパス");
        if (cookieFile) roles.push({ name, ...(description ? { description } : {}), cookieFile });
        else console.log("  ↳ パス未入力のためスキップ");
      } else {
        const username = await ask("  username (空なら role 名を使用)");
        const password = await askSecret("  password");
        if (password) roles.push({ name, ...(description ? { description } : {}), ...(username ? { username } : {}), password });
        else console.log("  ↳ password 未入力のためスキップ");
      }
    }

    const manifest: AssessManifest = {
      target,
      scope: {
        inScopeHosts,
        outOfScopeHosts,
        inScopePathPrefixes: ["/"],
        outOfScopePathPrefixes,
        approvalPathPrefixes,
        approvalMethods: ["DELETE", "PUT", "PATCH"],
        rate: { requestsPerMinute, maxConcurrent },
      },
      crawl: { followLinks, maxDepth },
      model,
    };
    if (roles.length) manifest.auth = { roles };

    const safeHost = host.replace(/[^a-zA-Z0-9._-]/g, "_");
    const outPath = values.out ?? (await ask("\n出力ファイル", `scope_manifest_${safeHost}.json`));
    if (existsSync(outPath) && !values.force) {
      if (!(await askBool(`${outPath} は既に存在します。上書きしますか?`, false))) {
        console.log("中止しました。");
        return;
      }
    }
    writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`\n✓ 書き出しました: ${outPath}`);
    if (roles.length) {
      console.log("⚠ 資格情報/Cookie を含む = 秘密ファイル。gitignore 済みパターン scope_manifest_*.json に一致させてください。");
    }
    console.log(`\n次の一手:\n  node packages/cli/dist/main.js pilot --manifest ${outPath} --model ${model}\n`);
  } finally {
    rl.close();
  }
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "manifest":
    case "init":
      await cmdManifest(rest);
      return;
    case "assess":
      await cmdAssess(rest);
      return;
    case "pilot":
      await cmdPilot(rest);
      return;
    case "run":
      cmdRun(rest);
      return;
    case "crawl":
      await cmdCrawl(rest);
      return;
    case "label":
      await cmdLabel(rest);
      return;
    case "scan":
      await cmdScan(rest);
      return;
    case "logic":
      await cmdLogic(rest);
      return;
    case "serve":
      await cmdServe(rest);
      return;
    case "report":
      cmdReport(rest);
      return;
    case "shots":
      await cmdShots(rest);
      return;
    case "header-audit":
      await cmdHeaderAudit(rest);
      return;
    case "burp-scan":
      await cmdBurpScan(rest);
      return;
    case "burp-import":
      await cmdBurpImport(rest);
      return;
    case "status":
      cmdStatus(rest);
      return;
    case "list":
      cmdList(rest);
      return;
    case undefined:
    case "help":
    case "-h":
    case "--help":
      console.log(USAGE);
      return;
    default:
      fail(`unknown command: ${cmd}`);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
