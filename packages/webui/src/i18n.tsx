// Display-language i18n for the WebUI (shared by serve mode and the desktop renderer).
// Canonical source strings are ENGLISH; the JA table maps them to Japanese. Missing keys fall
// back to the source string, so untranslated text renders English instead of breaking.
// Choice persists in localStorage; default follows navigator.language (ja → ja, else en).
import { createContext, useContext, useMemo, useState, type ReactNode } from "react";
import { NativeSelect } from "./components/ui/native-select";

export type Lang = "en" | "ja";
export const LANG_CHOICES: ReadonlyArray<{ value: Lang; label: string }> = [
  { value: "en", label: "English" },
  { value: "ja", label: "日本語" },
];

const LS_KEY = "verdict.lang";

export type T = (s: string, vars?: Record<string, string | number>) => string;

const LangCtx = createContext<{ lang: Lang; setLang: (l: Lang) => void; t: T }>({
  lang: "en",
  setLang: () => {},
  t: (s) => s,
});

function initialLang(): Lang {
  try {
    const v = window.localStorage.getItem(LS_KEY);
    if (v === "en" || v === "ja") return v;
  } catch {
    /* storage unavailable */
  }
  return typeof navigator !== "undefined" && (navigator.language ?? "").toLowerCase().startsWith("ja") ? "ja" : "en";
}

/** English → 日本語. Keys are the exact source strings passed to t(). */
const JA: Record<string, string> = {
  " (note)": "（ノート）",
  " — log in / clear CAPTCHA in the Browser tab, then Capture session → Logged in → continue.":
    " — Browser タブでログイン／CAPTCHA を解除し、「セッションを保存」→「ログイン済み → 続行」。",
  "(latest 200)": "（最新 200 件）",
  "(leave blank if none)": "（なければ空欄）",
  "(you)": "（あなた）",
  "+ New": "+ 新規",
  "+ New assessment": "+ 新規アセスメント",
  "+ add header": "+ ヘッダ追加",
  "+ add role": "+ ロール追加",
  "+ screen {id}": "+ 画面 {id}",
  "4 · 0 = off": "4 · 0 = オフ",
  "A canary is required — plant it out-of-band in the assistant's system prompt / custom instructions, then paste it here (or Generate one and seed it).":
    "カナリアは必須です — アシスタントのシステムプロンプト／カスタム指示に帯域外で仕込んでからここに貼るか、Generate で生成して投入してください。",
  "A trailing * is a wildcard; a specific allowed prefix wins over a block (a bare /* alone doesn't lift a block).":
    "末尾の * はワイルドカードです。具体的な許可プレフィックスはブロックより優先されます（/* 単独ではブロックは解除されません）。",
  "A04 cross-screen scenarios ({n})": "A04 画面横断シナリオ（{n}）",
  "AI assistant red-team": "AI アシスタント・レッドチーム",
  "API key": "API キー",
  "API spec": "API 仕様",
  "API specification assessment": "API 仕様アセスメント",
  APIs: "API",
  "APIs ({n})": "API（{n}）",
  Account: "アカウント",
  Accounts: "アカウント",
  Action: "アクション",
  Actions: "操作",
  "Actions for {id}": "{id} の操作",
  Actor: "実行者",
  "Add target": "ターゲット追加",
  "Add target — investigate a specific URL": "ターゲット追加 — 特定の URL を調査",
  "Advanced (rate · limits · crawl · headers)": "詳細（レート・上限・クロール・ヘッダ）",
  Agent: "エージェント",
  "Allowed hosts: {hosts}": "許可ホスト: {hosts}",
  "Anchor URL (menu hub)": "アンカー URL（メニューハブ）",
  "Applies to the whole interface immediately; saved on this device.":
    "即座に画面全体へ適用され、この端末に保存されます。",
  Apply: "適用",
  "Apply the captured login and continue this diagnosis; restart it if stopped":
    "取得したログインを適用してこの診断を続行します。停止中なら再起動します",
  "Apply the captured login, restart the diagnosis if stopped, and return to Main":
    "取得したログインを適用し、停止中なら診断を再起動してメインへ戻ります",
  "Ask a question…  (Ctrl/Cmd+Enter to send)": "質問を入力…（Ctrl/Cmd+Enter で送信）",
  "Ask about this assessment — findings, risk, coverage, scope.":
    "このアセスメントについて質問 — 検出・リスク・カバレッジ・スコープ。",
  "Ask an operator to start one.": "オペレーターに開始を依頼してください。",
  "Ask is read-only for viewers — sign in as operator to use it.":
    "Ask はビューアでは読み取り専用です — オペレーターでサインインしてください。",
  "Assessment views": "アセスメントビュー",
  "Attended assessment": "有人アセスメント",
  "Attended sessions (live browser takeover) are operator-only. Viewers have read-only access.":
    "有人セッション（ブラウザの実機操作）はオペレーター専用です。ビューアは読み取り専用です。",
  "Audit REST URL": "Audit REST URL",
  "Audit log": "監査ログ",
  "Audit token": "Audit トークン",
  "Auth — site-wide Basic / Digest & roles ({n})": "認証 — サイト共通 Basic / Digest とロール（{n}）",
  "Auto (Interactsh if a server is set, else Burp Audit REST, else off)":
    "自動（サーバ設定時は Interactsh、なければ Burp Audit REST、どちらもなければオフ）",
  "Autonomous recon → diagnosis of a web app from one URL.":
    "1 つの URL から Web アプリを自律的に偵察 → 診断。",
  Back: "戻る",
  "Base URL": "ベース URL",
  "Basic password": "Basic パスワード",
  "Basic user": "Basic ユーザー",
  "Blind SSRF/XXE/SQLi need an out-of-band callback host. Interactsh is free (public server is opt-in third-party egress). Burp Collaborator needs the Audit REST extension.":
    "Blind SSRF/XXE/SQLi にはアウトオブバンドのコールバックホストが必要です。Interactsh は無料（公開サーバはオプトインの第三者 egress）。Burp Collaborator には Audit REST 拡張が必要です。",
  Browser: "ブラウザ",
  "Browser tab + scan traffic (browser + http), e.g. Burp — blank = direct":
    "ブラウザタブ＋スキャントラフィック（browser + http）、例: Burp — 空欄 = 直接接続",
  "Browse…": "参照…",
  "Burp Collaborator (Audit REST)": "Burp Collaborator（Audit REST）",
  "Burp XML report": "Burp XML レポート",
  "Can't reach server": "サーバに接続できません",
  "Canary * — plant this in the assistant's system prompt / custom instructions first, then paste it here":
    "カナリア * — まずアシスタントのシステムプロンプト／カスタム指示に仕込み、ここに貼り付けてください",
  Cancel: "キャンセル",
  "Capture session": "セッションを保存",
  "Change password": "パスワード変更",
  "Changes land at the next between-screens checkpoint. Proxy is restart-class — change it by stopping and resuming the run with a new proxy.":
    "変更は次の画面間チェックポイントで反映されます。Proxy は再起動系の設定です — run を停止し、新しい proxy で再開してください。",
  "Changing the password signs out every session on every device.":
    "パスワードを変更すると、全デバイスの全セッションがサインアウトされます。",
  "Chat UI URL *": "チャット UI URL *",
  "Chat UI URL is required": "チャット UI URL は必須です",
  "Chat URL must start with http:// or https:// (e.g. https://{url})":
    "チャット URL は http:// または https:// で始めてください（例: https://{url}）",
  "Check connections": "接続チェック",
  "Check executions ({n})": "チェック実行（{n}）",
  "Check setup": "セットアップを確認",
  "Checking setup…": "セットアップ確認中…",
  "Checking…": "確認中…",
  "Checks use the values above without saving. Model checks send short test requests and may use quota.":
    "チェックは保存せず上記の値で実行されます。モデルチェックは短いテスト要求を送り、クォータを消費する場合があります。",
  "Choose a valid OpenAPI / Swagger JSON file first": "先に有効な OpenAPI / Swagger JSON ファイルを選択してください",
  "Choose role": "ロールを選択",
  "Chromium path": "Chromium パス",
  "Claude manages its context window and automatic compaction.":
    "Claude はコンテキストウィンドウと自動圧縮を自前で管理します。",
  "Claude model name": "Claude モデル名",
  "Click again to confirm": "もう一度クリックで確定",
  "Click {action} to run an authenticated scan (headless, in this window).":
    "{action} をクリックすると認証済みスキャンを実行します（ヘッドレス・このウィンドウ内）。",
  "Click {action} to save cookies and localStorage (SPA tokens).":
    "{action} をクリックすると Cookie と localStorage（SPA トークン）を保存します。",
  Close: "閉じる",
  Collapse: "折りたたむ",
  "Coming Soon": "近日対応",
  Composer: "コンポーザー",
  "Connecting to {id} … ({conn})": "{id} に接続中 …（{conn}）",
  "Connection checks could not finish. Try again shortly.":
    "接続チェックを完了できませんでした。しばらくして再試行してください。",
  "Continue this run →": "この run を続行 →",
  "Continuing…": "続行中…",
  "Copy URL": "URL をコピー",
  "Copy cookies": "Cookie をコピー",
  "Copy the Cookie header to the clipboard (Repeater / curl)":
    "Cookie ヘッダをクリップボードへコピー（Repeater / curl 用）",
  "Could not check setup. Open Settings and check connections.":
    "セットアップを確認できませんでした。設定で接続チェックを開いてください。",
  "Could not read the specification": "仕様ファイルを読み取れませんでした",
  Crawl: "クロール",
  Create: "作成",
  Created: "作成日時",
  "Created {name}": "{name} を作成しました",
  "Custom headers ({n})": "カスタムヘッダ（{n}）",
  "DOM-XSS sinks": "DOM-XSS シンク",
  "Deep max context": "Deep 最大コンテキスト",
  "Deep model": "Deep モデル",
  "Diagnosis breakdown": "診断の内訳",
  "Diagnosis progress by status": "ステータス別 診断進捗",
  "Diagnosis restarted with the captured session": "取得したセッションで診断を再起動しました",
  Disable: "無効化",
  Discard: "破棄",
  "Display language": "表示言語",
  "Display name": "表示名",
  "Done (logged in)": "完了（ログイン済み）",
  "Duplicate assessment": "アセスメントを複製",
  "Duplicate…": "複製…",
  Enable: "有効化",
  "Enter target URLs to preview": "対象 URL を入力するとプレビューします",
  Exclude: "除外",
  "Exclude this branch — {n} un-scanned screen(s)": "このブランチを除外 — 未スキャン画面 {n} 件",
  "Exclude this screen from scanning": "この画面をスキャン対象から除外",
  "Exclude {n}?": "{n} 件を除外しますか？",
  Expand: "展開",
  Export: "エクスポート",
  "Export / Import": "エクスポート / インポート",
  "Fast model": "Fast モデル",
  "File input": "ファイル入力",
  "Filter findings by text": "検出をテキストで絞り込み",
  Findings: "検出",
  "Findings (0)": "検出（0）",
  "Findings ({n})": "検出（{n}）",
  "Findings CSV": "検出 CSV",
  "Findings on this screen ({n})": "この画面の検出（{n}）",
  "Fix the failed setup checks in Settings before starting.":
    "開始前に設定で失敗したセットアップチェックを直してください。",
  "Focus — what to prioritize in this run": "フォーカス — この run で優先すること",
  Forward: "進む",
  "Full assess — crawl & diagnose the whole site": "フルアセス — サイト全体をクロール＆診断",
  "Go ↵": "移動 ↵",
  Help: "ヘルプ",
  ID: "ID",
  IP: "IP",
  Import: "インポート",
  Input: "入力",
  "Input/output are provider-reported (prompt vs completion; Claude cache buckets count as input). \"—\" = recorded before split tracking or estimated without provider usage.":
    "input/output はプロバイダ報告値です（prompt vs completion。Claude のキャッシュ系は input に計上）。「—」= 分割記録導入前、または usage 未報告の推定値。",
  "Interactsh (free)": "Interactsh（無料）",
  "Interactsh server": "Interactsh サーバ",
  "Interactsh token": "Interactsh トークン",
  "Inventory HTML": "インベントリ HTML",
  "JS ({n})": "JS（{n}）",
  "Keep editing": "編集を続ける",
  "Keepalive (min)": "Keepalive（分）",
  Language: "言語",
  Launch: "開始",
  "Launch redteam": "レッドチーム開始",
  "Launching…": "起動中…",
  "Light max context": "Light 最大コンテキスト",
  "Light model": "Light モデル",
  "Loading…": "読み込み中…",
  "Log in / clear any CAPTCHA by hand — this is a real browser, not automation.":
    "手動でログイン／CAPTCHA を解除してください — これは実ブラウザで、自動化ではありません。",
  "Logged in → continue": "ログイン済み → 続行",
  "Logged-in role": "ログイン済みロール",
  "Login URL (blank = target)": "ログイン URL（空欄 = ターゲット）",
  Main: "メイン",
  "Main — back to the assessments view": "メイン — アセスメント一覧へ戻る",
  "Max context includes input and response. VERDICT reserves room for replies and summarizes older history as it fills. Blank defaults to 256,000 tokens; Light inherits Deep when they use the same model. Use each model's supported limit.":
    "最大コンテキストには入力と応答を含みます。VERDICT は応答用の余白を残し、いっぱいになると古い履歴を要約します。空欄は 256,000 トークンが既定。同じモデルを使う場合 Light は Deep を継承します。各モデルの対応上限を使ってください。",
  "Max screens": "最大画面数",
  Maximize: "最大化",
  Minimize: "最小化",
  Model: "モデル",
  "Model (deep)": "モデル（deep）",
  "Model ID from your provider": "プロバイダのモデル ID",
  "Model tiering": "モデル階層化",
  "Needs human [{reason}]:": "人要介入 [{reason}]:",
  "Never scan these paths — e.g. /logout": "このパスはスキャンしない — 例: /logout",
  "New assessment": "新規アセスメント",
  "New chat": "新規チャット",
  "New passwords do not match": "新しいパスワードが一致しません",
  "New user": "新規ユーザー",
  "No APIs discovered yet.": "API はまだ検出されていません。",
  "No JS analyzed yet.": "JS はまだ解析されていません。",
  "No state changes recorded yet.": "状態変更はまだ記録されていません。",
  "State changes ({n})": "状態変更（{n}）",
  "current value": "現在値",
  "writes": "変更回数",
  "subject": "対象",
  "field": "項目",
  "action": "操作",
  "evidence": "証拠",
  "at": "時刻",
  "No accounts.": "アカウントがありません。",
  "No activity yet.": "まだアクティビティがありません。",
  "No assessments yet": "アセスメントはまだありません",
  "No assessments yet — token usage appears here once a run starts.":
    "アセスメントはまだありません — run が始まるとトークン使用量がここに表示されます。",
  "No audit events yet.": "監査イベントはまだありません。",
  "No auth configured — the run goes unauthenticated; login-protected areas won't be reached (add a role under Auth if the target needs login).":
    "認証未設定 — この run は非認証で実行され、ログイン保護領域には到達しません（対象にログインが必要なら認証でロールを追加）。",
  "No findings yet.": "検出はまだありません。",
  "No live session. (attended runs launched from “+ New” with attended on appear here.)":
    "ライブセッションはありません。（「+ 新規」から attended を有効にして起動した run がここに表示されます）",
  "No multi-step / cross-screen scenario findings (yet).":
    "複数ステップ／画面横断シナリオの検出は（まだ）ありません。",
  "No plans yet — methodology runs after the survey maps the surface.":
    "計画はまだありません — サーベイで対象面を把握してから methodology が実行されます。",
  "Observed URLs": "観測 URL",
  Off: "オフ",
  "Open in Browser": "ブラウザで開く",
  "Open this URL in the in-app Browser tab": "この URL をアプリ内ブラウザタブで開く",
  "OpenAPI 3.x / Swagger 2.0 JSON file *": "OpenAPI 3.x / Swagger 2.0 JSON ファイル *",
  "Operator context": "オペレーターコンテキスト",
  "Operator context is standing FACTS about your targets — auth shape, tenant model, where the API lives. It pre-fills the New form on every run and is appended to each stage's system prompt (--context). Additive only: it guides the agent, it never overrides the safety / scope / evidence-discipline rules. Leave blank if your targets differ each time (set it per run instead).":
    "オペレーターコンテキストはターゲットに関する恒常的な事実（認証形式・テナントモデル・API の場所）です。毎回 New フォームへ事前入力され、各ステージのシステムプロンプトにも追加されます（--context）。追加のみ: エージェントを導くもので、安全性・スコープ・証跡ルールを上書きしません。ターゲットが毎回異なるなら空欄にして、run ごとに設定してください。",
  "Operator usage guide — scope, auth roles, run options":
    "オペレーター向けガイド — スコープ・認証ロール・run オプション",
  Options: "オプション",
  Output: "出力",
  Overview: "概要",
  Owner: "オーナー",
  "Page base — diagnose the URLs you enter below": "ページ指定 — 下に入力した URL を診断",
  "Pages to scan — one URL per line": "スキャン対象ページ — 1 行に 1 URL",
  Params: "パラメータ",
  "Password changed — signing you out of all sessions…":
    "パスワードを変更しました — 全セッションからサインアウト中…",
  "Path scope (optional)": "パススコープ（任意）",
  "Per-screen attack plans ({n})": "画面別攻撃計画（{n}）",
  Phase: "フェーズ",
  "Point VERDICT at a target and it maps the app, then hunts for vulnerabilities — autonomously.":
    "ターゲットを指定すれば、VERDICT がアプリをマッピングし、脆弱性を自律的に探索します。",
  Project: "プロジェクト",
  Projects: "プロジェクト",
  Provider: "プロバイダ",
  "Queued, in progress, blocked, or failed; diagnosis is not complete":
    "キュー中・実行中・ブロック・失敗 — 診断は未完了",
  "REST API URL": "REST API URL",
  "Rate (ms)": "レート（ms）",
  "Read-only (viewer). Live control — add target / reconfigure — is operator-only.":
    "読み取り専用（ビューア）。ライブ操作 — ターゲット追加・設定変更 — はオペレーター専用です。",
  "Reconfigure the running scan (live)": "実行中スキャンの設定変更（ライブ）",
  Refresh: "更新",
  Reload: "再読み込み",
  "Remove header": "ヘッダ削除",
  "Remove role": "ロール削除",
  Report: "レポート",
  Requests: "リクエスト",
  "Reset password — signs out all their sessions":
    "パスワードリセット — そのユーザーの全セッションをサインアウト",
  "Reset pw": "PW リセット",
  "Resolve without capturing/applying a session": "セッションを保存・適用せずに解決",
  "Resolve without session": "セッションなしで解決",
  "Resource pool": "リソースプール",
  Restore: "元のサイズに戻す",
  Resume: "再開",
  Role: "ロール",
  "Role for {name}": "{name} のロール",
  Roles: "ロール",
  Run: "実行",
  "Run a Burp active scan after diagnosis on each run":
    "各 run の診断後に Burp アクティブスキャンを実行",
  "Run metrics": "Run メトリクス",
  "SITE TREE": "サイトツリー",
  Save: "保存",
  "Save cookies + localStorage (SPA Bearer) for the scan":
    "スキャン用に Cookie＋localStorage（SPA Bearer）を保存",
  "Scan (new run) →": "スキャン（新規 run）→",
  "Scan only these paths — e.g. /app/*": "このパスだけスキャン — 例: /app/*",
  "Scan waiting on you — log in / clear CAPTCHA here (real browser). Then Capture session and Logged in → continue (injects cookies into the scan).":
    "スキャンが入力待ちです — ここ（実ブラウザ）でログイン／CAPTCHA を解除してください。その後「セッションを保存」→「ログイン済み → 続行」（Cookie をスキャンへ注入）。",
  "Scan waiting on you — log in / clear CAPTCHA here (real browser). Then Capture session.":
    "スキャンが入力待ちです — ここ（実ブラウザ）でログイン／CAPTCHA を解除してください。その後「セッションを保存」。",
  Scenarios: "シナリオ",
  "Screen inventory": "画面インベントリ",
  Screens: "画面",
  "Screens CSV": "画面 CSV",
  "Screens marked conclusive with no check records — a legacy/log claim, detail unknown":
    "チェック記録なしで確定扱いの画面 — 旧形式・ログベースの主張で詳細不明",
  "Screens omitted from diagnosis": "診断から除外された画面",
  "Screens whose diagnosis ended inconclusive — check-execution gaps or unfulfilled plans remain":
    "診断が非確定で終わった画面 — チェック実行の欠落か未消化の計画が残存",
  "Screens whose diagnosis finished WITH recorded check executions; excludes omitted screens":
    "記録されたチェック実行を伴って診断完了した画面（除外画面を除く）",
  "Select a JSON file (YAML / external refs unsupported).":
    "JSON ファイルを選択してください（YAML・外部参照は未対応）。",
  "Selectors (optional — override the adapter's auto-discovery when it misfires)":
    "セレクタ（任意 — アダプタの自動検出が外れた時に上書き）",
  Send: "送信",
  "Send button": "送信ボタン",
  "Session queued; the running diagnosis will apply it shortly":
    "セッションをキューしました — 実行中の診断がまもなく適用します",
  Settings: "設定",
  "Settings categories": "設定カテゴリ",
  "Settings could not be saved.": "設定を保存できませんでした。",
  "Setup check failed. Open Settings → Check connections before starting.":
    "セットアップチェックが失敗しました。開始前に 設定 → 接続チェック を開いてください。",
  "Sign out": "サインアウト",
  "Site tree": "サイトツリー",
  "Specification must be 2 MB or smaller": "仕様ファイルは 2 MB 以下にしてください",
  "Start a new headless authenticated scan of {host} with this session":
    "このセッションで {host} の新規ヘッドレス認証スキャンを開始",
  "Starting…": "起動中…",
  Status: "ステータス",
  Stop: "停止",
  "Survey — map screens & APIs only, no diagnosis":
    "サーベイ — 画面と API のマッピングのみ、診断なし",
  Target: "ターゲット",
  "Target URL *": "ターゲット URL *",
  "Target URL is required": "ターゲット URL は必須です",
  "Target must start with http:// or https:// (e.g. https://{target})":
    "ターゲットは http:// または https:// で始めてください（例: https://{target}）",
  "Target scope": "ターゲットスコープ",
  "Temporary password for {user} — shown once, all their sessions were signed out.":
    "{user} の一時パスワード — 一度だけ表示されます。全セッションはサインアウト済みです。",
  "The Claude subscription CLI needs the `claude` binary on PATH. Choose OpenCodeGo, OrcaRouter, or Other to use an API provider.":
    "Claude サブスクリプション CLI には PATH 上の `claude` バイナリが必要です。API プロバイダを使うには OpenCodeGo・OrcaRouter・Other を選択してください。",
  "The live view appears here while an assessment is running.":
    "アセスメント実行中、ここにライブビューが表示されます。",
  Time: "時刻",
  Total: "合計",
  "Total tokens": "合計トークン",
  "Transcript container": "トランスクリプト領域",
  Type: "種別",
  "Type the target's login URL in the address bar above and press Enter.":
    "上のアドレスバーにターゲットのログイン URL を入力して Enter を押してください。",
  "URL (must be in scope, or tick “extend scope”)":
    "URL（スコープ内必須。または「スコープ拡張」にチェック）",
  "Unsaved changes — discard them?": "未保存の変更があります — 破棄しますか？",
  "Update password": "パスワード更新",
  Updated: "更新日時",
  "Upstream proxy": "上流プロキシ",
  Usage: "使用量",
  "Use an OpenAI-compatible API endpoint, including a local model server.":
    "ローカルのモデルサーバを含む OpenAI 互換 API エンドポイントを使用します。",
  "User management requires the admin role.": "ユーザー管理には admin ロールが必要です。",
  Username: "ユーザー名",
  Users: "ユーザー",
  "Uses the Audit REST URL on the Burp tab (default http://127.0.0.1:1338). Collaborator must be enabled in the Burp project.":
    "Burp タブの Audit REST URL を使用します（既定 http://127.0.0.1:1338）。Burp プロジェクトで Collaborator を有効化してください。",
  Version: "バージョン",
  "Web / API app": "Web / API アプリ",
  "Which manifest role the captured login belongs to": "取得したログインが属するマニフェストロール",
  You: "あなた",
  "a “manual” role makes the run attended — log in via the Sessions tab":
    "「manual」ロールにすると run は有人モードになります — Sessions タブでログイン",
  account: "アカウント",
  "active Burp scan after diagnosis (uses env BURP_API)":
    "診断後に Burp アクティブスキャン（環境変数 BURP_API を使用）",
  "add in-scope host": "スコープ内ホストを追加",
  "added to in-scope requests (WAF bypass / required headers)":
    "スコープ内リクエストに付与（WAF 回避 / 必須ヘッダ）",
  admin: "管理者",
  administrator: "管理者",
  "all ({n})": "すべて（{n}）",
  "applied — takes effect at the next screen": "適用済み — 次の画面から有効",
  "applies immediately, saved on this device": "即座に適用・この端末に保存",
  as: "として",
  auth: "認証",
  "authz comparison {id} → {outcome}": "認可比較 {id} → {outcome}",
  "autonomous web / API pentest agent. AI drives · evidence proves · scans behind login.":
    "自律型 web / API ペンテストエージェント。AI が駆動 · 証跡が証明 · ログインの先もスキャン。",
  "awaiting login": "ログイン待ち",
  blocked: "ブロック",
  "capture failed": "保存に失敗しました",
  "captured {what} for {host} — click Logged in → continue":
    "{host} の {what} を保存しました — 「ログイン済み → 続行」をクリック",
  "captured {what} for {host} — start an authenticated scan below":
    "{host} の {what} を保存しました — 下で認証済みスキャンを開始",
  "chat failed ({status})": "チャット失敗（{status}）",
  "check {checkClass} → {status} ({target}{subject})": "check {checkClass} → {status}（{target}{subject}）",
  "checks models, browser, and Burp before launch (model pings may use quota)":
    "起動前にモデル・ブラウザ・Burp を確認（モデルの ping でクォータを消費する場合あり）",
  claimed: "主張あり",
  "claimed (no records)": "主張あり（記録なし）",
  closed: "クローズ",
  collapse: "折りたたむ",
  "collapse all": "すべて折りたたむ",
  "confirm new password": "新しいパスワード（確認）",
  connected: "接続中",
  "connected — waiting for the scan to drive the browser…":
    "接続済み — スキャンがブラウザを駆動するのを待機中…",
  connecting: "接続中",
  "connecting…": "接続中…",
  "continue failed ({status})": "続行に失敗しました（{status}）",
  "cookie file": "Cookie ファイル",
  "copied Cookie header": "Cookie ヘッダをコピーしました",
  "copied URL": "URL をコピーしました",
  "copy failed": "コピーに失敗しました",
  credentials: "認証情報",
  "current password": "現在のパスワード",
  "derived from recorded check executions": "記録されたチェック実行から導出",
  "desc (e.g. admin)": "説明（例: admin）",
  disconnected: "切断",
  "display name": "表示名",
  "e.g. Focus on the checkout flow and IDOR in /api/orders. Also coupons / price tampering.":
    "例: チェックアウトの流れと /api/orders の IDOR を重点。クーポン・価格改ざんも。",
  "e.g. http://host/Account/AccountMenu  (blank = off)":
    "例: http://host/Account/AccountMenu（空欄 = オフ）",
  "e.g. “Why is f-001 high?” · “Summarize the auth posture” · “Which screens weren’t tested?”":
    "例: 「f-001 が high の理由は？」「認証状況をまとめて」「どの画面が未テスト？」",
  "eTLD+1 — seed domain + subdomains": "eTLD+1 — シードドメイン＋サブドメイン",
  endpoint: "エンドポイント",
  endpoints: "エンドポイント",
  "entry URL for manual login windows (attended). blank = target URL.":
    "手動ログインウィンドウ（attended）の入口 URL。空欄 = ターゲット URL。",
  "evidence ({n})": "証跡（{n}）",
  excluded: "除外",
  expand: "展開",
  "expand all": "すべて展開",
  "extend scope to this host — only if it is within your authorization":
    "このホストへスコープ拡張 — あなたの認可範囲内の場合のみ",
  "failed ({status})": "失敗（{status}）",
  fallback: "フォールバック",
  "filter text…": "テキスト絞り込み…",
  findings: "検出",
  "follow links": "リンクを辿る",
  gated: "ゲート済み",
  generate: "生成",
  "goto-safe authed hub (the app menu). for sites where deep routes die on a direct/cold navigation: a route that bounces to an error page is reached by clicking its link from here instead, and this becomes the keepalive target. blank = off (unchanged).":
    "認証済みの安全なハブへ移動（アプリのメニュー画面）。直接/コールド遷移で深いルートが死ぬサイト向け: エラーページへ飛ばされるルートはここからリンククリックで到達し、keepalive 対象にもなります。空欄 = オフ（変更なし）。",
  handoffs: "ハンドオフ",
  "headed (debug)": "headed（デバッグ）",
  "headed window": "headed ウィンドウ",
  "header name (e.g. X-Forwarded-For)": "ヘッダ名（例: X-Forwarded-For）",
  "headless scan browser — blank = installed Chrome/Edge":
    "ヘッドレススキャンブラウザ — 空欄 = インストール済み Chrome/Edge",
  "high-value diagnosis / scenario": "高価値の診断 / シナリオ",
  "hostname or URL — blank with Interactsh selected = oast.pro":
    "ホスト名または URL — Interactsh 選択時の空欄 = oast.pro",
  "how many screens to diagnose (default 120). raise for large apps.":
    "診断する画面数（既定 120）。大規模アプリでは引き上げ。",
  "https://app.example.com/login  — navigate the live session here (blank-screen recovery)":
    "https://app.example.com/login — ライブセッションをここへ遷移（白画面からの復帰）",
  "if set, only paths matching one of these prefixes are scanned":
    "設定時、このプレフィックスのいずれかに一致するパスのみスキャン",
  "import list": "リストをインポート",
  "inconclusive (check gaps)": "非確定（チェック欠落）",
  input: "入力",
  "keepalive interval (minutes). touches a safe authed page (never /) to keep the session warm. set 0 to turn off for sites whose session dies on a cold / hit or a full reload.":
    "keepalive 間隔（分）。安全な認証済みページ（/ 以外）へアクセスしてセッションを維持。/ へのコールドアクセスやフルリロードでセッションが死ぬサイトでは 0 でオフ。",
  "launch failed ({status})": "起動失敗（{status}）",
  "live — watching the scan browser": "ライブ — スキャンブラウザを観測中",
  "load a URL list from a file (CSV: first column, or one URL per line)":
    "ファイルから URL リストを読み込み（CSV: 先頭列、または 1 行 1 URL）",
  "loading …": "読み込み中 …",
  "logged in": "ログイン済み",
  "login URL (optional)": "ログイン URL（任意）",
  manual: "手動",
  map: "マップ",
  "max depth": "最大深度",
  "max replays": "最大リプレイ数",
  "max screens": "最大画面数",
  method: "メソッド",
  "minimum delay between HTTP requests (politeness throttle)":
    "HTTP リクエスト間の最小遅延（ポリットネススロットル）",
  "model tiering: high-value screens use the deep model, survey/methodology/low-value screens use this fast model":
    "モデル階層化: 高価値画面は deep モデル、survey/methodology/低価値画面はこの fast モデルを使用",
  name: "名前",
  "navigate the live session browser here — use this to recover from a blank/stuck page":
    "ライブセッションのブラウザをここへ遷移 — 白画面・スタックからの復帰用",
  "needs a REST or Audit endpoint below": "下記の REST または Audit エンドポイントが必要",
  "never scanned — unless an allowed prefix above also matches it":
    "スキャンしない — 上の許可プレフィックスにも一致する場合を除く",
  "new password (12+ chars)": "新しいパスワード（12 文字以上）",
  "no http(s) URLs found in the file": "ファイルに http(s) URL が見つかりません",
  "no launch input ({status})": "起動入力がありません（{status}）",
  "no screens yet — run a crawl": "画面はまだありません — クロールを実行してください",
  "no screenshot — backfill with": "スクリーンショットなし — 補填:",
  "no valid baseline": "有効なベースラインなし",
  "not streaming — the scan is not running (start or resume it to watch live)":
    "ストリーミングしていません — スキャンが停止中（開始または再開するとライブ表示）",
  "nothing to apply — set a rate, max-screens, or a host":
    "適用する変更がありません — レート・最大画面数・ホストのいずれかを設定",
  "one per line": "1 行に 1 件",
  "one per line (blank = all in-scope paths)": "1 行に 1 件（空欄 = スコープ内全パス）",
  "only for a protected / self-hosted server": "保護された / セルフホストサーバのみ",
  open: "開く",
  "open a real browser window on the runner — only useful when running locally with a display":
    "ランナー上に実ブラウザウィンドウを開く — ディスプレイ付きのローカル実行時のみ有効",
  "open in browser (log in / watch in the Sessions tab)":
    "ブラウザで開く（Sessions タブでログイン / 監視）",
  operation: "オペレーション",
  "operator --focus, injected as the top priority of the scenario stage":
    "operator --focus — シナリオステージの最優先事項として注入",
  "operator focus — injected as the TOP priority of the scenario (A04) stage, not per-screen diagnosis. emphasis, not exclusive (full coverage still runs).":
    "オペレーターフォーカス — シナリオ（A04）ステージの最優先事項として注入（画面ごとの診断ではありません）。強調であり排他ではありません（フルカバレッジは継続）。",
  "operator — full access": "operator — フルアクセス",
  password: "パスワード",
  "password (12+ chars)": "パスワード（12 文字以上）",
  "pasted {n}": "{n} 件を貼り付けました",
  pause: "一時停止",
  "4 · 1 = sequential": "4 · 1 = 逐次",
  "concurrent diagnosis workers — one per role with session material + one unauth (default 4, max 8). each worker is bound to its own session; cross-role checks still run. set 1 for the sequential loop.":
    "診断の並列ワーカー数 — セッション情報を持つロールごとに1ワーカー + 未認証ワーカー（デフォルト4、最大8）。各ワーカーは自セッションにバインドされ、ロール間チェックもそのまま実行。1 で従来の逐次ループ。",
  "Parallel workers": "並列ワーカー数",
  paused: "一時停止中",
  pending: "保留",
  phase: "フェーズ",
  plan: "計画",
  "plan slot(s) with no satisfying terminal execution": "対応する終端実行のない計画スロット",
  planned: "計画済み",
  "queued {url} — diagnoses now if the run is active, otherwise on the next Resume":
    "{url} をキューしました — run が稼働中なら即診断、停止中なら次回 Resume 時",
  "rate ms": "レート ms",
  repro: "再現",
  resource: "リソース",
  resume: "再開",
  role: "ロール",
  "route all traffic through the Burp proxy (uses env BURP_PROXY)":
    "全トラフィックを Burp プロキシ経由に（環境変数 BURP_PROXY を使用）",
  "run {id}": "run {id}",
  running: "実行中",
  "same-origin — exact host only": "同一オリジン — 完全一致ホストのみ",
  "saved — applies to the next run": "保存しました — 次の run に適用",
  "scan status said clean — {gaps} check gap(s), {unfulfilled} unfulfilled plan slot(s) remain":
    "スキャンは clean と主張 — ただしチェック欠落 {gaps} 件・未消化計画 {unfulfilled} 件が残存",
  "scan status {status} recorded without structured check executions — coverage detail unknown (legacy run or log note; no evidence records).":
    "スキャンステータス {status} が構造化チェック実行なしで記録 — カバレッジ詳細不明（旧形式の run またはログノート、証跡記録なし）。",
  "scans behind login (recommended)": "ログインの先をスキャン（推奨）",
  "screencast the chat into the Sessions tab: log into the chatbot manually, then click Done to start the probes":
    "チャットを Sessions タブへ中継: チャットボットへ手動ログイン後、Done を押してプローブ開始",
  screens: "画面",
  screenshot: "スクリーンショット",
  script: "スクリプト",
  secrets: "シークレット",
  "self-reported note — no structured check records; detail unknown":
    "自己申告ノート — 構造化チェック記録なし、詳細不明",
  session: "セッション",
  "show the automation browser window (headless off) — for debugging. In the desktop app, open the Live tab to watch the scan instead, so this is hidden.":
    "自動化ブラウザのウィンドウを表示（ヘッドレス解除）— デバッグ用。デスクトップアプリでは代わりに Live タブでスキャンを見るため非表示。",
  "sign out": "サインアウト",
  size: "サイズ",
  "status claim — no check records (detail unknown)": "ステータス主張 — チェック記録なし（詳細不明）",
  "survey / methodology / low-value": "survey / methodology / 低価値",
  "survey role {role}: {state}{reason}": "survey ロール {role}: {state}{reason}",
  suspected: "疑いあり",
  "target facts — pre-fills New; editable per run":
    "ターゲットの事実 — New に事前入力、run ごとに編集可",
  tenant: "テナント",
  tested: "テスト済み",
  "tested, findings": "テスト済み・検出あり",
  "tested, no findings": "テスト済み・検出なし",
  "tested, unconfirmed leads": "テスト済み・未確認の手がかりあり",
  "the VERDICT Burp Audit extension, e.g. http://127.0.0.1:1338":
    "VERDICT Burp Audit 拡張、例: http://127.0.0.1:1338",
  "the browser 401 dialog, before the app's own login":
    "ブラウザの 401 ダイアログ（アプリ独自ログインの手前）",
  tokens: "トークン",
  type: "種別",
  unfinished: "未完了",
  "unrestricted — any host (⚠ may leave the program)":
    "無制限 — 任意ホスト（⚠ プログラム範囲外に出る可能性）",
  unverified: "未検証",
  user: "ユーザー",
  username: "ユーザー名",
  value: "値",
  "viewer — read-only": "viewer — 読み取り専用",
  "waiting for login": "ログイン待ち",
  yes: "はい",
  "{action} evidence {id}": "{action} 証跡 {id}",
  "{id} screenshot": "{id} スクリーンショット",
  "{id}: {from} → {to}": "{id}: {from} → {to}",
  "{label} failed — {reason}": "{label} 失敗 — {reason}",
  "{n} candidate(s)": "{n} 件の候補",
  "{n} cookie(s)": "{n} 個の Cookie",
  "{n} finding(s) inside": "検出 {n} 件を含む",
  "{n} localStorage key(s)": "{n} 個の localStorage キー",
  "{n} low": "low {n} 件",
  "{owner} (you)": "{owner}（あなた）",
  "{status} (no records)": "{status}（記録なし）",
  "— none (single model)": "— なし（単一モデル）",
  "… thinking": "… 思考中",
  "← Select a screen from the tree.": "← ツリーから画面を選択してください。",
  "→ navigating to {url}": "→ {url} へ遷移中",
  "⏳ importing {name}…": "⏳ {name} をインポート中…",
  "⏸ paused": "⏸ 一時停止",
  "■ halted: {reason}": "■ 停止: {reason}",
  "▶ now:": "▶ 現在:",
  "▶ resumed": "▶ 再開",
  "▷ phase {from} → {to}": "▷ フェーズ {from} → {to}",
  "▷ request": "▷ リクエスト",
  "◁ res": "◁ 応答",
  "● assessment created": "● アセスメント作成",
  "★ finding {id}": "★ 検出 {id}",
  "⚠ handoff requested ({reason})": "⚠ ハンドオフ要求（{reason}）",
  "✅ done sent — agent continues": "✅ done 送信 — エージェント続行",
  "✓ handoff resolved": "✓ ハンドオフ解決",
  "✓ importing — net-new findings appear, High+ get AI re-verified":
    "✓ インポート中 — 新規検出が追加され、High 以上は AI 再検証",
  "🎯 Operator focus:": "🎯 オペレーターフォーカス:",
};

export function LangProvider({ children }: { children: ReactNode }) {
  const [lang, setLangState] = useState<Lang>(initialLang);
  const value = useMemo(
    () => ({
      lang,
      setLang: (l: Lang): void => {
        setLangState(l);
        try {
          window.localStorage.setItem(LS_KEY, l);
        } catch {
          /* storage unavailable */
        }
      },
      t: ((s: string, vars?: Record<string, string | number>): string => {
        let out = lang === "ja" ? (JA[s] ?? s) : s;
        if (vars) for (const [k, v] of Object.entries(vars)) out = out.replaceAll(`{${k}}`, String(v));
        return out;
      }) as T,
    }),
    [lang],
  );
  return <LangCtx.Provider value={value}>{children}</LangCtx.Provider>;
}

/** Translate a canonical English UI string. `{name}` placeholders interpolate via vars. */
export function useT(): T {
  return useContext(LangCtx).t;
}

export function useLang(): { lang: Lang; setLang: (l: Lang) => void } {
  const c = useContext(LangCtx);
  return { lang: c.lang, setLang: c.setLang };
}

/** Shared language selector — used by the web Settings pane and the desktop Settings view. */
export function LanguageSelect({ id = "display-language" }: { id?: string }) {
  const { lang, setLang } = useLang();
  return (
    <NativeSelect id={id} value={lang} onChange={(e) => setLang(e.target.value as Lang)} className="w-44">
      {LANG_CHOICES.map((l) => (
        <option key={l.value} value={l.value}>
          {l.label}
        </option>
      ))}
    </NativeSelect>
  );
}

export { JA as JA_DICT };
