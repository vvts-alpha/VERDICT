# Umbra Hands — autonomous web/API pentest agent

Claude 主導の自律 Web/API ペネトレーションテスト・エージェント。TypeScript の pnpm モノレポ。設計の源泉は [`DESIGN.md`](./DESIGN.md)。

> ⚠️ **認可済みターゲット専用。** すべてのネットワーク操作は scope ゲート(`isInScope`)を通り、スコープ外は拒否される。`--url` は同一オリジン + 配下を既定スコープに導出。manifest で明示スコープを与える。

---

## これは何か

2 つの実行モードが 1 つの基盤(`@veritas/core` の状態ストア)を共有する:

- **`pilot`(Claude 主導・推奨)** — Claude が tool-use ループでツール(browser / http / login / record …)を操縦し、自律的に **調査 → 方法論 → 診断** の 3 ステージで回す。
  - **調査**: 画面を巡回してマップ(screens + スクショ + API 抽出)。frontier を消し切るまで + 各 role でログイン。
  - **方法論**: 全画面の一覧から、画面ごとに「どの脆弱性クラスをどう試すか」を立てる。
  - **診断**: **1 画面ずつ**バウンドした文脈で検証。カバレッジ台帳が全画面を潰し切る(取りこぼし防止)。
  - **証拠規律**: confirmed = 陰性コントロール(失敗すべき要求が失敗)+ 2 回以上の positive replay。catch-all 200 / 0-byte / ログインリダイレクトは成功扱いしない。
  - finding は `(カテゴリ × エンドポイント × param)` で**重複排除**(横断エンドポイントの過剰報告を束ねる)。
- **`assess`(決定論・一括)** — crawl → label → scan → logic → report を固定パイプラインで実行。粒度が細かく検査しやすい。

LLM は **`claude` CLI(Max サブスク認証)**を使う。従量 API キーは不要。

---

## 動作フロー

```
manifest (scope + 認証)
   │
   ├── pilot   ── Claude 主導 ── survey → methodology → diagnosis → report
   └── assess  ── 決定論一括   ── crawl → label → scan → logic → report
```

`pilot` の中身(各ステージ = 1 回の `query()`。Claude が下のツールを操縦する):

```
pilot --manifest scope_manifest.json
│
├─ 0. 起動
│     └─ manifest 読込 → scope ゲート構築(isInScope)→ 状態ストア(state.sqlite)初期化
│
├─ 1. 調査  survey ……………… 1× query()  〔fast-model〕
│     ├─ browser_navigate / fill / click … 画面を巡回してマップ
│     ├─ login(role) ……………………… 資格情報→smartLogin / cookieFile→注入
│     ├─ probe_paths ………………………… 既知パス当て
│     └─ survey_done ………………………… frontier(未訪問)が空で確定
│           └─▶ Screen[] + スクショ + API 抽出 を永続化
│
├─ 2. 方法論  methodology …… 1× query()  〔fast-model〕
│     ├─ get_inventory ……………………… 全画面の一覧
│     └─ record_methodology ………… 画面ごとに「どのクラスをどう試すか」立案
│           └─▶ plan を各 screen に紐付け
│
├─ 3. 診断  diagnosis ………… 1 画面 = 1× query()  〔高価値画面のみ deep-model〕
│     │     ※ 画面の合間に keepalive(トップへ navigate + cookie 再同期)
│     ├─ get_screen ………………………… 詳細 + plan を取得
│     ├─ http_request / probe_params … 検証トラフィック
│     ├─ verify_access ………………………… auth-bypass の機械 veto(302/401/403/login body は HARD veto)
│     ├─ analyze_session …………………… cookie の構造・予測可能性を解析
│     └─ record_finding ─────────┐
│           証拠規律: 陰性コントロール失敗 + 2× positive replay でのみ confirmed
│           catch-all / 0-byte-200 / login-redirect は refuted
│           (カテゴリ × エンドポイント × param)で dedup
│           └─▶ EvidenceStore に req/resp 全体(request.http.txt)を保存
│
└─ 4. レポート
      └─ buildReport → runs/<id>/report.md

   （全工程を通して WebUI が events ログを購読し、SITE TREE / 進捗 / findings をライブ投影）
```

モード差分:
- `--survey-only` … **1 で停止**(map だけ。診断/finding なし)。後で `--resume` に繋ぐ。
- `--resume --id <id>` … **1・2 をスキップ**し、3 を未診断(非 terminal)画面だけで再開。
- `--burp-proxy <url>` … 全 HTTP+ブラウザ通信を Burp 経由(off で挙動不変)。スキャン後 `burp-import` で net-new を merge。

---

## 前提・セットアップ

- **Node.js >= 24**(状態ストアに組み込み `node:sqlite` を使用。native 依存なし)。`nvm use 24`。
- **pnpm**(corepack): `corepack enable pnpm`(pin `pnpm@9.15.4`)。
- **Chromium**(Playwright 用): `npx playwright install chromium`、または `--browser-path <bin>` / 環境変数 `VERITAS_BROWSER_PATH` で既存バイナリを指定。コンテナ/root では `--no-sandbox`。

```bash
cd NewAgent
pnpm install
pnpm -r build        # 全パッケージを依存順にビルド(webui の Vite ビルド含む)
pnpm -r test         # node:test(外部ネット/LLM 不要、Fake で完結)
```

> ブラウザパスは一度 `export VERITAS_BROWSER_PATH=/path/to/chrome` しておけば、各コマンドで `--browser-path` を省略できる。`--no-sandbox` はサンドボックスが通らない環境(コンテナ/root)でだけ付ける。

---

## クイックスタート

```bash
# 1) 観測 WebUI を起動(別ターミナル)
node packages/cli/dist/main.js serve --host 0.0.0.0
#    → http://127.0.0.1:4317/ をブラウザで開く(?id 無しなら最新 run を自動追従)

# 2) Claude 主導アセスメント(manifest に scope + 認証)
node packages/cli/dist/main.js pilot --manifest scope_manifest.json --model claude-sonnet-4-6
```

WebUI で **SITE TREE / Screen(スクショ+API+findings)/ Findings / APIs / 診断ログ**がリアルタイムに埋まる。終了後 `runs/<id>/report.md` が生成される。

---

## manifest(scope + 認証)

手書きするなら `scope_manifest.example.json` を参照。対話型で作るなら:

```bash
node packages/cli/dist/main.js manifest          # 質問に答えると scope_manifest_<host>.json を生成
node packages/cli/dist/main.js manifest --out m.json
```

資格情報を含む実ファイルは gitignore すること(生成名 `scope_manifest_*.json` は既に対象)。

```json
{
  "target": "https://app.example.com/",
  "scope": {
    "inScopeHosts": ["app.example.com"],
    "outOfScopePathPrefixes": ["/logout"],
    "rate": { "requestsPerMinute": 30, "maxConcurrent": 2 }
  },
  "crawl": { "followLinks": true, "maxDepth": 8 },
  "model": "claude-sonnet-4-6",
  "auth": {
    "roles": [
      { "name": "alice", "pass": "...", "description": "全権管理者" },
      { "name": "bob",   "pass": "...", "description": "一般ユーザ(読取のみ)" },
      { "name": "carol", "cookieFile": "carol.cookies" }
    ]
  }
}
```

- **認証は資格情報だけでよい** — ログイン URL・フォーム項目はエージェントが自動発見(`smartLogin`)。`auth.roles[0]` = 主ログイン、複数 role = クロスユーザ/auth-diff のソース。
- **`description`(任意)で権限レベルを添える** — 例 `"全権管理者"` / `"一般ユーザ(読取のみ)"`。エージェントの `login`/`get_screen` に渡り、auth-diff で「どれが高権限/低権限か(=境界越えの方向)」を判断する材料になる。秘密ではないが state には永続しない。
- **事前取得 Cookie でもよい** — 自動ログインできない壁(Arkose/MFA 等)向けに、role に `cookieFile`(または `cookie_file_path`)を指定できる。中身は **生 `Cookie:` ヘッダ(`sid=…; foo=…`)** か **Playwright `storageState` JSON** のどちらでも可(自動判別)。`login(role)` がそれを **ブラウザ + http セッションに注入**してログインを省く。**Cookie ファイルはセッション秘密 → 必ず gitignore(`*.cookies` 等)。** エージェントが Cookie を捏造/盗むのではなく、operator が供給する点は不変。
- MFA/CAPTCHA で Cookie も無ければ headed ブラウザで人手フォールバック(`detectStuck` が非ブロッキングで起票)。
- `auth.roles[0]` = 主ログイン、複数 role = クロスユーザ/auth-diff のソース。
- `--url <url>` で manifest 無し起動も可(scope は同一オリジン導出、認証なし)。

---

## コマンド

| コマンド | 用途 |
|---|---|
| `manifest`(別名 `init`) | **対話型 scope-manifest ジェネレータ**: 質問に答えるだけで manifest JSON を生成(target / in・out-of-scope hosts・path / rate / crawl / model / 認証ロール)。`--out <file>` で出力先指定、password はエコー伏字。生成名 `scope_manifest_<host>.json` は gitignore 済み |
| **`pilot`** | Claude 主導アセスメント(full)。`--manifest` / `--url`、`--model`、`--max-turns`、`--rate`、`--headed`、`--browser-path`、`--no-sandbox`、`--burp-proxy <url>`、`--keepalive-min <n>`(認証セッション維持: 画面の合間にトップへ navigate して cookie 再同期。既定 4 分、`0` で無効) |
| `pilot --survey-only` | **調査のみ**: 画面マップ+スクショ+API だけ。診断/finding はしない(安い recon、後で `--resume`) |
| `pilot --resume --id <id>` | 既存 run の**未診断(queued)画面だけ**診断(落ちた run の仕上げ / survey-only の続き) |
| `pilot --attended` | **手動マルチセッション認証**(headed 必須)。ロールごとに永続コンテキストを開き、人手でログイン(CAPTCHA/MFA/Arkose 突破)→ Enter 確認 → 生きたセッションで調査・診断。`login(role)` は再ログインせず**そのロールのライブセッションへ切替**。合間に全ロールを keepalive(失効=ログイン画面に戻されたら再ログインを要求)。`--login-url <u>`(手動ログインの入口、既定 target)/ `--keepalive-min <n>`(既定 1 分)。自動ログイン/Cookie ファイルで越えられない壁向け |
| `assess` | 決定論パイプライン一括: crawl → label → scan → logic → report |
| `serve` | 観測 WebUI + 状態 API/WS(既定 `127.0.0.1:4317`、LAN 公開は `--host 0.0.0.0`) |
| `report` / `status` / `list` | report.md 生成 / phase・coverage・stop 判定 / `runs/` 一覧 |
| `shots --id <id>` | 既存 run の各画面スクショを backfill(run の認証済プロファイル再利用・ナビゲートのみ) |
| `header-audit --id <id>` | Info 系: レスポンスヘッダ監査(CSP/HSTS/XFO/…)。`--headers csp,hsts,…` で絞る。トグル=走らせる/走らせない |
| `burp-import --id <id> --report <xml>` | Burp Pro の XML レポートを取り込み、既存と重複しない net-new だけ finding 追加 |
| `run` / `crawl` / `label` / `scan` / `logic` | 決定論パイプラインの個別ステップ(`assess` の中身) |

`node packages/cli/dist/main.js <command>`(ビルド済)または `pnpm --filter @veritas/cli dev <command>`(tsx、src 解決)。全コマンドは `--out <dir>`(既定 `runs`)を取る。

---

## ワークフロー

**A. ふつうのアセスメント**
```bash
node packages/cli/dist/main.js serve --host 0.0.0.0          # 観測
node packages/cli/dist/main.js pilot --manifest m.json       # 別ターミナルで診断
```

**B. map now / diagnose later**(安い recon → 後で診断)
```bash
node packages/cli/dist/main.js pilot --survey-only --manifest m.json   # ① 全面マップだけ
#   WebUI で SITE TREE / スクショ / API を眺めて判断
node packages/cli/dist/main.js pilot --resume --id <run-id> --manifest m.json   # ② queued だけ診断
```

**C. 手動マルチセッション認証(attended)** — CAPTCHA/MFA/Arkose・絶対TTL 失効など 自動ログインで越えられない壁向け
```bash
# ロールごとに headed の窓が開く → 各窓で人手ログイン → ターミナルで Enter
node packages/cli/dist/main.js pilot --attended --manifest m.json
#   --login-url <u> で手動ログインの入口を指定(既定 target)。--keepalive-min n で維持間隔(既定 1 分)。
#   診断中に login(role) すると、再ログインせず そのロールのライブセッションへ切替。
#   セッションが切れた(ログイン画面に戻された)ら、その窓で再ログインして Enter。
```

**D. Burp 連携(任意・フラグ式)** — `--burp-proxy` を付けない限り挙動は不変
```bash
# Burp Pro の Proxy リスナを起動(別端末なら All interfaces に bind)
node packages/cli/dist/main.js pilot --manifest m.json --burp-proxy http://127.0.0.1:8080
#   → 全 HTTP+ブラウザ通信が Burp 経由(TLS は検証スキップ、Burp CA 不要)
# Burp でスキャン → レポートを XML で export →
node packages/cli/dist/main.js burp-import --id <run-id> --report burp.xml
#   → Burp の net-new(ヘッダ/脆弱JS/バージョン開示 等)だけ finding に merge(重複は弾く)
```

**D. Info 系を足す(Burp 無しの軽量版)**
```bash
node packages/cli/dist/main.js header-audit --id <run-id>            # 既定リスト
node packages/cli/dist/main.js header-audit --id <run-id> --headers csp,hsts
```

役割分担: **エージェント = 創発的ロジック**(IDOR 連鎖・マスアサイン・business logic)/ **Burp = 網羅パッシブ+能動**。重複は `burp-import` が排除する。

---

## WebUI(`serve`)

ターゲット 1 つ = 1 ページで完結。左 **SITE TREE**(URL 階層 + スキャン状態バッジ)、上部 **進捗バー**(scan 内訳 + 今診断中の画面)、右はタブ:

- **Screen** — ツリーで選んだ 1 画面: 大スクショ → 概要 → APIs/params → その画面の findings。
- **Findings** — 全 finding(severity フィルタ + screenId クリックで画面ジャンプ)。各 finding の **evidence をクリックで req/resp を展開**(headers マスク済)。
- **APIs** — 全画面の API を横断集約(method+endpoint+auth+参照画面)。
- **診断ログ** — Claude の思考 / probe / plan / FINDING / phase 遷移を新しい順に live 表示。

最小操作: pause/resume、画面 exclude、handoff resolve(WS push で即反映)。

---

## パッケージ構成

依存は下方向に流れる。共有契約型は `@veritas/core` のみに集約する(内部パッケージ名は `@veritas/*` のまま)。

| パッケージ | 役割 |
|---|---|
| `@veritas/core` | 契約型 + SQLite ストア(作業記憶 = UI データソース)+ カバレッジ台帳 + ツリー/状態投影 + scope + 予算/停止 + `buildReport` |
| `@veritas/crawler` | Playwright ドライバ(永続コンテキスト/傍受/プロキシ)+ 純パイプライン(正規化/dedup/ラベリング/`smartLogin`/`detectStuck`) |
| `@veritas/llm` | `ClaudeCliClient`(サブスク認証 `claude -p`)+ Fake + zod 構造化出力 |
| `@veritas/scanner` | `EvidenceStore` / `FetchHttpClient`(scope ゲート+プロキシ)/ 証拠規律 / validator カタログ / header 監査 / Burp レポート解析 |
| `@veritas/agent` | ビジネスロジック: 仮説生成 + IDOR 検証 + auth-diff(マルチロール) |
| `@veritas/pilot` | **Claude 主導ループ**(Agent SDK の in-process MCP ツール + 3 ステージ・オーケストレータ) |
| `@veritas/server` / `@veritas/webui` | 状態 API + WebSocket / React 観測 UI(core は型のみ import) |
| `@veritas/cli` | 全コマンドのオーケストレーション |

---

## 不変条件(壊さないこと)

- **scope ゲートは全ネットワーク操作に**。out-of-scope は例外でなくブロック。
- **証拠規律**: confirmed = 陰性コントロール + 2 positive replays。catch-all / 0-byte-200 / 不安定は refuted。手で confirmed にしない。
- **LLM = `claude` CLI サブスク**(従量 API 不使用)。テストは `FakeLlmClient`。
- **認証 = operator 供給の資格情報 OR 事前 Cookie ファイル**(`smartLogin` / `loadCookieFile`)。エージェントは Cookie を捏造/盗まない。MFA/CAPTCHA で Cookie も無ければ `detectStuck` → 非ブロッキング HumanHandoff(headed で人手)。
- **状態は append-only + 再生可能**。UI は純投影(`buildStateView` / `buildSiteTree`)。

> 状態: ステージ型 Claude 主導 pilot(調査→方法論→診断)+ 決定論 assess、WebUI 観測、Burp/header 連携、survey-only/resume/attended(手動マルチセッション)モード — すべて実装・実機検証済み。`pnpm -r test` は緑。
