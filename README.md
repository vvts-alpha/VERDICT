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

`scope_manifest.example.json` を参照。資格情報を含む実ファイルは gitignore すること。

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
      { "name": "alice", "pass": "..." },
      { "name": "bob",   "pass": "..." }
    ]
  }
}
```

- **認証は資格情報だけでよい** — ログイン URL・フォーム項目はエージェントが自動発見(`smartLogin`)。MFA/CAPTCHA で詰まったら headed ブラウザで人手フォールバック(`detectStuck` が非ブロッキングで起票)。**Cookie/トークンは注入しない。**
- `auth.roles[0]` = 主ログイン、複数 role = クロスユーザ/auth-diff のソース。
- `--url <url>` で manifest 無し起動も可(scope は同一オリジン導出、認証なし)。

---

## コマンド

| コマンド | 用途 |
|---|---|
| **`pilot`** | Claude 主導アセスメント(full)。`--manifest` / `--url`、`--model`、`--max-turns`、`--rate`、`--headed`、`--browser-path`、`--no-sandbox`、`--burp-proxy <url>` |
| `pilot --survey-only` | **調査のみ**: 画面マップ+スクショ+API だけ。診断/finding はしない(安い recon、後で `--resume`) |
| `pilot --resume --id <id>` | 既存 run の**未診断(queued)画面だけ**診断(落ちた run の仕上げ / survey-only の続き) |
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

**C. Burp 連携(任意・フラグ式)** — `--burp-proxy` を付けない限り挙動は不変
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
- **認証 = 資格情報のみ、Cookie 注入しない**。MFA/CAPTCHA は `detectStuck` → 非ブロッキング HumanHandoff(headed で人手)。
- **状態は append-only + 再生可能**。UI は純投影(`buildStateView` / `buildSiteTree`)。

> 状態: ステージ型 Claude 主導 pilot(調査→方法論→診断)+ 決定論 assess、WebUI 観測、Burp/header 連携、survey-only/resume モード — すべて実装・実機検証済み。`pnpm -r test` は緑。
