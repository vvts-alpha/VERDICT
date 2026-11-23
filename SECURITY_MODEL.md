# VERDICT 脅威モデル

参照: `SECURITY.md`（脆弱性報告方針・認可済み利用のみ）、`DESIGN.md`、`CLAUDE.md`。インフラ用リポジトリ（Terraform/Kubernetes 等）は存在しない。配布物は Windows 向け Electron デスクトップアプリで、サーバーはローカルで動作する。

## 1. システム概要と信頼境界

VERDICT は認可済みの Web/API ターゲットを診断する攻撃ツール。オペレーターが対象 URL・スコープ・認証情報を与え、LLM 主導のエージェントが対象サイトをブラウザ（Playwright/Chromium）と HTTP で探索・攻撃し、証拠付き findings をローカルの SQLite に記録する。

主な信頼境界:
1. **診断対象サイト ↔ VERDICT**（最重要）: 対象サイトのレスポンス・DOM・JS・リダイレクト・ヘッダはすべて攻撃者制御の可能性がある。これが crawler / scanner / pilot / LLM プロンプト / SQLite / WebUI / レポート (HTML/PDF/MD/CSV) へ流れ込む。
2. **LLM 出力 ↔ ツール実行**: 対象サイト由来の文字列が LLM コンテキストに入り、LLM が MCP ツール（`http_request`、`probe_*`、`browser_*`）を呼ぶ。プロンプトインジェクションでスコープ外アクセスや破壊的操作を誘導されうる。最終防壁はスコープゲート `isInScope`（`packages/core/src/scope-check.ts`）。
3. **ブラウザ/他ローカルプロセス ↔ ローカルサーバー**: `@veritas/server` は 127.0.0.1 の空きポートで HTTP/WS を提供。デスクトップではメインプロセスが `x-verdict-token` を全リクエストに付与（`apps/desktop/src/main.ts`）、`isTrustedRequest`（Host/Origin/Sec-Fetch-Site 検証で DNS rebinding・CSRF 防止、`packages/server/src/request-security.ts`）。Host 名は bind 先・localhost・（ワイルドカード bind 時は）ローカルインターフェース IP・`--allowed-host` 指定名のみ許可。
4. **ネットワーク利用者 ↔ `serve --host 0.0.0.0`**: CLI の `serve` は LAN 公開可能。認証はパスワード 2 ロール（operator/viewer、HMAC Cookie、`auth.ts`）または `--multi-user`（scrypt、セッション DB、run 所有者ゲート、監査ログ、`server.ts`/`users-db.ts`）。ループバック以外への認証なし公開は `--allow-unauthenticated` の明示指定がない限り起動を拒否する。サーバー経由で起動する run の `options.wordlist` は同梱 ID（`standard`/`extended`）のみ、manifest の `cookieFile` は呼び出し元が所有する run ディレクトリ内の実ファイルのみ許可（`launch-paths.ts`、違反は 400）。デスクトップ（起動トークン付き・単一ユーザー）はローカルパス指定を維持。
5. **Electron レンダラー ↔ メインプロセス**: `contextIsolation: true`、`nodeIntegration: false`、preload の `verdictDesktop` ブリッジ（設定 get/set、ファイル選択、埋め込みブラウザ操作、セッション取得）。埋め込みブラウザ（`attended-browser.ts`）は別パーティションで対象サイトを表示し、証明書エラーを無視する。
6. **サーバー ↔ CLI 子プロセス**: `Supervisor` が `spawn` で CLI を起動（引数配列、シェルなし）。マニフェスト・オプションは run ディレクトリに保存。

## 2. コンポーネント

| 名前 | コード | 説明 |
|---|---|---|
| Desktop | `apps/desktop/` | Electron シェル、設定保存、埋め込みブラウザ、IPC |
| Server | `packages/server/` | ローカル HTTP/WS API、認証、run 管理、Supervisor、LiveHands relay |
| WebUI | `packages/webui/`, `apps/desktop/renderer/` | React UI。findings・証拠・対象サイト由来データを表示 |
| Engine | `packages/pilot/`, `packages/agent/`, `packages/scanner/`, `packages/crawler/`, `packages/llm-attacks/`, `packages/llm/` | 対象サイトとの通信、LLM エージェント、プローブ、証拠規律、スコープ適用 |
| Core | `packages/core/` | 契約型、SQLite ストア、スコープゲート、レポート生成 (`report*.ts`) |
| CLI | `packages/cli/` | コマンド群、manifest、env 読み込み |
| Tooling | `tools/`（Burp 拡張 Java、リリーススクリプト）, `.github/` | リリース・CI・Burp Audit REST 拡張 |

## 3. エントリーポイント

- 対象サイトの HTTP レスポンス、HTML/JS、リダイレクト、Cookie、WebSocket、OOB コールバック（Interactsh/Collaborator）
- ローカル HTTP API `/api/*`、`/ws/*`、静的配信（`serveStatic`）、`/auth`・`/api/auth/login`
- LiveHands relay `/ws/agent?id=&token=`（子プロセスの逆接続、トークン認証）
- Electron IPC（`settings:*`、`attbrowser:*`、`dialog:pick-file`）
- インポート: Burp XML (`burp-import`)、OpenAPI spec (`spec-import`)、manifest JSON
- Burp Audit REST 拡張（`tools/burp-audit-ext`、トークン付き）

## 4. 資産

- オペレーター端末の完全性（任意コード実行されないこと）
- API キー・トークン: LLM（`apiKey`）、Burp、Interactsh（`settings.ts` で userData の JSON に平文保存、`.env`）
- 対象サイトのセッション/認証情報: manifest の role 資格情報、取得済み Cookie・localStorage（`attended_session_*.json`、`browser-profile/`）
- 診断結果・証拠（req/resp、スクリーンショット、レポート）— 顧客の脆弱性情報を含む機密
- スコープゲートの健全性（許可外システムへ攻撃しないこと＝法的リスク）
- multi-user 時のアカウント・run 所有権の分離

## 5. 想定攻撃者

- **A1 悪意ある診断対象サイト**（主）: 細工したコンテンツで WebUI/レポートの XSS → Electron/WebUI 権限奪取、プロンプトインジェクション → スコープ外攻撃・情報送出、パス操作 → 任意ファイル書き込み、パーサ脆弱性を狙う。
- **A2 同一ネットワーク上の第三者**: `serve --host 0.0.0.0` 時の認証回避・セッション偽造・総当たり。
- **A3 ブラウザで開いた悪意ある Web ページ**: localhost API への CSRF / DNS rebinding / WS ハイジャック。
- **A4 multi-user の一般ユーザー**: 他ユーザーの run 閲覧・操作、管理者権限取得。
- **A5 サプライチェーン**: 依存パッケージ、リリース成果物の改ざん、CI ワークフロー。

## 6. 既存の対策

- スコープゲート `isInScope`（crawler/HTTP クライアント/pilot ツール全経路）、out-of-scope は blocked
- 証拠規律（陰性対照 + 2 回の陽性リプレイ）、findings-QA は降格のみ
- `validateRequestPath`（run ID を `[a-z0-9_-]` に制限、`..` 拒否）、`isContainedPath` による静的配信の封じ込め
- `isTrustedRequest`（Host 固定・Origin 同一・Sec-Fetch-Site）、デスクトップのローカルトークン
- Cookie: HttpOnly・SameSite=Strict、HMAC 署名、timingSafeEqual、ログイン試行制限、scrypt、ダミーハッシュでユーザー列挙防止
- Electron: contextIsolation、nodeIntegration 無効、外部 URL は OS ブラウザ、will-navigate 制限
- 子プロセス起動は引数配列（シェル非経由）、ビルトイン Bash/Write ツールは LLM に不許可
- CI で `pnpm audit --audit-level low`

## 7. ユーザー回答（2026-11-22、ユーザー提供の事実）

- **利用形態**: デスクトップに加え、`serve --host 0.0.0.0` / `--multi-user` の共有サーバーも対象（A2・A3・A4 は有効）。
- **アカウント保有者**: `--multi-user` のアカウントを持てるのは自チーム・社内メンバーのみ。外部の第三者は認証済みユーザーになれない（A4 は社内の内部者に限られる。未認証の LAN 上の第三者 A2 は有効）。
- **許容リスク（対象外）**:
  - 選択した LLM プロバイダへ診断証拠・対象データが送信されること（設計上の仕様）。
  - インストーラが未署名であること、自動更新がないこと。
- **対象外にしていないもの**: 同一 Windows ユーザーで動くローカルマルウェアは許容リスクとして選ばれていない（対象のまま）。
- **最重要資産（ユーザー指定、すべて同等に重要）**: オペレーター端末（RCE されないこと）、LLM/Burp 等の API キー、取得した対象サイトのセッション・認証情報、診断結果・証拠の機密性、スコープゲート（許可外へ攻撃しないこと）。
- SECURITY.md より: オペレーター自身による不正利用・許可外ターゲットへの意図的利用は VERDICT のコードの脆弱性ではない。

## 8. 未解決の質問

- multi-user の社内ユーザー間で run の機密性をどこまで分離すべきか（admin とそれ以外）。
