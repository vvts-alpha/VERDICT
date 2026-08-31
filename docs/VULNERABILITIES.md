# VERDICT が検出対象にしている脆弱性

**正:** `packages/pilot/src/tools.ts` の `CATEGORIES` と確認プローブ。Finding の `category` はこの一覧に正規化される。  
**対象外の書き方:** ASR は findings を書かない。Burp 取り込みは下の「外部」を参照。

`confirmed` になる条件は共通で、**陰性対照が失敗し、陽性が 2 回安定して成功する**こと。クラスによってはマーカー出現・ブラウザ実行・OOB コールバックがそれに代わる。幻覚や「形が怪しい」だけでは記録されない。

デスクトップの新規スキャンは **pilot** がこの一覧を回す。`assess` は別経路（末尾）。

---

## 1. 専用プローブがある（確認まで機械化）

診断ステージがこれらを撃つ。手法ステージの計画にクラス名が載ると、カバレッジゲートが消化を要求する（`headers` / `info-disclosure` / `misconfig` は計画強制から除外）。

| category | 名前 | 確認の仕方 | 深刻度帯 |
|---|---|---|---|
| `xss-reflected` | 反射 XSS / DOM XSS | `probe_xss`: HTML に未エスケープで残る。SPA は `probe_dom_xss` で実ブラウザ実行。DOM も category は `xss-reflected` | low–medium |
| `xss-stored` | 蓄積 XSS | `probe_stored_xss`: 保存のあと別 URL / 別ロールで読む | medium–high |
| `sqli` | SQL インジェクション | `probe_sqli`: boolean 差または SLEEP | high–critical |
| `ssti` | SSTI | `probe_ssti`: テンプレートが積を計算する | high–critical |
| `rce` | OS コマンドインジェクション | `probe_cmdi`。blind は `probe_oob` | critical |
| `path-traversal` | パストラバーサル / LFI | `probe_traversal` + impact oracle | medium–critical |
| `open-redirect` | オープンリダイレクト | `probe_redirect`: Location が攻撃者ホスト | low–medium |
| `session` | JWT 偽造 / Cookie セッション | JWT は `probe_jwt`。Cookie は `analyze_session` がライブ 1 リクエストをダンプし、診断モデルがありそうか判定。偽造確認は別 identity の `http_request` | low–high |
| `csrf` | CSRF | `probe_csrf`。Bearer セッションは対象外 | low–medium |
| `idor` | IDOR（読み取り） | `probe_idor` | medium–high |
| `idor-write` | IDOR（書き込み） | 同上。変異メソッド | high–critical |
| `auth-bypass` | 認証バイパス | `verify_access`。302/401/403 は機械却下 | high–critical |
| `price-tampering` / `qty-tampering` / `mass-assignment` / `workflow-bypass` | ビジネスロジック | `probe_logic` / `probe_scenario` | medium–critical |
| `race-condition` | レース | `probe_race` | medium–high |
| `account-takeover` | アカウントテイクオーバー | `probe_reset_poison` | High+ |
| `user-enumeration` | ユーザー列挙 | `probe_user_enum`: 既知ユーザー vs 存在しないユーザー。マーカー（wrong password / exists:true / ステータス差）。長さ差ではない | low–medium |
| `secret-exposure` | 秘密情報の露出 | `probe_secrets` + impact oracle（キー、秘密鍵、`.env`、passwd） | medium–critical |
| `info-disclosure` | 情報漏洩 | `probe_secrets`: phpinfo / ディレクトリ一覧 / スタックトレース | info–medium |
| `headers` | セキュリティヘッダ欠落 | `probe_headers`（CSP / HSTS / XFO / nosniff / Referrer-Policy / Permissions-Policy）。欠如は決定的 | info–low |
| `ssrf` | SSRF | in-band は `probe_ssrf`（IMDS / file:// / loopback の応答差）。blind は `probe_oob`（Collaborator 必須） | medium–high |
| `xxe` | XXE | `probe_upload`（in-band）または `probe_oob`（XML / アップロードに `{{OOB}}`） | high–critical |

`probe_params` はリード生成。確認は上のプローブへ。

---

## 2. カテゴリはあるが、専用プローブがない

意図して専用にしない、または別ステージ。

| category | 名前 | どう検出するか |
|---|---|---|
| `misconfig` | 設定不備 | シグネチャが弱い。専用にしない |
| `rate-limit` | レート制限の欠如 | 連打は DoS になるので専用にしない |
| `vulnerable-component` | 既知脆弱コンポーネント | `fingerprint_scan` + `cve_lookup`（別ステージ） |
| `other` | その他 | 常用しない |

Cookie の予測可能性は `analyze_session` がライブの 1 リクエストをダンプし、診断モデルが見て判定する。偽造の確認は別 identity の `http_request`。できなければ `suspected`。

---

## 3. 付随して見るもの（Finding にならない／別経路）

| 対象 | 経路 | メモ |
|---|---|---|
| 未リンクパス | `probe_paths` / `probe_guesses` | マップ。脆弱性ではない |
| JS 内 API・sink | `analyze_js` | エンドポイント登録と DOM-XSS リード |
| アップロード | `probe_upload` | 対照 SVG → 応答 URL を GET → SVG XSS / in-band XXE。受け入れだけでは confirmed にしない。webshell は後回し |
| JWT `jku` / `kid` / RS256→HS256 | なし | `probe_jwt` の対象外 |

---

## 4. `assess` だけが自動で見るもの

決定論パイプライン（CLI `assess` / `scan`）。デスクトップの主経路ではない。

| 名前 | validator |
|---|---|
| 公開 `.git/config` / `.git/HEAD` / `.env` | `exposed_file` |
| 認証が必要なのに未認証で取れる | `auth_required` |
| CORS 誤設定 | `cors_misconfig` |
| IDOR 仮説（隣 id） | `@veritas/agent` の verify |
| ロール差分 | `authDiffScreen` |

---

## 5. 外部スキャナ（任意）

`--burp-scan` / `burp-import` は Burp の issue をネット新規だけマージする。High+ は再検証する。

---

## 6. LLM アプリ（別コマンド）

`veritas redteam`。OWASP LLM Top 10 (2025)。確認はカナリア漏えい。

---

## 7. 検出対象にしていないもの（明示）

- GraphQL 固有
- HTTP リクエストスマグリング / キャッシュポイズニング
- 本格デシリアライズ
- プロトタイプ汚染（fingerprint の JS 注記のみ）
- デフォルト認証情報の辞書ログイン

残作業は [`CHECKLIST.md`](CHECKLIST.md)。
