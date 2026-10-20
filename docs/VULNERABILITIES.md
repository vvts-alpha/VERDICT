# VERDICT が検出対象にしている脆弱性

**正:** `packages/pilot/src/tools.ts` の `CATEGORIES` と確認プローブ。Finding の `category` はこの一覧に正規化される。  
Burp 取り込みは下の「外部」を参照。

`confirmed` になる条件は共通で、**陰性対照が失敗し、陽性が 2 回安定して成功する**こと。クラスによってはマーカー出現・ブラウザ実行・OOB コールバックがそれに代わる。幻覚や「形が怪しい」だけでは記録されない。診断のあと **findings QA** がエージェント自身の finding を独立に見る（定型 FP は機械的に落とす。残り High+ confirmed と suspected A06 は証拠本文＋ヘッダの懐疑ワンショット。**最初の writeup は渡さない**）。Burp 取り込みの High+ は従来どおり `verifyBurpFindings`。誤検知の方針は下の §8。

デスクトップの新規スキャンは **pilot** がこの一覧を回す。`assess` は別経路（末尾）。

---

## 1. 専用プローブがある（確認まで機械化）

診断ステージがこれらを撃つ。手法ステージの計画にクラス名が載ると、カバレッジゲートが消化を要求する（`headers` / `info-disclosure` / `misconfig` は計画強制から除外）。

さらに、画面の構造シグナルから**決定的に注入される最低限クラス（plan-floor）**が同じゲートを通る — メソドロジーが書き忘れても、id を持つパラメータ → `idor`（+mutating API があると `idor-write`）、URL 値のパラメータ → `open-redirect` / `ssrf`、GraphQL の id 変数リーフ → 操作単位 `idor`、login 系パラメータ＋POST → `user-enumeration`、JWT 形状の値 → `session`、price/qty/file の `guessedType` → `price-tampering` / `qty-tampering` / `upload`、XML/SOAP 系エンドポイント → `xxe` が必ず消化対象になる。floor 由来のスロットは `tool: "plan-floor"` で記録され、計画由来と区別できる。LLM の計画は floor を縮められない（拡張のみ）。

| category | 名前 | 確認の仕方 | 深刻度帯 |
|---|---|---|---|
| `xss-reflected` | 反射 XSS / DOM XSS | `probe_xss`: HTML に未エスケープで残る。SPA は `probe_dom_xss` で実ブラウザ実行。DOM も category は `xss-reflected` | low–medium |
| `xss-stored` | 蓄積 XSS | `probe_stored_xss`: 保存のあと別 URL / 別ロールで読む | medium–high |
| `sqli` | SQL インジェクション | `probe_sqli`: JSON/XML の boolean 差または SLEEP。HTML 検索ページの長さ差だけでは確定しない | high–critical |
| `ssti` | SSTI | `probe_ssti`: テンプレートが積を計算する | high–critical |
| `rce` | OS コマンドインジェクション | `probe_cmdi`。blind は `probe_oob` | critical |
| `path-traversal` | パストラバーサル / LFI | `probe_traversal` + impact oracle | medium–critical |
| `open-redirect` | オープンリダイレクト | `probe_redirect`: Location が攻撃者ホスト | low–medium |
| `session` | JWT 偽造 / Cookie セッション | JWT は `probe_jwt`。Cookie は `analyze_session` がライブ 1 リクエストをダンプし、診断モデルがありそうか判定。偽造確認は別 identity の `http_request` | low–high |
| `csrf` | CSRF | `probe_csrf`。Bearer セッションは対象外 | low–medium |
| `idor` | IDOR（読み取り） | `probe_idor`。公開店舗／拠点カタログ（`og:type=place`、Find a Station、連番 store id）は対象外 | medium–high |
| `idor-write` | IDOR（書き込み） | 同上。変異メソッド | high–critical |
| `auth-bypass` | 認証バイパス | `verify_access`。302/401/403 は機械却下 | high–critical |
| `price-tampering` / `qty-tampering` / `mass-assignment` / `workflow-bypass` | ビジネスロジック | `probe_logic` / `probe_scenario` | medium–critical |
| `race-condition` | レース | `probe_race` | medium–high |
| `account-takeover` | アカウントテイクオーバー | `probe_reset_poison` | High+ |
| `user-enumeration` | ユーザー列挙 | `probe_user_enum`: 既知ユーザー vs 存在しないユーザー。マーカー（wrong password / exists:true / ステータス差）。長さ差ではない | low–medium |
| `secret-exposure` | 秘密情報の露出 | `probe_secrets` + impact oracle（キー、秘密鍵、`.env`、passwd）。Maps JS / Firebase web apiKey / reCAPTCHA site key は公開前提なので対象外 | medium–critical |
| `info-disclosure` | 情報漏洩 | `probe_secrets`: phpinfo / ディレクトリ一覧 / スタックトレース。robots.txt / sitemap.xml は対象外 | info–medium |
| `headers` | セキュリティヘッダ欠落 | `probe_headers`（CSP / HSTS / XFO / nosniff / Referrer-Policy / Permissions-Policy）。欠如は決定的 | info–low |
| `ssrf` | SSRF | in-band は `probe_ssrf`（IMDS / file:// / loopback の応答差）。blind は `probe_oob`（Interactsh または Collaborator） | medium–high |
| `xxe` | XXE | `probe_upload`（in-band）または `probe_oob`（XML / アップロードに `{{OOB}}`） | high–critical |

追加の専用プローブ（確認まで機械化）:

| probe | 対象 | 確認の仕方 |
|---|---|---|
| `probe_nosql` | NoSQL インジェクション | 演算子差・時間差 |
| `probe_cors` | CORS 誤設定 | Origin 反射と資格情報許可の組合せ |
| `probe_proto` | プロトタイプ汚染 | 注入後の応答マーカー |
| `probe_parser` | パーサ差異 | content-type/charset/duplicate-key の解釈差 |
| `probe_xxe` | XXE（in-band） | DOCTYPE/ENTITY が応答に実体化 |
| `probe_websocket` | WebSocket 認証/Origin/CSWSH | raw Upgrade 3脚（legit/別Origin/無認証）＋双方向 echo 確認 |
| `probe_cache` | キャッシュ・デセプション | 静的suffix で非公開 body を公開キーに保存させる |
| `probe_cache_poison` | キャッシュ・ポイズニング | unkeyed ヘッダが応答に反射しキャッシュされる（自キーのみ） |
| `probe_method_bypass` | verb tunneling / メソッド別認可差 | 同一リクエストを別メソッドで送りメソッド行列を作る |
| `probe_rate_limit` | レート制限の欠如 | 上限付きバーストで 429/423/Retry-After/CAPTCHA を測定（執行が観測されたら coverage として報告、DoS にならないよう bounded） |
| `probe_host_header` | Host/X-Forwarded-Host 信頼 | 注入ホストが応答にエコー（reset リンク生成・canonical 生成・cache key） |
| `probe_crlf` | CRLF インジェクション / レスポンス分割 | `%0d%0a`・overlong エンコード等で注入ヘッダが実ヘッダ化 |
| `probe_smuggling` | HTTP リクエストスマグリング | CL-vs-TE 不一致を安全なタイムアウトオラクルで検出（queue poisoning なし・socket に迷子バイトを残さない） |
| `probe_oauth` | OAuth/OIDC authorize URL | state 欠落・implicit flow・nonce 欠落を静的監査＋redirect_uri 改竄の手動リダイレクト検証 |
| `analyze_saml` | SAML 署名/アルゴリズム | assertion/response の署名・暗号・弱いアルゴリズムを受動監査（リプレイしない） |
| `probe_deser` | デシリアライズ受容面 | フォーマット別 probe（Java マジック/PHP `O:`/`__VIEWSTATE`）で「シリアル化オブジェクトを消費するか」を検出 — gadget chain は送らない |

これらの存在は対象全体の網羅や実害の自動証明を意味しない。

`probe_params` はリード生成。確認は上のプローブへ。

### GraphQL

GraphQL エンドポイントは専用プローブで診断される（同一 `POST /graphql` の別操作は inventory で `operationName`／文書構造ハッシュにより個別の ApiCall として保持される）。

- **`probe_graphql`（メタ面）** — 型名・field 名・引数などの範囲を限定したスキーマカタログを収集する。field の戻り型や input field の型を網羅した完全なスキーマ取得ではなく、root 型名だけの応答もカタログ取得成功にはしない。public と言えるのは**認証なし再送でもカタログが返る**ときだけ。フィールド候補漏洩（`Did you mean`）と batching 受理も見る。**batching 受理は機能の観測**として記録可能だが、受付の証拠だけを用いた rate-limit／lockout bypass の Finding は拒否する。
- **`probe_graphql_op`（操作面）** — 観測済みまたは introspection で採れた 1 操作を、保存された変数でリプレイ。**baseline が成立しない応答（構文・型・認証失敗・データ不在）は未検証**として報告し、clean には数えない。`compareRole` で同一操作を別ロールで再生し、フィールド単位の認可差分（denied/extra fields、部分応答）を出す。mutation は**フェイルクローズ**:デフォルトの sweep では一切実行されず、明示リプレイも `mutationAck`（その操作への opt-in）+ `verifyQuery`/`verifyPath`（許可されたテストリソース上の状態パス）を必須とし、削除・移譲系の名前はコード上で拒否する。実効の帰属は replay ごとの pre→post 読取で行い、冪等・非冪等を問わず両 replay が独立に状態を動かさなければ未検証になる。
- **IDOR / mass-assignment への接続** — `probe_idor` のスイープは `variables.input.ownerId` のようなネストした変数リーフを自前のリクエストテンプレートで辿る（型を保持した置換のみ）。`probe_logic` 系の raw body 指定で mass-assignment 変数を追加する経路もある。

**GraphQL で残る制限:** 値の契約（Int型・input object のスキーマ整合）は観測値の型を保持するまでで、スキーマからの厳密な型検査はしない。深さ・複雑度制限、クエリコスト、サブスクリプション、フェデレーション固有の問題、batching の実害確認は対象外。credentials-only ロールは帯域外リプレイ不可（`login(role)` で切替が必要）。

---

## 2. カテゴリはあるが、専用プローブがない

意図して専用にしない、または別ステージ。

| category | 名前 | どう検出するか |
|---|---|---|
| `misconfig` | 設定不備 | シグネチャが弱い。専用にしない |
| `rate-limit` | レート制限の欠如 | `probe_rate_limit` が bounded バーストで測定（認証系画面のみ・執行観測時は coverage として報告）。無制限連打はしない |
| `vulnerable-component` | 既知脆弱コンポーネント | `fingerprint_scan` + `cve_lookup`（別ステージ）。**版が取れた**コンポーネントだけ。版なしバナー（`Server: BigIP` など）＋ファミリーの CVE 履歴は対象外 |
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
| CORS 誤設定 | `cors_misconfig`（pilot にも `probe_cors` あり） |
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

- GraphQL の残る制限は §1 の「GraphQL」節を参照（メタ面・操作認可・変数置換は対象内、深度/コスト/subscription/フェデレーション/batching実害は対象外）
- 本格デシリアライズ（gadget chain の生成・RCE 化）— `probe_deser` は「シリアライズを消費する受容面」の検出まで
- デフォルト認証情報の辞書ログイン
- HTTP リクエストスマグリングの**実害確認**（queue poisoning・他人リクエスト横取り）— `probe_smuggling` はタイムアウトオラクルでの desync 検出まで（安全側設計）

残作業は [`CHECKLIST.md`](CHECKLIST.md)。

---

## 8. 誤検知を落とす／見逃さない

プロンプトで「慎重に」とは書かない。**証拠の形が既知の非脆弱性なら機械的に落とす。曖昧なら残す。**

落としてよい（再現しても脆弱性にならない）:

- HTML 検索ページの長さ差だけを SQLi にした
- 公開ディレクトリ（ピープルピッカー、店舗／拠点ロケータ）を IDOR にした
- クライアントに出す前提の鍵（Maps JS `key=`、Firebase web apiKey、reCAPTCHA site key）
- robots.txt / sitemap.xml
- 版が取れない製品バナー＋ファミリーの CVE 履歴（`Server: BigIP` など）
- SharePoint の `/_layouts/15/` / `corev15.css` だけを「2013」にして RCE CVE を載せた（2016/2019/Online も 15 ハイブを出す。ビルドヘッダが要る）
- WAF ブロックページ上の差分

残す（ここを絞ると見逃す）:

- JSON/XML の boolean SQLi、時間ベース SQLi、SQL エラー本文
- 非公開オブジェクトの IDOR（注文、残高、他人の電話／自宅住所／SSN）
- `.env` / `const KEY=` の AIza、AWS `AKIA`、`sk_live_`、`GOCSPX-`、秘密鍵
- **版が取れた** High/Critical CVE（Apache 2.4.49 など）。PoC が通れば confirmed
- probe_* が CONFIRMED と出した構造化証拠

AI の二次判定は **High/Critical**（confirmed の残り、および機械を通った suspected A06）。**最初の writeup は渡さない**（タイトルを見せると SharePoint ハイブを 2013 とゴム印する）。Medium 全体を「FP 前提」で潰すと本物の XSS/IDOR を落とす。新しい定型ノイズはオラクルに足す。
