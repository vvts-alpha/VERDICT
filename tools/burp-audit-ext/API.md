# API 仕様 — Audit selected items REST 拡張

| 項目 | 値 |
|---|---|
| Base URL | `http://127.0.0.1:1338`（既定。Burp 標準 REST API の `1337` とは別） |
| Content-Type | リクエスト/レスポンスとも `application/json`（`/report` を除く） |
| 認証 | 任意。`AUTH_TOKEN` 設定時は全リクエストに `X-Scan-Token: <値>` を必須 |
| 前提 | Burp Suite Professional（Scanner は Pro 限定） |

## 共通事項

- **エラー形式**：すべて `{ "error": "<理由>" }` を JSON で返す。
- **raw リクエスト**：`POST /scan` の `request` は CRLF（`\r\n`）区切りの生 HTTP リクエスト。Cookie・ヘッダー・body を含めた完成品をそのまま渡す（＝セッションはリクエスト内に内包）。
- **ホストキー**：監査は接続先 `host:port` 単位で束ねられる。進捗・キー指定はこの単位。
- **Issue の捕捉**：拡張は起動時に `Scanner.registerAuditIssueHandler` を登録し、検出された Issue を発生時刻 (`found_at`) と req/resp つきで蓄積する。`/issues`・`/report` はこの蓄積から返す（プロジェクト全体の SiteMap ではなく、本拡張が捕捉した分）。run またぎの差分取得・リセット・証拠取得が可能。

## 1. `POST /scan`

認証済みの raw HTTP リクエストを 1 件、対象ホストの Audit に投入（GUI の「Audit selected items」相当）。同じ `host:port` は 1 Audit に集約。

```json
{
  "host": "192.168.74.148",
  "port": 8000,
  "secure": false,
  "audit_mode": "active",
  "request": "POST /support HTTP/1.1\r\nhost: 192.168.74.148:8000\r\ncookie: minishop_session=...\r\ncontent-type: application/x-www-form-urlencoded\r\nContent-Length: 98\r\n\r\nsubject=...&message=..."
}
```

| フィールド | 型 | 必須 | 既定 | 説明 |
|---|---|---|---|---|
| `host` | string | ○ | — | 接続先ホスト（ドメイン/IP。名前解決は Burp） |
| `port` | int | ○ | — | 接続先ポート |
| `secure` | bool | × | `false` | TLS 有無 |
| `request` | string | ○ | — | CRLF 区切りの生 HTTP リクエスト。`Content-Length` は呼び出し側で正しく設定 |
| `audit_mode` | string | × | `active` | `active`（能動）/ `passive`（受動）。設定ファイルではない（Montoya は2択のみ） |

レスポンス `200`：`{ "status": "queued", "host": "192.168.74.148:8000", "audit_mode": "active" }`
エラー：`400`（欠落/不正/解釈不能）、`401`（token）、`405`（POST 以外）

## 2. `GET /status/{host}`

`{host}` は `host:port`。

```json
{ "host": "192.168.74.148:8000", "audit_mode": "active", "status": "auditing",
  "requests_made": 142, "errors": 0, "insertion_points": 31 }
```
`404` … 未投入。由来: `Audit.statusMessage()/requestCount()/errorCount()/insertionPointCount()`。

## 3. `GET /status`

```json
{ "hosts": [ { "host": "192.168.74.148:8000", "status": "auditing", "requests_made": 142, "errors": 0 } ] }
```

## 4. `GET /issues`

| 名前 | 既定 | 説明 |
|---|---|---|
| `since` | （全件） | epoch ミリ秒。これより後に捕捉された Issue のみ（run 差分） |
| `host` | （全体） | `host:port` 指定でそのホストのみ |
| `evidence` | `false` | `true` で各 Issue に req/resp（base64）を含める |

```json
{ "issues": [ { "found_at": 1719230012345, "name": "Cross-site scripting (reflected)",
  "severity": "HIGH", "confidence": "FIRM", "url": "http://192.168.74.148:8000/support",
  "detail": "...", "evidence": [ { "request_b64": "...", "response_b64": "..." } ] } ] }
```
由来: `AuditIssue.name()/severity()/confidence()/baseUrl()/detail()/requestResponses()`。

## 5. `GET /report`

| 名前 | 既定 | 説明 |
|---|---|---|
| `format` | `xml` | `xml` / `html`（Montoya `ReportFormat`） |
| `since` | （全件） | epoch ミリ秒 |
| `host` | （全体） | `host:port` |

`200`：`Content-Type: application/xml`（html 時 `text/html`）、ボディは Burp レポート本体。

## 6. `POST /reset`

捕捉済み Issue の蓄積をクリア（`{ "status": "cleared" }`）。Burp の SiteMap や進行中 Audit は消さない。

## 想定フロー（AMRAAM 連携）

```
0. (任意) POST /reset            run 前にクリア。または開始時刻を since= に使う
1. POST /scan                    各画面の認証済み raw リクエストを投入
2. GET /status/{host}            succeeded までポーリング
3. GET /issues?since=<開始ts>    この run の新規 Issue を mergeBurpIssues へ
   GET /report?format=xml&host=… ネイティブ XML が要ればこちら
```

## 制約（Montoya API 由来）

- `audit_mode` は active/passive のみ。scan configuration ファイルは渡せない（scope 等は起動時 `--config-file`）。
- resource pool はデフォルト固定（スロットリングは起動時 config）。
- Issue → 投入リクエスト/ロールの相関は自動では付かない（Issue にタグが無い）。各 Issue の evidence(request) に
  Cookie/Bearer 値が含まれるので、AMRAAM 側は自分が投入した raw と突き合わせて識別する。
