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
- **識別子**：順次 API はリクエストごとの UUID。旧 `/scan` のみ `host:port` 単位で束ねる。
- **Issue の捕捉**：拡張は起動時に `Scanner.registerAuditIssueHandler` を登録し、検出された Issue を発生時刻 (`found_at`) と req/resp つきで蓄積する。`/issues`・`/report` はこの蓄積から返す（プロジェクト全体の SiteMap ではなく、本拡張が捕捉した分）。run またぎの差分取得・リセット・証拠取得が可能。

## 順次投入 API（v0.2.0、VERDICT が使用）

`POST /scan/serial` は下記 `/scan` と同じ body を受け取り、新しい Audit に1件だけ投入する。
成功時 `200`: `{ "id": "<uuid>", "status": "queued", "audit_mode": "active" }`。
この拡張の Audit が実行中・一時停止・完了不明なら `409`（旧 `/scan` の Audit も対象）。
投入結果が不明な通信障害では POST を再試行しない。

`GET /scan/serial/{id}` は該当 Audit のみの結果を返す（存在しなければ `404`）。

```json
{ "id": "<uuid>", "status": "finished", "requests_made": 142, "errors": 0, "issues": [] }
```

`issues` の形は `/issues` と同じで、常に evidence を含む。完了状態かつ `errors=0` を確認して
結果を保存してから次を投入する。paused/failed/unknown を成功扱いしない。
旧 JAR が `/scan/serial` に `404` を返す場合、JAR 更新を案内して停止する。旧 API へはフォールバックしない。

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

捕捉済み Issue の蓄積をクリア（`{ "status": "cleared" }`）。本拡張で作った Audit を削除し、Collaborator の相関情報もクリアする。実行中の評価では使わない。

## 想定フロー（VERDICT 連携）

```
1. POST /scan/serial             認証済み raw リクエストを1件投入
2. GET /scan/serial/{id}         完了までポーリング（issues も取得）
3. 結果を保存してから 1. へ      失敗・一時停止・通信障害・時間切れなら停止
```

## 制約（Montoya API 由来）

- `audit_mode` は active/passive のみ。scan configuration ファイルは渡せない（scope 等は起動時 `--config-file`）。
- resource pool はデフォルト固定（スロットリングは起動時 config）。
- 順次 API の Issue は個別 Audit に紐づく。旧 `/issues` は全体の蓄積であり、run やロールを識別しない。
- 拡張が管理するタスク間の排他制御。Burp GUI や標準 REST から起動した別タスクの並列実行は防がない。
