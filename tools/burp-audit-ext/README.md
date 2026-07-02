# VERDICT Audit REST — Burp 拡張

Burp Suite Professional の Montoya 拡張。**認証済みの生 HTTP リクエストを 1 件ずつ Scanner の Audit に
投入できる REST API**（GUI の「Audit selected items」相当）を `http://127.0.0.1:1338` に立てる。

Burp 標準 REST API(`1337`)は scan のリクエストにセッションを乗せる手段が無い。本拡張は
**セッションをリクエスト内に内包**させることでこれを回避する — VERDICT は live な Cookie/Bearer を載せた
生リクエストをそのまま `POST /scan` するだけでよい(注入も OpenAPI も不要、パラメータも生リクエストの
body/query がそのまま insertion point になる)。

API 仕様は `API.md`(本ディレクトリ)。

## Prebuilt jar(ビルド不要・すぐ使う）

`prebuilt/verdict-burp-audit.jar` をそのまま Burp にロードできる(Gson 同梱の fat jar、`montoya-api:2026.4` でコンパイル済み）。

- **既定は `127.0.0.1:1338` + 認証なし**(config も env も無い場合）= **localhost 限定なので安全**。同一マシンの VERDICT からだけ叩ける。
- **別マシン(WSL→Windows 等)から叩くなら**、初回ロード時にユーザホームへ生成される `~/.verdict-audit.properties` を編集 → `host=0.0.0.0` + `token=<秘密>` を設定 → 拡張を Reload(0.0.0.0 公開時は token 必須）。
- ソース(`src/`）を変更したら `gradle shadowJar` で焼き直すこと(この prebuilt は**手動更新の便宜バイナリ**で、ソースと自動同期はしない）。

## ビルド

要 JDK 17+ と Gradle(or `gradle wrapper` を生成)。初回はネットワーク(Montoya / Gson / shadow plugin)が要る。

```bash
cd tools/burp-audit-ext
gradle shadowJar           # → build/libs/verdict-burp-audit.jar (Gson 同梱の fat jar)
```

**`montoya-api:2026.4` でコンパイル検証済み**(javac で全クラス生成・`AuditExtension implements BurpExtension` 確認）。
古い Burp で API シグネチャが違う場合は `build.gradle.kts` の版を下げて、差分が出た所だけ直す。

## Burp へのロード

1. Burp → **Extensions → Installed → Add**
2. Extension type: **Java**、Select file: `build/libs/verdict-burp-audit.jar`
3. 出力に `VERDICT Audit REST listening on http://127.0.0.1:1338` が出れば OK

### オプション(env、Burp 起動プロセスに渡す)

| env | 既定 | 説明 |
|---|---|---|
| `SCAN_API_HOST` | `127.0.0.1` | bind 先。**別マシンの VERDICT から叩くなら `0.0.0.0`**(LAN 公開) |
| `SCAN_API_PORT` | `1338` | listen ポート |
| `AUTH_TOKEN` | (無) | 設定すると全リクエストに `X-Scan-Token: <値>` を必須化 |

> ⚠ `SCAN_API_HOST=0.0.0.0` で公開する時は **`AUTH_TOKEN` を必ず併用**(誰でもスキャン投入できてしまうため)。トークン未設定で 0.0.0.0 にすると拡張が起動時に警告を出す。

スコープ/スロットリング等のプロジェクト設定は Burp 起動時 `--config-file` で読ませる
(Montoya の Audit は active/passive の2択のみで、scan config ファイルは渡せないため)。

## 動作確認(curl)

```bash
# 認証済みリクエストを投入
curl -s localhost:1338/scan -H 'content-type: application/json' -d '{
  "host":"192.168.74.148","port":8000,"secure":false,"audit_mode":"active",
  "request":"GET /account HTTP/1.1\r\nHost: 192.168.74.148:8000\r\nCookie: session=abc\r\n\r\n"
}'
# 進捗
curl -s localhost:1338/status/192.168.74.148:8000
# 新規 issue(run 開始 ts 以降)
curl -s 'localhost:1338/issues?since=1719230000000&evidence=true'
# クリア
curl -s -X POST localhost:1338/reset
```

## VERDICT 連携(次のステップ)

`@veritas/scanner` 側に本 API のクライアント(`burp-audit.ts`)+ 生リクエストビルダーを足し、
burp フェーズで「inventory を dedup → 各エンドポイントの **live 認証ヘッダ込み生リクエスト**を `POST /scan`
→ `GET /status` をポーリング → `GET /issues?since=` を `mergeBurpIssues` で取り込み」を回す。
拡張(Java)はこのリポジトリの `tools/`、クライアント(TS)は packages 側、という分担。
