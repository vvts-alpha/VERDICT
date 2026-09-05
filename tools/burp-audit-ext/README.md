# VERDICT Audit REST — Burp 拡張

Burp Suite Professional の Montoya 拡張。**認証済みの生 HTTP リクエストを 1 件ずつ Scanner の Audit に
投入できる REST API**（GUI の「Audit selected items」相当）を `http://127.0.0.1:1338` に立てる。

Burp 標準 REST API(`1337`)は scan のリクエストにセッションを乗せる手段が無い。本拡張は
**セッションをリクエスト内に内包**させることでこれを回避する — VERDICT は live な Cookie/Bearer を載せた
生リクエストをそのまま `POST /scan/serial` するだけでよい(注入も OpenAPI も不要、パラメータも生リクエストの
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
curl -s localhost:1338/scan/serial -H 'content-type: application/json' -d '{
  "host":"192.168.74.148","port":8000,"secure":false,"audit_mode":"active",
  "request":"GET /account HTTP/1.1\r\nHost: 192.168.74.148:8000\r\nCookie: session=abc\r\n\r\n"
}'
# 返された id の進捗と、その Audit の issue（証拠込み）
curl -s localhost:1338/scan/serial/<id>
# 完了を確認して結果を保存した後、次のリクエストを投入する
```

## VERDICT 連携

拡張 v0.2.0 と更新後の VERDICT は、**投入 → 完了確認 → 結果保存 → 次の1件**で動く。
同じホストでも毎回新しい Audit を作る。実行中または完了不明の Audit が本拡張にあれば、追加投入は `409`。
既存の `/scan` は互換用に残るが、VERDICT は使わない。旧 JAR の `404` 時も一括投入へ戻さず停止する。
JAR を差し替えて Reload する前に、以前の Audit が終了していることを Burp で確認すること。

既定のタイムアウトは **1件あたり30分**（CLI `burp-scan --max-min`）。失敗・一時停止・通信エラー・
タイムアウト時は次を投入せず、取得済みの結果を保存して部分結果と表示する。Burp 側の実行中タスクは
自動削除しない。残りの結果は XML をエクスポートして `burp-import` で取り込める。
`/reset` は自動実行しないため、過去の結果や Collaborator の相関情報を消さない。

タスク内の HTTP 並列数は Burp の設定に従う。順次投入だけで HTTP 同時接続数が1になるわけではない。
この変更は投入負荷の対策であり、AWT のネイティブクラッシュ解消を保証するものではない。

## 回帰テスト

`gradle check` は Burp 本体やネットワーク対象を使わず、順次投入の排他制御・完了判定・新規 Audit の生成を検証する。
