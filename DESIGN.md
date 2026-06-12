# NewAgent — 自律型 Web/API ペンテストエージェント 設計書

| | |
|---|---|
| Status | **Draft v0.1** |
| Date | 2026-06-08 |
| Author | veritas-rt + Claude |
| 前提 | 既存資産 (CrowSong / HungrySong) は **コードを一切流用しない**。`NewAgent/` でゼロから実装する。継承するのは *原則* のみ。 |
| 実装スタック | **TypeScript フルスタック**(agent / Playwright / WebUI を全て TS、JSON 契約スキーマを型として全レイヤーで共有) |
| オーケストレーション | **Claude 主導** — Claude Agent SDK(TypeScript)で制御ループと画面別サブエージェントを構成。**Claude Max サブスク(定額)認証**で回し、従量 API 課金にしない。 |

> この文書は実装の前段。ここで設計を固め、別プロジェクト (`NewAgent/`) で 1 から作り直す。

---

## 0. TL;DR（設計の背骨）

1. **2 フェーズに分割**し、その間を **画面インベントリ JSON** だけで疎結合にする。
   - 前半 = 抽出 & ラベリング(Playwright で画面・API を採取し意味付け)
   - 後半 = スキャン(画面ごとに脆弱性 + ビジネスロジック)
   - 動機は **コンテキスト管理**。後半は「1 画面 = 1 ユニット」でコンテキストが有界になり、画面ごとにサブエージェントへ分割・並列できる。
2. **エージェントの作業記憶 = WebUI が読む単一状態**。観測性のための要求が、そのまま自律性の土台(明示的な状態)を強制する。
3. **人間ハンドオフは認証等の技術的不能点のみ**。Cookie 注入はせず、生きたブラウザ上で人間にその場でログインさせて続行する。
4. 継承する原則 = **スコープゲート / 証拠規律(negative control + 2 positive replays)/ 証拠保管**。これは自律エージェントの **安全弁** として残す。

---

## 1. 目的・スコープ・非目標

### 1.1 目的
認可済みの Web/API ターゲットに対し、**観測 → 計画 → 行動 → 評価** の閉ループを自分で回す自律アセスメントを行い、証拠付きの findings を出す。

### 1.2 自律性の定義
- エージェントが「次に何をするか」を自分で決めてループを回し続ける(人が毎ステップ繋がない)。
- 詰まり(認証等)は **hard stop ではなく人間ハンドオフ点** として設計に組み込む。ハンドオフ待ちの間も他の作業は進める(non-blocking)。

### 1.3 非目標(明示的にやらないこと)
過去 2 世代の戦績(ローカル/機器では成果、認証の壁を越えられない大手 VRP では成果ゼロ)から、できないことを正直に線引きする。

- ❌ **full-auto signup / CAPTCHA・Arkose 突破** → 自動化しない。人間ハンドオフに倒す。
- ❌ **WAF / bot defense の突破** → 非目標。アプリ層に到達できない場合は「到達不能」と報告して該当ターゲットを停止(過去の Sony/Akamai 403、HotelTonight Fastly 406)。
- ❌ **破壊的アクション**(DoS、データ破壊、本番データの改変を伴う検証)→ 禁止。
- ❌ Cookie / セッショントークンの直接注入による認証なりすまし。

### 1.4 倫理・認可
- `scope_manifest` または明示的なターゲット指定が**必須**。スコープ外はポリシーで DENY。
- 全ネットワークアクションは PolicyEngine を通る(§4.2)。

---

## 2. 過去 2 世代からの教訓(継承 / 廃棄)

### 2.1 廃棄する設計(なぜ作り直すか)
| 廃棄 | 理由 |
|---|---|
| 人(Claude)が手でオーケストレーション | 制御ループが閉じない。半自動に留まる |
| CrowSong / HungrySong の 2 プロセス分断 | recon と validation で状態が分断、import で詰まる |
| 状態が証拠 DB にしかなく作業記憶がない | エージェントが「今何を追ってるか」を保持できない |
| 詰まり = hard stop | 認証 / WAF で人間待ちになり自己回復しない |
| strategize が validator 経路をバイパス | 計画・実行・検証の責務が混線 |

### 2.2 継承する原則(コードではなく思想)
| 継承 | 形 |
|---|---|
| スコープゲート(PolicyEngine) | ALLOW / CAUTION / APPROVAL / DENY。自律エージェントの安全弁 |
| 証拠規律 | confirmed には **negative control + 2 positive replays** 必須。誤検知=暴走を防ぐ |
| 証拠保管 | req/resp/screenshot を artifacts に保存 |
| インタラクティブ認証(新) | Cookie 注入を避け、生ブラウザで人間ハンドオフ |
| レート配慮 | Sophos WAF 教訓。デフォルト保守的なレート |

---

## 3. 全体アーキテクチャ

```
                 ┌──────────── 横断レイヤー(全フェーズが依存)────────────┐
                 │  PolicyEngine │ EvidenceStore │ BudgetGuard │ AssessmentState │
                 └───────┬───────────────┬────────────┬─────────────┬──────────┘
                         │               │            │             │ (購読)
  Input                  ▼               ▼            ▼             ▼
 ┌─────────┐      ┌─────────────┐                          ┌──────────────┐
 │SingleURL│─────▶│  Phase 1    │   screen_inventory.json  │   WebUI      │
 │   or    │      │ Recon&Label │ ───────────────────────▶ │ (観測+最小操作)│
 │  Scope  │      └─────────────┘          │               └──────────────┘
 └─────────┘                               ▼
                                    ┌─────────────┐   per-screen   ┌──────────┐
                                    │  Phase 2    │ ─ subagents ─▶ │ findings │
                                    │   Scan      │  (並列/fresh)   │  report  │
                                    └─────────────┘                └──────────┘
```

- **2 フェーズは `screen_inventory.json`(§6.7)を唯一の契約として疎結合**。
- 横断レイヤーの **AssessmentState**(§4.1)が単一の正規状態であり、**WebUI のデータソース兼エージェントの作業記憶**。
- TypeScript モノレポ(§11)。契約スキーマは `core` パッケージの型として一元定義し、全レイヤーで共有。

---

## 4. 横断的関心事(全フェーズが依存するので先に定義)

### 4.1 AssessmentState — 作業記憶 = UI データソース
**最重要コンポーネント**。エージェントの内部状態を明示的にシリアライズした単一の正規ストア。

- 実体: **SQLite(`state.sqlite`)** + **append-only イベントログ**。派生ビューを WebSocket で WebUI に push。
- 「UI のための state」と「エージェントの作業記憶」を**同一物**にすることで、過去の「作業記憶がない」弱点を構造的に解消する。

```ts
// core/state.ts
type Phase = "init" | "phase1_recon" | "phase1_label" | "phase2_scan" | "report" | "done" | "halted";

interface AssessmentState {
  id: string;
  target: TargetInput;          // §5
  phase: Phase;
  scope: ScopePolicy;           // §4.2
  budget: BudgetState;          // §4.4
  screens: Screen[];            // §6.7  画面インベントリ
  hypotheses: Hypothesis[];     // §7.4  攻撃仮説(=「方針」)
  findings: Finding[];          // §7.6
  handoffs: HumanHandoff[];     // §6.4  人間ハンドオフ要求
  events: StateEvent[];         // append-only(再生可能)
}
```

- すべての状態遷移は `StateEvent` として追記 → 再生可能・監査可能。
- WebUI は `events` を購読して差分描画。

### 4.2 PolicyEngine(スコープゲート)
- 判定: `ALLOW | ALLOW_WITH_CAUTION | REQUIRES_APPROVAL | DENY`。
- 入力 2 系統(§5):
  - **単一 URL** → 同一オリジン + 明示許可サブパスを自動でスコープ導出。
  - **scope_manifest** → 既存の構造化スコープをそのまま読む。
- **全ネットワークアクション(crawl の各遷移、scan の各リクエスト)が通過必須**。out-of-scope は DENY、要承認は WebUI 経由で人間承認(§8.3)。

### 4.3 EvidenceStore(証拠規律)
- `confirmed` 判定には **negative control + 2 positive replays** を必須(ValidatorBase 相当の不変条件)。
- 証拠成果物: リクエスト/レスポンス対、差分、スクショ → `artifacts/<screen_id>/<evidence_id>/`。

### 4.4 BudgetGuard(予算・停止条件)
- 予算次元: **トークン / 実時間 / 総リクエスト数 / ターゲットあたりリクエスト数**。
- 停止条件: ①カバレッジ達成(全画面スキャン済) ②予算超過 ③ no-progress(N ステップ findings も新画面もゼロ) ④到達不能(WAF) ⑤人間 halt。

### 4.5 安全弁
- 破壊的メソッド/パスのブロックリスト(`DELETE` 大量、危険な管理 API 等は REQUIRES_APPROVAL)。
- デフォルト保守的レート + ターゲット別オーバーライド(WAF 教訓)。
- グローバル kill switch(WebUI / CLI / SIGINT)。

---

## 5. 入力モデル

```ts
// core/input.ts
type TargetInput =
  | { kind: "single_url"; url: string; followLinks: boolean; maxDepth: number }
  | { kind: "scope_manifest"; path: string };   // 構造化スコープ YAML/JSON
```

- **single_url**: 起点 URL を取りに行き、内部で叩く API を採取。`followLinks` ならスコープ内リンクを辿る。スコープは同一オリジン + 起点配下を既定とし、PolicyEngine が自動導出。
- **scope_manifest**: in-scope / out-of-scope ホスト・パス・レート・要承認領域を明示。

---

## 6. Phase 1: 抽出 & ラベリング

**出力 = `screen_inventory.json`(§6.7)**。「URL 一覧を返すクローラ」ではなく「攻撃の入口を意味づけする偵察」にするのが肝。前半のラベル品質が後半の天井を決める。

### 6.1 クロール戦略
- **Playwright `launchPersistentContext`(`userDataDir` 指定、非ヘッドレス可)** を 1 つ保持。
- BFS。`maxDepth` / 予算 / scope で打ち切り。フォーム検出(入力 → パラメータ候補)。
- リンク辿り + 明示 URL 取得の両対応。各遷移は PolicyEngine を通す。

### 6.2 ネットワーク傍受 → 内部 API 抽出
- `page.on("request")` / `page.on("response")` で **XHR / fetch を全捕捉**。GraphQL(POST `/graphql` の operationName)も対応。
- req/res 対から **API スキーマを推定**(method, url_template, クエリ/ボディ形, レスポンス形)。
- 認証ヘッダ(Bearer / Cookie)は **存在のみ検出し値は保存しない/マスク**。

### 6.3 認証ハンドオフ(インタラクティブ)— Cookie 注入なし
過去の最大ボトルネック(auth wall)を「hard stop」ではなく「設計された人間ハンドオフ点」にする。

```
1. エージェントが自動ログイン試行(vault 資格情報でフォーム入力)
2. 詰まり検出(CAPTCHA / MFA / Arkose / 想定外リダイレクト)
3. AssessmentState に HumanHandoff{reason:"auth", url} を追加
4. WebUI が「要・人間ログイン: <url>」を通知(§8.3)
5. 人間が *その生きている Playwright ブラウザ* 上で手でログイン完了
6. エージェントは同じ永続コンテキストのまま続行(認証状態は userDataDir に宿る)
```

- **エージェントは Cookie/トークンを一切触らない**。認証状態はブラウザプロファイルに宿り、エージェントは「認証済みブラウザを使い続けるだけ」。
- セッション切れ → 再認証も同じハンドオフ。
- **non-blocking**: ハンドオフ待ちの間、unauth で到達できる画面の探索は並行して進める。

#### 詰まり検出ヒューリスティクス
CAPTCHA iframe(Arkose/hCaptcha/reCAPTCHA の既知セレクタ)、`/challenge` 系リダイレクト、ログイン後想定の遷移が起きない、403/429 の連続 — のいずれかでハンドオフへ。

### 6.4 画面 dedup(ハイブリッドキー)
URL 構造が同じものはまとめる。ただし **SPA は URL が変わらない**ので素朴な URL dedup は破綻する → 2 段キー。

```
dedup_key = (正規化ルート, DOM骨格hash)
```

- **古典的アプリ**: パスのパラメータ値をプレースホルダ化。`/orders/1`, `/orders/2` → `url_template = /orders/{id}`。数値/UUID/slug を型推定してプレースホルダ化。
- **SPA**: `history.pushState` / `hashchange` で取れる **仮想ルート** を採取 + **DOM 骨格 hash**(テキスト/属性値を除いたタグ構造のみの正規化ハッシュ)で「同一 URL だが別画面」を分離。
- 同一 `dedup_key` は 1 画面に集約し、`observed_urls` に実例を貯める。

### 6.5 LLM ラベリング
- 入力: **スクショ + 簡約 DOM(可視テキスト・フォーム・リンクの要約)+ URL + 観測 API**。
- 出力(**構造化・型でバリデート**): `screen_type` / `description`(意味付け)/ `params` の意味推定 / `labels`(後半への攻撃ヒント)。
- 例: 「注文詳細。注文 ID で他人の注文が見える可能性」+ `labels:["idor-candidate","pii"]`。

### 6.6 `screen_inventory.json` スキーマ(2 フェーズ間の契約)

```ts
// core/screen.ts — Phase1 が書き Phase2 と WebUI が読む唯一の契約
type AuthState = "unauth" | "post-login";
type ScreenType =
  | "listing" | "detail" | "form" | "auth" | "dashboard"
  | "search" | "upload" | "payment" | "admin" | "other";
type ParamLoc = "path" | "query" | "body" | "header";

interface ApiCall {
  method: string;                 // GET/POST/...
  urlTemplate: string;            // 正規化済 例 /api/orders/{id}
  auth: "none" | "bearer" | "cookie";
  reqSchema: JsonShape | null;    // ボディ/クエリ形の推定
  resSchema: JsonShape | null;
}
interface Param {
  name: string; in: ParamLoc; example: string;
  guessedType: "object_ref" | "id" | "enum" | "free_text" | "file" | "price" | "qty" | "unknown";
}
interface Screen {
  screenId: string;               // s-0007
  urlTemplate: string;            // 正規化ルート
  observedUrls: string[];
  authState: AuthState;
  screenType: ScreenType;
  description: string;            // LLM の意味付け
  params: Param[];
  apis: ApiCall[];
  screenshot: string;            // artifacts/s-0007.png
  domSkeletonHash: string;       // dedup キーの一部
  labels: string[];              // 攻撃ヒント 例 ["idor-candidate","pii"]
}
```

### 6.7 Phase 1 の停止条件
新規 `dedup_key` が N 連続ゼロ / maxDepth 到達 / クロール予算超過 / scope を出尽くした。

---

## 7. Phase 2: スキャン

`screen_inventory.json` を 1 画面ずつ読み、**(a) 汎用脆弱性 + (b) ビジネスロジック** の 2 系統をかける。

### 7.1 オーケストレータ
- 画面を優先度付け(`auth` / sensitive `labels` / object_ref param / payment を優先)。
- 各画面を **サブエージェントへディスパッチ**。並列度は予算とレートで制御。
- サブエージェントの結果(仮説 → テスト → 証拠)を AssessmentState に集約。

### 7.2 画面別サブエージェント(フレッシュコンテキスト)= 自律性の器
- 入力: **1 画面分の JSON + scope + ツールボックス(§9)**。フレッシュコンテキストで自律ループ。
- 「自律性が足りない」への直接の回答。各画面が独立 → コンテキスト有界・並列・再実行可能。
- TS 実装は **Claude Agent SDK のサブエージェント(Claude 主導)**。各画面を独立サブエージェントに割り当てる。

### 7.3 汎用脆弱性スキャン(決定論バリデータ)
- 画面種別 / API に応じて該当チェックだけ起動するカタログ方式。
  - 例: `exposed_file`, `auth_required`(0-byte 200 ガード含む), reflected/stored XSS, SQLi プローブ, open redirect, SSRF プリミティブ, CORS 誤設定, security headers。
- 各チェックは **証拠規律(§4.3)準拠**。auth_required の 0-byte 200 ガードなど過去の教訓もカタログに反映。

### 7.4 ビジネスロジックスキャン(自律の本体)
画面の `screenType / description / params / apis / labels` から **攻撃仮説(Hypothesis)** を生成し、検証する。

```ts
// core/hypothesis.ts —「方針」= WebUI に出る攻撃仮説
type HypoStatus = "queued" | "testing" | "confirmed" | "refuted" | "blocked";
interface Hypothesis {
  id: string; screenId: string;
  class: "idor" | "privilege_escalation" | "price_tampering" | "qty_tampering"
       | "state_skip" | "mass_assignment" | "race" | "auth_bypass" | "info_disclosure" | "other";
  statement: string;             // 「他人の order_id を閲覧できる」
  testPlan: string;              // 具体手順
  status: HypoStatus;
  evidenceIds: string[];
}
```

- 仮説 → 具体テスト計画 → 実行 → 証拠化 → 判定。
- **マルチアカウント / ロール比較**(auth diff): 2 つのロールで同一 API を叩き、認可境界を越えられるかを差分検出。
- IDOR / 権限昇格はここが主戦場(過去 unauth black-box で取れなかった領域を、認証ハンドオフ × auth diff で初めて狙える)。

### 7.5 証拠規律の適用
すべての `confirmed` は negative control(正常応答)+ 2 positive replays を `EvidenceStore` に残してから昇格(§4.3)。

### 7.6 findings 集約とレポート
- `Finding` = confirmed Hypothesis or 決定論チェック陽性 + 証拠群。
- レポート(`report.md`)に重大度・再現手順・証拠・スコープ根拠を出力。

---

## 8. WebUI(観測 + 最小操作)

### 8.1 役割
AssessmentState を **WebSocket 購読**し、現在のフェーズ・検出画面・方針(仮説)を一覧表示。加えて最小限の操作。

### 8.2 レイアウト(3 ペイン)
```
┌─────────────────────────────────────────────────────────────┐
│  Phase: ② Scanning   screens 42  scanned 17  findings 3  $1.2 │ ← 状態バー
├──────────────────┬──────────────────────────────────────────┤
│ SITE TREE        │  SCREEN DETAIL: /orders/{id}              │
│ (navigator)      │  [screenshot]  type: detail               │
│ ▾ example.com    │  auth: post-login                         │
│   ▾ /orders   ●  │  params: id (object_ref)                  │
│     /orders/{id}◐│  APIs: GET /api/orders/{id}               │
│   ▸ /api      ✓  │  ── HYPOTHESES(方針)──                    │
│   /login      ✓  │   ⚠ IDOR: 他人の order 閲覧 → testing      │
│   ▾ /admin    ⚠  │   ◐ mass-assignment PATCH → queued        │
│     /admin/users⚠│   ✓ XSS reflected → clean(neg+2replay)    │
│ ●実行中 ◐queued   │  EVIDENCE: artifacts/s-0007/...           │
│ ✓clean ⚠finding  │                                          │
└──────────────────┴──────────────────────────────────────────┘
```
- **左 = サイトツリー(ナビゲータ)**。URL 階層 + SPA 仮想ルート。各ノードに **スキャン状態バッジ**(未/実行中/clean/finding)を色表示(Burp の site map 流で、ペンテスターに馴染む)。
- **中央 = 画面詳細**。スクショ・ラベル・params・API・**HYPOTHESES(=方針)一覧**・証拠リンク。
- **上 = 状態バー**。フェーズ・進捗カウント・予算。
- 任意で **グラフビュー切替**(API 共有・認証フローの相互参照を見る副次ビュー。木で消える相互リンクを補う)。

### 8.3 最小操作
- **人間認証ハンドオフの通知・承認**(§6.3)。「要・人間ログイン」を出し、人間が生ブラウザで完了したら「続行」を押す。
- **pause / resume**。
- **画面をスキャン対象から除外**(誤検知ノイズ源やセンシティブ領域を外す)。
- REQUIRES_APPROVAL アクションの承認(§4.2)。
- (将来)スキャン起動・ターゲット追加。

### 8.4 技術
- フロント: TS(React)+ ツリーコンポーネント。
- バック: 状態 API + WebSocket(`server` パッケージ)。
- **契約スキーマ型を agent と共有**(`core` パッケージ)→ 画面インベントリ/仮説の型がフロントまで一気通貫。

---

## 9. ツール抽象(エージェントの道具箱)
サブエージェントが叩く粗粒度ツール。全ツールが PolicyEngine / BudgetGuard / EvidenceStore を横断的に通す。

| ツール | 役割 |
|---|---|
| `browser.navigate(url)` | scope ゲート付き遷移 |
| `browser.intercept()` | ネットワーク傍受の取得 |
| `http.request(req)` | policy gated な生 HTTP(検証用) |
| `validator.run(name, screen)` | 決定論チェック起動 |
| `evidence.record(...)` | 証拠保存(neg control / replay) |
| `screen.label(ctx)` | LLM ラベリング |
| `state.update(event)` | 作業記憶への追記 |
| `human.handoff(reason)` | 人間ハンドオフ要求(認証/承認) |

---

## 10. データレイアウト / 成果物
```
NewAgent/runs/<assessment_id>/
  state.sqlite              # AssessmentState(作業記憶=UIソース)
  screen_inventory.json     # Phase1→Phase2 契約
  artifacts/<screen_id>/<evidence_id>/   # req/resp/screenshot
  report.md                 # 最終レポート
  browser-profiles/<...>/    # 永続ブラウザ userDataDir(認証状態。gitignore)
```

---

## 11. モノレポ構成(TypeScript)
```
NewAgent/
  package.json            # pnpm workspace
  packages/
    core/                 # 型・状態・policy・evidence・budget(全レイヤー共有)
    crawler/              # Phase1: Playwright クロール・傍受・dedup・ラベリング
    scanner/              # Phase2: 汎用validator + ビジネスロジック
    agent/                # Claude Agent SDK ベースのオーケスト + 画面別サブエージェント
    server/               # 状態API + WebSocket(UIバック)
    webui/                # React フロント(3ペイン)
    cli/                  # エントリポイント(run / resume / report)
```
- **共有型は `core`** に集約 → 画面インベントリ/仮説スキーマを agent・scanner・webui で型共有。
- **オーケストレーション層 = Claude Agent SDK(TS)で確定(Claude 主導)**。制御ループ・画面別サブエージェントとも SDK のエージェント機構に乗せ、Claude Max サブスクで認証。

---

## 12. 段階的実装計画(MVP → 拡張)
| M | 内容 | 完了条件 |
|---|---|---|
| M0 | モノレポ雛形 + `core`(状態/scope/budget 型)+ SQLite 状態ストア | `cli run` が空アセスメントを生成し state.sqlite を書く |
| M1 | Phase1: クロール + 傍受 + dedup + `screen_inventory.json` 出力(ラベルはルールベース仮) | ローカル juice-shop 等で画面/API を JSON 化 |
| M2 | LLM ラベリング(構造化出力) | screen_type/description/labels が付く |
| M3 | WebUI 観測(状態バー + サイトツリー + 画面詳細) | ブラウザで Phase1 結果がツリー表示される |
| M4 | Phase2: 汎用 validator 数種 + 証拠規律(neg+2replay) | exposed_file/auth_required 等が confirmed を出す |
| M5 | ビジネスロジックスキャン(画面別サブエージェント / Claude Agent SDK) | IDOR 仮説の生成→検証が 1 画面で回る |
| M6 | 認証ハンドオフ + WebUI 最小操作(承認/pause/除外) | CAPTCHA 検出 → UI 通知 → 人間ログイン → 続行 |
| M7 | レポート / 予算・停止 / auth-diff(マルチロール) | report.md と停止条件が機能 |

各マイルストンは **ローカル安全ターゲット(juice-shop / mattermost docker)** で先に検証してから実ターゲットへ。

---

## 13. 未解決の論点 / リスク
- **SPA 網羅性**: 仮想ルート採取と DOM 骨格 hash の精度。状態が JS イベントで深く分岐する SPA をどこまで辿れるか。
- **LLM ラベリング品質が後半の天井**: 誤ラベルは無駄な仮説/見逃しに直結。評価セットで継続計測したい。
- **認証ハンドオフ UX**: 生ブラウザと WebUI(別窓)の連携。将来 CDP screencast で UI 内に映すかは MVP 後。
- **並列スキャンの WAF/レート**: 並列度を上げると bot defense を誘発(過去教訓)。レート × 並列のバランス。
- **証拠の偽陽性**: 証拠規律で抑えるが、ビジネスロジックの「判定」は曖昧になりやすい。
- **コスト**: 画面ごとサブエージェントはトークン消費が大きいが、**Claude Max サブスク(定額)で回すため従量課金リスクは小さい**。予算ガードは実時間/リクエスト数を主軸に。

---

## 14. 用語集
- **画面インベントリ(screen_inventory.json)**: Phase1 が出力し Phase2/WebUI が読む唯一の契約。
- **dedup_key**: `(正規化ルート, DOM骨格hash)`。SPA と古典アプリ双方の画面同一判定。
- **Hypothesis(仮説/方針)**: ビジネスロジック攻撃の単位。WebUI の HYPOTHESES に表示。
- **人間ハンドオフ**: 認証等の技術的不能点で人間に処理を渡す設計点。Cookie 注入はしない。
- **証拠規律**: confirmed に negative control + 2 positive replays を要求する不変条件。
```
