// DESIGN §8.1 / §8.4 — 状態 API + WebSocket。
// AssessmentState を StateView に投影して push。別プロセス(crawler/labeler)が書く state.sqlite を
// events.seq でポーリングし、新規イベントを差分 push する(in-process イベントが無いため)。

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { WebSocket, WebSocketServer } from "ws";

import { AssessmentStore, buildReportModel, buildStateView, renderFindingsCsv, renderInventoryHtml, renderMarkdown, renderReportHtml, renderScreensCsv } from "@veritas/core";
import type { TargetInput, WsMessage } from "@veritas/core";
import { htmlToPdf } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import type { AssessmentState } from "@veritas/core";
import { handleAuthSubmit, handleLogout, roleForReq, loginPageHtml } from "./auth.js";
import type { AuthConfig, Role } from "./auth.js";
import { Supervisor, type RunLauncherConfig, type StartRunInput } from "./supervisor.js";
import { Relay } from "./relay.js";

export interface ServerOptions {
  runsDir: string;
  port?: number;
  host?: string;
  /** ビルド済み webui(静的配信)。未指定なら API/WS のみ */
  webRoot?: string;
  /** events ポーリング間隔(ms)。既定 1000 */
  pollMs?: number;
  /** 接続/push を可観測化するログ(CLI が console.log を渡す。テストは未指定=無音)。 */
  onLog?: (msg: string) => void;
  /** 設定すると WebUI/API/WS を認証ゲート(/login フォーム + 署名 Cookie)。operator は全権、
   *  viewer は read-only(全 POST と attended を 403)。未設定なら従来どおり無認証。
   *  cmdServe が --password / --viewer-password / env AMRAAM_WEB_PASSWORD[_VIEWER] で渡す。 */
  authPasswords?: AuthConfig;
  /** 設定すると WebUI から run を起動/停止/再開できる(server が CLI を子プロセスで spawn)。
   *  未設定なら /api/run 等は無効。cmdServe が CLI パス等を DI。 */
  runLauncher?: RunLauncherConfig;
}

export interface RunningServer {
  port: number;
  url: string;
  close(): Promise<void>;
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".svg": "image/svg+xml",
  ".ico": "image/x-icon",
  ".map": "application/json",
  ".woff2": "font/woff2",
};

interface AssessmentSummaryRow {
  id: string;
  phase: string;
  screens: number;
  findings: number;
  target: TargetInput;
  createdAt: string;
  updatedAt: string;
}

function listAssessments(runsDir: string): AssessmentSummaryRow[] {
  if (!existsSync(runsDir)) return [];
  const rows: AssessmentSummaryRow[] = [];
  for (const ent of readdirSync(runsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const dbPath = join(runsDir, ent.name, "state.sqlite");
    if (!existsSync(dbPath)) continue;
    try {
      const store = AssessmentStore.open(dbPath);
      const state = store.loadAssessment(ent.name);
      const summary = store.listAssessments().find((s) => s.id === ent.name);
      store.close();
      if (state) {
        rows.push({
          id: state.id,
          phase: state.phase,
          screens: state.screens.length,
          findings: state.findings.length,
          target: state.target,
          createdAt: summary?.createdAt ?? "",
          updatedAt: summary?.updatedAt ?? "",
        });
      }
    } catch {
      /* skip unreadable */
    }
  }
  // 更新が新しい順(= 実行中 / 直近)。一覧の先頭が最新になる。
  rows.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0));
  return rows;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" });
  res.end(payload);
}

function serveStatic(res: ServerResponse, webRoot: string, urlPath: string): void {
  const rootAbs = normalize(webRoot);
  let rel = decodeURIComponent((urlPath.split("?")[0] ?? "/"));
  if (rel === "/" || rel === "") rel = "/index.html";
  const full = normalize(join(rootAbs, rel));
  if (full !== rootAbs && !full.startsWith(rootAbs + "/")) {
    res.writeHead(403);
    res.end("forbidden");
    return;
  }
  if (existsSync(full) && statSync(full).isFile()) {
    res.writeHead(200, { "content-type": MIME[extname(full)] ?? "application/octet-stream" });
    res.end(readFileSync(full));
    return;
  }
  // SPA fallback → index.html
  const index = join(rootAbs, "index.html");
  if (existsSync(index)) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(readFileSync(index));
    return;
  }
  res.writeHead(404);
  res.end("not found");
}

// DESIGN §8.3 — WebUI 最小操作: pause/resume / handoff resolve / screen exclude。
// + Phase-1 制御面: run の起動(/api/run) / 停止 / 再開(supervisor 経由)。
function handleControl(req: IncomingMessage, res: ServerResponse, opts: ServerOptions, supervisor?: Supervisor): void {
  const url = req.url ?? "";

  // run 起動: body = { command, manifest, options }。supervisor が CLI を spawn し、新 id を返す。
  if (url === "/api/run") {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 256 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      let input: StartRunInput;
      try {
        input = JSON.parse(body) as StartRunInput;
      } catch {
        return sendJson(res, 400, { error: "invalid JSON body" });
      }
      if (input.command !== "pilot" && input.command !== "assess") {
        return sendJson(res, 400, { error: "command must be 'pilot' or 'assess'" });
      }
      if (!input.manifest || typeof input.manifest !== "object" || !(input.manifest as { target?: unknown }).target) {
        return sendJson(res, 400, { error: "manifest.target is required" });
      }
      try {
        const { id } = supervisor.start(input);
        sendJson(res, 200, { id });
      } catch (e) {
        sendJson(res, 500, { error: `failed to launch: ${String(e).slice(0, 200)}` });
      }
    });
    return;
  }

  // run プロセス停止 / 再開(/api/run 名前空間。/api/assessments の pause/resume(状態)とは別物)
  const runCtl = url.match(/^\/api\/run\/([^/]+)\/(stop|resume)$/);
  if (runCtl) {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    const id = decodeURIComponent(runCtl[1] ?? "");
    if (runCtl[2] === "stop") {
      const ok = supervisor.stop(id);
      return sendJson(res, ok ? 200 : 409, ok ? { ok: true } : { error: "not running" });
    }
    if (supervisor.isRunning(id)) return sendJson(res, 409, { error: "already running" });
    supervisor.resume(id);
    return sendJson(res, 200, { ok: true });
  }

  // 既存 run に対して Burp 能動スキャン(REST)を起動 → 完了時に自動取り込み(XML export 不要)。
  // 子プロセス(burp-scan CLI)が runs/<id>/state.sqlite に findings を upsert → WS 投影で WebUI に反映。
  const burpCtl = url.match(/^\/api\/run\/([^/]+)\/burp-scan$/);
  if (burpCtl) {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    const id = decodeURIComponent(burpCtl[1] ?? "");
    if (!existsSync(join(opts.runsDir, id, "state.sqlite"))) return sendJson(res, 404, { error: "assessment not found" });
    if (supervisor.isRunning(id)) return sendJson(res, 409, { error: "a run is already active for this assessment" });
    supervisor.burpScan(id);
    return sendJson(res, 200, { ok: true });
  }

  // 💬 Ask: その assessment の findings/screens/scope を文脈に Claude へ質問する(読み取り Q&A)。
  const chat = url.match(/^\/api\/assessments\/([^/]+)\/chat$/);
  if (chat) {
    const id = decodeURIComponent(chat[1] ?? "");
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 256 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return sendJson(res, 413, { error: "too large" });
      let parsed: { messages?: Array<{ role?: string; content?: string }> };
      try {
        parsed = JSON.parse(body) as typeof parsed;
      } catch {
        return sendJson(res, 400, { error: "invalid JSON body" });
      }
      const messages = (parsed.messages ?? []).filter((m) => typeof m.content === "string" && m.content.trim());
      if (!messages.length) return sendJson(res, 400, { error: "messages required" });
      void serveChat(res, opts.runsDir, id, messages as Array<{ role: string; content: string }>);
    });
    return;
  }

  // Burp Pro の XML レポートをアップロード → 既存 run に取り込み → High+ を AI 再検証。
  // server は in-process でマージせず、XML を保存して CLI(burp-import)を spawn する(取り込み + 検証は
  // CLI 側に集約 / server = 制御面)。findings は子が upsert → WS 投影で WebUI に反映。body = 生 XML(大)。
  const burpImp = url.match(/^\/api\/assessments\/([^/]+)\/burp-import$/);
  if (burpImp) {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    const id = decodeURIComponent(burpImp[1] ?? "");
    if (!existsSync(join(opts.runsDir, id, "state.sqlite"))) return sendJson(res, 404, { error: "assessment not found" });
    if (supervisor.isRunning(id)) return sendJson(res, 409, { error: "a run is already active for this assessment" });
    const chunks: Buffer[] = [];
    let size = 0;
    let tooBig = false;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > 128 * 1024 * 1024) {
        tooBig = true;
        req.destroy();
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => {
      if (tooBig) return sendJson(res, 413, { error: "report too large (>128MB)" });
      const reportPath = join(opts.runsDir, id, "burp-upload.xml");
      try {
        writeFileSync(reportPath, Buffer.concat(chunks));
      } catch (e) {
        return sendJson(res, 500, { error: `failed to save upload: ${String(e).slice(0, 160)}` });
      }
      supervisor.burpImport(id, reportPath);
      sendJson(res, 200, { ok: true });
    });
    return;
  }

  const openStore = (id: string): AssessmentStore | null => {
    const dbPath = join(opts.runsDir, id, "state.sqlite");
    return existsSync(dbPath) ? AssessmentStore.open(dbPath) : null;
  };
  const replyView = (id: string, store: AssessmentStore): void => {
    const state = store.loadAssessment(id);
    store.close();
    sendJson(res, 200, state ? buildStateView(state) : { ok: true });
  };
  // 書き込み系はここで防御: DB が(spawn された pilot との競合で)一時的にロックされ書けなくても、
  // store を閉じて 503 を返すだけにする — 例外を投げるとリクエストハンドラ経由でサーバごと落ちるため。
  const mutateAndReply = (id: string, store: AssessmentStore, fn: () => void): void => {
    try {
      fn();
    } catch (e) {
      try {
        store.close();
      } catch {
        /* 既にクローズ済み等は無視 */
      }
      sendJson(res, 503, { error: `state store busy, retry shortly: ${String(e).slice(0, 120)}` });
      return;
    }
    replyView(id, store);
  };

  let m = url.match(/^\/api\/assessments\/([^/]+)\/(pause|resume)$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    return mutateAndReply(id, store, () => store.setPaused(id, m![2] === "pause", "via WebUI"));
  }

  m = url.match(/^\/api\/assessments\/([^/]+)\/handoffs\/([^/]+)\/resolve$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const handoffId = decodeURIComponent(m[2] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    return mutateAndReply(id, store, () => {
      const handoff = store.loadAssessment(id)?.handoffs.find((h) => h.id === handoffId);
      if (handoff) store.upsertHandoff(id, { ...handoff, status: "resolved", resolvedAt: new Date().toISOString() });
    });
  }

  m = url.match(/^\/api\/assessments\/([^/]+)\/screens\/([^/]+)\/exclude$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const screenId = decodeURIComponent(m[2] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    return mutateAndReply(id, store, () => store.setScreenScanStatus(id, screenId, "excluded"));
  }

  // 一括 exclude(サイトツリーの親ノード = 部分木をまとめて除外)。body = { screenIds: [...] }。
  m = url.match(/^\/api\/assessments\/([^/]+)\/exclude-screens$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 256 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      let ids: string[] = [];
      try {
        const j = JSON.parse(body) as { screenIds?: unknown };
        ids = Array.isArray(j.screenIds) ? j.screenIds.filter((x): x is string => typeof x === "string") : [];
      } catch {
        try {
          store.close();
        } catch {
          /* noop */
        }
        return sendJson(res, 400, { error: "invalid JSON body" });
      }
      mutateAndReply(id, store, () => {
        for (const sid of ids) store.setScreenScanStatus(id, sid, "excluded");
      });
    });
    return;
  }

  sendJson(res, 404, { error: "unknown control endpoint" });
}

function handleHttp(req: IncomingMessage, res: ServerResponse, opts: ServerOptions, supervisor?: Supervisor, relay?: Relay): void {
  const url = req.url ?? "/";
  // 認証ゲート(authPasswords 設定時のみ)。/login と POST /auth は素通し、それ以外は Cookie 必須。
  const cfg = opts.authPasswords;
  let role: Role = "operator"; // 無認証時は全権扱い(従来どおり)
  if (cfg) {
    const now = Date.now();
    if (req.method === "POST" && (url === "/auth" || url.startsWith("/auth?"))) {
      handleAuthSubmit(req, res, cfg, now);
      return;
    }
    if (req.method === "GET" && (url === "/login" || url.startsWith("/login?"))) {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
      res.end(loginPageHtml(url.includes("e=1")));
      return;
    }
    if (req.method === "GET" && url === "/logout") {
      handleLogout(res);
      return;
    }
    const r = roleForReq(req, cfg, now);
    if (!r) {
      if (url.startsWith("/api/") || req.method === "POST") {
        sendJson(res, 401, { error: "unauthorized" });
      } else {
        res.writeHead(302, { location: "/login" });
        res.end();
      }
      return;
    }
    role = r;
    // viewer は read-only: mutating(全 POST は handleControl 経由)は operator 限定。
    if (role === "viewer" && req.method === "POST") {
      sendJson(res, 403, { error: "forbidden: viewer is read-only" });
      return;
    }
  }
  // 自分のロール(WebUI が operator 専用ボタンを出し分けるため)。無認証なら authEnabled:false。
  if (req.method === "GET" && (url === "/api/me" || url.startsWith("/api/me?"))) {
    sendJson(res, 200, { role, authEnabled: !!cfg });
    return;
  }
  if (req.method === "POST") {
    handleControl(req, res, opts, supervisor);
    return;
  }
  if (url === "/api/assessments") {
    const rows = listAssessments(opts.runsDir).map((r) => ({ ...r, running: supervisor?.isRunning(r.id) ?? false }));
    sendJson(res, 200, rows);
    return;
  }
  // attended×LiveHands: その run に逆接続中の子(agent)が持つ role セッション一覧。
  const sess = url.match(/^\/api\/assessments\/([^/?]+)\/sessions$/);
  if (sess) {
    sendJson(res, 200, relay?.rolesFor(decodeURIComponent(sess[1] ?? "")) ?? []);
    return;
  }
  // 画面スクショ: runs/<id>/artifacts/screens/<screenId>.png を配信(WebUI 表示用)。
  const shot = url.match(/^\/api\/assessments\/([^/]+)\/screens\/([^/?]+)\/screenshot/);
  if (shot) {
    const sid = decodeURIComponent(shot[1] ?? "");
    const scr = decodeURIComponent(shot[2] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(sid) || !/^[a-z0-9_-]+$/i.test(scr)) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const file = join(opts.runsDir, sid, "artifacts", "screens", `${scr}.png`);
    if (existsSync(file) && statSync(file).isFile()) {
      res.writeHead(200, { "content-type": "image/png", "cache-control": "no-cache", "access-control-allow-origin": "*" });
      res.end(readFileSync(file));
    } else {
      res.writeHead(404);
      res.end("no screenshot");
    }
    return;
  }
  // 証拠アーティファクト: finding が引用する evId の req/resp を返す(headers はマスク済)。evId は一意なので screen 横断で探す。
  const evm = url.match(/^\/api\/assessments\/([^/]+)\/evidence\/([^/?]+)/);
  if (evm) {
    const aid = decodeURIComponent(evm[1] ?? "");
    const evId = decodeURIComponent(evm[2] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(aid) || !/^ev-[a-z0-9_-]+$/i.test(evId)) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const artRoot = join(opts.runsDir, aid, "artifacts");
    let found: string | null = null;
    if (existsSync(artRoot)) {
      for (const ent of readdirSync(artRoot, { withFileTypes: true })) {
        if (!ent.isDirectory()) continue;
        const cand = join(artRoot, ent.name, evId);
        if (existsSync(cand) && statSync(cand).isDirectory()) {
          found = cand;
          break;
        }
      }
    }
    if (!found) {
      sendJson(res, 404, { error: "evidence not found" });
      return;
    }
    const readJson = (f: string): unknown => {
      try {
        return JSON.parse(readFileSync(join(found as string, f), "utf8"));
      } catch {
        return null;
      }
    };
    let body = "";
    try {
      body = readFileSync(join(found, "response.body.txt"), "utf8");
    } catch {
      /* no body */
    }
    const readText = (f: string): string | null => {
      try {
        return readFileSync(join(found as string, f), "utf8");
      } catch {
        return null;
      }
    };
    sendJson(res, 200, {
      request: readJson("request.json"),
      response: readJson("response.json"),
      meta: readJson("meta.json"),
      body: body.slice(0, 20000),
      requestRaw: readText("request.http.txt"), // リクエスト全体(生 HTTP)
      responseRaw: readText("response.http.txt")?.slice(0, 24000) ?? null,
    });
    return;
  }
  // レポート / 画面一覧のダウンロード(その場で最新を生成)。md/html/pdf/csv。
  const rep = url.match(/^\/api\/assessments\/([^/?]+)\/(report|inventory)(?:\?|$)/);
  if (rep) {
    const fmt = new URL(url, "http://localhost").searchParams.get("format");
    void serveReport(res, opts.runsDir, decodeURIComponent(rep[1] ?? ""), rep[2] as "report" | "inventory", fmt);
    return;
  }
  const m = url.match(/^\/api\/assessments\/([^/?]+)/);
  const id = m?.[1];
  if (id) {
    const dbPath = join(opts.runsDir, decodeURIComponent(id), "state.sqlite");
    if (!existsSync(dbPath)) {
      sendJson(res, 404, { error: "assessment not found" });
      return;
    }
    const store = AssessmentStore.open(dbPath);
    const state = store.loadAssessment(decodeURIComponent(id));
    store.close();
    if (!state) {
      sendJson(res, 404, { error: "assessment not found" });
      return;
    }
    sendJson(res, 200, buildStateView(state));
    return;
  }
  if (url.startsWith("/api/")) {
    sendJson(res, 404, { error: "unknown endpoint" });
    return;
  }
  if (opts.webRoot) {
    serveStatic(res, opts.webRoot, url);
    return;
  }
  sendJson(res, 200, { service: "amraam-server", runsDir: opts.runsDir });
}

const CHAT_SYSTEM = `You are a security-assessment assistant embedded in AMRAAM's web UI. Answer the operator's questions about THIS assessment using ONLY the assessment data provided below (findings, screens, scope, stats). Cite finding ids (e.g. f-003) and screen ids when relevant. Be concise and concrete. If something is not in the data, say so plainly — do NOT invent vulnerabilities, severities, or facts. For risk/impact or remediation you may reason generally, but ground claims in the recorded evidence.`;

/** assessment state を Claude への文脈テキストに整形(findings 本体 + 画面一覧 + scope)。 */
function buildChatContext(state: AssessmentState): string {
  const target = state.target.kind === "single_url" ? state.target.url : `scope_manifest ${state.target.path}`;
  const scanByScreen = new Map(state.screenScans.map((s) => [s.screenId, s.status]));
  const out: string[] = [];
  out.push(`Target: ${target} | Phase: ${state.phase} | Screens: ${state.screens.length} | Findings: ${state.findings.length}`);
  out.push(`Scope: in-hosts=[${state.scope.inScopeHosts.join(", ")}] out-hosts=[${state.scope.outOfScopeHosts.join(", ")}] in-paths=[${state.scope.inScopePathPrefixes.join(", ")}] out-paths=[${state.scope.outOfScopePathPrefixes.join(", ")}]`);
  out.push("", "## Findings");
  if (!state.findings.length) out.push("(none confirmed)");
  for (const f of state.findings) {
    const src = f.source.kind === "validator" ? `validator ${f.source.validatorName}` : `hypothesis ${f.source.hypothesisId}`;
    out.push(`### ${f.id} [${f.severity.toUpperCase()}] ${f.title}`);
    out.push(`screen=${f.screenId ?? "(cross-screen)"} | source=${src} | evidence=${f.evidenceIds.length}`);
    out.push(f.description);
    out.push(`Repro: ${f.reproSteps}`);
  }
  out.push("", "## Screens (id — url — type — auth — scan)");
  for (const s of state.screens.slice(0, 80)) {
    out.push(`- ${s.screenId} — ${s.urlTemplate} — ${s.screenType} — ${s.authState} — ${scanByScreen.get(s.screenId) ?? "queued"}`);
  }
  if (state.screens.length > 80) out.push(`… (${state.screens.length - 80} more screens)`);
  return out.join("\n");
}

/** 💬 Ask の本体: state を文脈に会話履歴を渡して Claude に答えさせる(claude CLI サブスク)。 */
async function serveChat(res: ServerResponse, runsDir: string, id: string, messages: Array<{ role: string; content: string }>): Promise<void> {
  if (!/^[a-z0-9_-]+$/i.test(id)) {
    sendJson(res, 400, { error: "bad id" });
    return;
  }
  const dbPath = join(runsDir, id, "state.sqlite");
  if (!existsSync(dbPath)) {
    sendJson(res, 404, { error: "assessment not found" });
    return;
  }
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  store.close();
  if (!state) {
    sendJson(res, 404, { error: "assessment not found" });
    return;
  }
  const transcript = messages.map((m) => `${m.role === "assistant" ? "Assistant" : "User"}: ${m.content}`).join("\n\n");
  try {
    const llm = new ClaudeCliClient({ defaultModel: "claude-sonnet-4-6" });
    const r = await llm.complete({
      system: `${CHAT_SYSTEM}\n\n# Assessment data\n${buildChatContext(state)}`,
      prompt: `${transcript}\n\nAssistant:`,
      timeoutMs: 120_000,
    });
    sendJson(res, 200, { answer: r.text, model: r.model });
  } catch (e) {
    sendJson(res, 500, { error: `chat failed: ${String(e).slice(0, 200)}` });
  }
}

const REPORT_ALLOWED: Record<"report" | "inventory", string[]> = {
  report: ["md", "html", "pdf", "csv"],
  inventory: ["csv", "html"],
};

/** artifacts/<screen>/<evId>/ から生 HTTP req/resp を読む(レポート埋め込み用)。evId は一意なので全 screen を探索。 */
function loadEvidenceArtifact(artifactsDir: string, evId: string, maxResponseBytes = 16384): { request: string | null; response: string | null; truncated: boolean } | null {
  if (!existsSync(artifactsDir)) return null;
  let dir: string | null = null;
  for (const ent of readdirSync(artifactsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const cand = join(artifactsDir, ent.name, evId);
    if (existsSync(cand) && statSync(cand).isDirectory()) {
      dir = cand;
      break;
    }
  }
  if (!dir) return null;
  const read = (f: string): string | null => {
    try {
      return readFileSync(join(dir as string, f), "utf8");
    } catch {
      return null;
    }
  };
  const request = read("request.http.txt");
  let response = read("response.http.txt");
  let truncated = false;
  if (response && response.length > maxResponseBytes) {
    response = response.slice(0, maxResponseBytes);
    truncated = true;
  }
  return { request, response, truncated };
}

/** レポート/画面一覧を要求フォーマットで生成して配信(その場で最新を描画)。pdf は Chromium 印刷。 */
async function serveReport(res: ServerResponse, runsDir: string, id: string, kind: "report" | "inventory", formatRaw: string | null): Promise<void> {
  if (!/^[a-z0-9_-]+$/i.test(id)) {
    sendJson(res, 400, { error: "bad id" });
    return;
  }
  const fmt = (formatRaw ?? (kind === "report" ? "html" : "html")).toLowerCase();
  if (!REPORT_ALLOWED[kind].includes(fmt)) {
    sendJson(res, 400, { error: `unknown format '${fmt}' (allowed: ${REPORT_ALLOWED[kind].join(",")})` });
    return;
  }
  const dbPath = join(runsDir, id, "state.sqlite");
  if (!existsSync(dbPath)) {
    sendJson(res, 404, { error: "assessment not found" });
    return;
  }
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  store.close();
  if (!state) {
    sendJson(res, 404, { error: "assessment not found" });
    return;
  }
  const artifactsDir = join(runsDir, id, "artifacts");
  const model = buildReportModel(state, new Date(), { loadEvidence: (evId) => loadEvidenceArtifact(artifactsDir, evId) });

  // {body, type, filename, inline}. inline = ブラウザ内プレビュー(html/pdf)、それ以外は添付 DL。
  let body: string | Buffer;
  let type: string;
  let filename: string;
  let inline = false;
  try {
    if (kind === "report" && fmt === "md") {
      body = renderMarkdown(model);
      type = "text/markdown; charset=utf-8";
      filename = "report.md";
    } else if (kind === "report" && fmt === "html") {
      body = renderReportHtml(model);
      type = "text/html; charset=utf-8";
      filename = "report.html";
      inline = true;
    } else if (kind === "report" && fmt === "csv") {
      body = renderFindingsCsv(model);
      type = "text/csv; charset=utf-8";
      filename = "findings.csv";
    } else if (kind === "report" && fmt === "pdf") {
      body = await htmlToPdf(renderReportHtml(model), { ...(process.env.VERITAS_BROWSER_PATH ? { executablePath: process.env.VERITAS_BROWSER_PATH } : {}), noSandbox: true });
      type = "application/pdf";
      filename = "report.pdf";
      inline = true;
    } else if (kind === "inventory" && fmt === "csv") {
      body = renderScreensCsv(model);
      type = "text/csv; charset=utf-8";
      filename = "screens.csv";
    } else {
      body = renderInventoryHtml(model);
      type = "text/html; charset=utf-8";
      filename = "inventory.html";
      inline = true;
    }
  } catch (e) {
    sendJson(res, 500, { error: `render failed: ${String(e).slice(0, 200)}` });
    return;
  }
  res.writeHead(200, {
    "content-type": type,
    "content-disposition": `${inline ? "inline" : "attachment"}; filename="${id}-${filename}"`,
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  res.end(body);
}

function handleWsConnection(ws: WebSocket, req: IncomingMessage, opts: ServerOptions): void {
  const log = opts.onLog ?? ((): void => {});
  const send = (msg: WsMessage): void => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg));
  };
  const id = new URL(req.url ?? "", "http://localhost").searchParams.get("id");
  if (!id) {
    send({ type: "error", message: "missing ?id=<assessment-id>" });
    ws.close();
    return;
  }
  const dbPath = join(opts.runsDir, id, "state.sqlite");
  if (!existsSync(dbPath)) {
    send({ type: "error", message: `no assessment '${id}'` });
    ws.close();
    return;
  }

  const store = AssessmentStore.open(dbPath);
  log(`▶ ws subscribed → ${id}`);
  let lastSeq = 0;
  const tick = (): void => {
    let state;
    try {
      state = store.loadAssessment(id);
    } catch {
      return;
    }
    if (!state) return;
    const view = buildStateView(state);
    if (lastSeq !== 0 && view.lastSeq === lastSeq) return; // 変化なし
    if (lastSeq === 0) {
      send({ type: "snapshot", view });
    } else {
      const newEvents = state.events.filter((e) => e.seq > lastSeq);
      send({ type: "events", events: newEvents, view });
      if (newEvents.length > 0) log(`⇢ ${id}: +${newEvents.length} event(s) → seq ${view.lastSeq}`);
    }
    lastSeq = view.lastSeq;
  };

  tick(); // 初回スナップショット
  const timer = setInterval(tick, opts.pollMs ?? 1000);
  const stop = (): void => {
    clearInterval(timer);
    try {
      store.close();
    } catch {
      /* already closed */
    }
  };
  ws.on("close", () => {
    log(`◼ ws left ← ${id}`);
    stop();
  });
  ws.on("error", stop);
}

export async function startServer(opts: ServerOptions): Promise<RunningServer> {
  const host = opts.host ?? "127.0.0.1";
  const pollMs = opts.pollMs ?? 1000;
  const log = opts.onLog ?? ((): void => {});
  const relay = opts.runLauncher ? new Relay() : undefined;
  const supervisor = opts.runLauncher ? new Supervisor(opts.runLauncher, relay) : undefined;
  const httpServer = createServer((req, res) => handleHttp(req, res, opts, supervisor, relay));

  // 複数 WS パスを同一サーバに載せるため noServer + 手動 upgrade ルーティング。
  //   /ws         状態投影(Cookie 認証)   /ws/session  操作者の attended ログイン(Cookie 認証)
  //   /ws/agent   子(pilot)の逆接続(token 認証 = relay 内)
  const wss = new WebSocketServer({ noServer: true });
  const agentWss = relay ? new WebSocketServer({ noServer: true }) : null;
  const sessionWss = relay ? new WebSocketServer({ noServer: true }) : null;
  const sockets = new Set<WebSocket>();
  wss.on("connection", (ws, req) => {
    sockets.add(ws);
    ws.on("close", () => sockets.delete(ws));
    handleWsConnection(ws, req, { ...opts, pollMs });
  });
  if (relay && agentWss) agentWss.on("connection", (ws, req) => relay.handleAgent(ws, req, log));
  if (relay && sessionWss)
    sessionWss.on("connection", (ws, req) => {
      sockets.add(ws);
      ws.on("close", () => sockets.delete(ws));
      relay.handleSession(ws, req);
    });
  httpServer.on("upgrade", (req, socket, head) => {
    const pathname = (req.url ?? "").split("?")[0] ?? "";
    const cfg = opts.authPasswords;
    const role = cfg ? roleForReq(req, cfg, Date.now()) : "operator"; // 無認証は operator 扱い
    if (pathname === "/ws") {
      if (!role) return void socket.destroy(); // 読み取り投影は認証済みなら operator/viewer どちらでも可
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    } else if (sessionWss && pathname === "/ws/session") {
      if (role !== "operator") return void socket.destroy(); // attended 乗っ取りは operator 限定(viewer 不可)
      sessionWss.handleUpgrade(req, socket, head, (ws) => sessionWss.emit("connection", ws, req));
    } else if (agentWss && pathname === "/ws/agent") {
      agentWss.handleUpgrade(req, socket, head, (ws) => agentWss.emit("connection", ws, req)); // token は relay 内で検証
    } else {
      socket.destroy();
    }
  });

  await new Promise<void>((resolve) => httpServer.listen(opts.port ?? 0, host, resolve));
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr ? addr.port : (opts.port ?? 0);
  supervisor?.setControlBase(`ws://127.0.0.1:${port}`); // 子はローカルに逆接続する

  let closing = false;
  return {
    port,
    url: `http://${host}:${port}`,
    async close() {
      if (closing) return;
      closing = true;
      relay?.closeAll();
      await supervisor?.closeAll(); // 子の run を停止
      // 開いている WS / keep-alive 接続を強制クローズ(そうしないと httpServer.close が完走しない)。
      for (const ws of sockets) {
        try {
          ws.terminate();
        } catch {
          /* ignore */
        }
      }
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      if (agentWss) await new Promise<void>((resolve) => agentWss.close(() => resolve()));
      if (sessionWss) await new Promise<void>((resolve) => sessionWss.close(() => resolve()));
      (httpServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}
