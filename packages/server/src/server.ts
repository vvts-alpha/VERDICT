// DESIGN §8.1 / §8.4 — 状態 API + WebSocket。
// AssessmentState を StateView に投影して push。別プロセス(crawler/labeler)が書く state.sqlite を
// events.seq でポーリングし、新規イベントを差分 push する(in-process イベントが無いため)。

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { extname, join, normalize } from "node:path";
import { WebSocket, WebSocketServer } from "ws";

import { AssessmentStore, buildStateView } from "@veritas/core";
import type { WsMessage } from "@veritas/core";

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
}

function listAssessments(runsDir: string): AssessmentSummaryRow[] {
  if (!existsSync(runsDir)) return [];
  const rows: Array<AssessmentSummaryRow & { mtime: number }> = [];
  for (const ent of readdirSync(runsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const dbPath = join(runsDir, ent.name, "state.sqlite");
    if (!existsSync(dbPath)) continue;
    try {
      const store = AssessmentStore.open(dbPath);
      const state = store.loadAssessment(ent.name);
      store.close();
      if (state) {
        rows.push({
          id: state.id,
          phase: state.phase,
          screens: state.screens.length,
          findings: state.findings.length,
          mtime: statSync(dbPath).mtimeMs,
        });
      }
    } catch {
      /* skip unreadable */
    }
  }
  // 最近書き込まれた順(= 実行中 / 直近)。WebUI の既定選択(?id 無し)が最新を指すように。
  rows.sort((a, b) => b.mtime - a.mtime);
  return rows.map(({ mtime: _mtime, ...r }) => r);
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
function handleControl(req: IncomingMessage, res: ServerResponse, opts: ServerOptions): void {
  const url = req.url ?? "";
  const openStore = (id: string): AssessmentStore | null => {
    const dbPath = join(opts.runsDir, id, "state.sqlite");
    return existsSync(dbPath) ? AssessmentStore.open(dbPath) : null;
  };
  const replyView = (id: string, store: AssessmentStore): void => {
    const state = store.loadAssessment(id);
    store.close();
    sendJson(res, 200, state ? buildStateView(state) : { ok: true });
  };

  let m = url.match(/^\/api\/assessments\/([^/]+)\/(pause|resume)$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    store.setPaused(id, m[2] === "pause", "via WebUI");
    return replyView(id, store);
  }

  m = url.match(/^\/api\/assessments\/([^/]+)\/handoffs\/([^/]+)\/resolve$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const handoffId = decodeURIComponent(m[2] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    const handoff = store.loadAssessment(id)?.handoffs.find((h) => h.id === handoffId);
    if (handoff) store.upsertHandoff(id, { ...handoff, status: "resolved", resolvedAt: new Date().toISOString() });
    return replyView(id, store);
  }

  m = url.match(/^\/api\/assessments\/([^/]+)\/screens\/([^/]+)\/exclude$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const screenId = decodeURIComponent(m[2] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    store.setScreenScanStatus(id, screenId, "excluded");
    return replyView(id, store);
  }

  sendJson(res, 404, { error: "unknown control endpoint" });
}

function handleHttp(req: IncomingMessage, res: ServerResponse, opts: ServerOptions): void {
  if (req.method === "POST") {
    handleControl(req, res, opts);
    return;
  }
  const url = req.url ?? "/";
  if (url === "/api/assessments") {
    sendJson(res, 200, listAssessments(opts.runsDir));
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
    sendJson(res, 200, {
      request: readJson("request.json"),
      response: readJson("response.json"),
      meta: readJson("meta.json"),
      body: body.slice(0, 20000),
    });
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
  sendJson(res, 200, { service: "umbra-hands-server", runsDir: opts.runsDir });
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
  const httpServer = createServer((req, res) => handleHttp(req, res, opts));
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });
  const sockets = new Set<WebSocket>();
  wss.on("connection", (ws, req) => {
    sockets.add(ws);
    ws.on("close", () => sockets.delete(ws));
    handleWsConnection(ws, req, { ...opts, pollMs });
  });

  await new Promise<void>((resolve) => httpServer.listen(opts.port ?? 0, host, resolve));
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr ? addr.port : (opts.port ?? 0);

  let closing = false;
  return {
    port,
    url: `http://${host}:${port}`,
    async close() {
      if (closing) return;
      closing = true;
      // 開いている WS / keep-alive 接続を強制クローズ(そうしないと httpServer.close が完走しない)。
      for (const ws of sockets) {
        try {
          ws.terminate();
        } catch {
          /* ignore */
        }
      }
      await new Promise<void>((resolve) => wss.close(() => resolve()));
      (httpServer as unknown as { closeAllConnections?: () => void }).closeAllConnections?.();
      await new Promise<void>((resolve) => httpServer.close(() => resolve()));
    },
  };
}
