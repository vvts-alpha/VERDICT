// DESIGN §8.1 / §8.4 — state API + WebSocket.
// Project AssessmentState into StateView and push. Poll the state.sqlite that a separate process
// (crawler/labeler) writes, via events.seq, and push new events as diffs (since there are no in-process events).

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { extname, join, normalize, resolve, sep } from "node:path";
import { WebSocket, WebSocketServer } from "ws";

import { AssessmentStore, buildReportModel, buildStateView, isInScope, parseTargetUrl, renderFindingsCsv, renderInventoryHtml, renderMarkdown, renderReportHtml, renderScreensCsv } from "@veritas/core";
import type { TargetInput, WsMessage, ControlCommand, ScopePolicy } from "@veritas/core";
import { htmlToPdf, validateOpenApiDocument } from "@veritas/crawler";
import { resolveLlmConfig, makeLlmClient } from "@veritas/llm";
import type { AssessmentState } from "@veritas/core";
import { handleAuthSubmit, handleLogout, roleForReq, loginPageHtml } from "./auth.js";
import type { AuthConfig, Role } from "./auth.js";
import { Supervisor, type RunLauncherConfig, type StartRunInput } from "./supervisor.js";
import { Relay } from "./relay.js";
import { continueSession, SessionContinuationError } from "./continue-session.js";

export interface ServerOptions {
  runsDir: string;
  port?: number;
  host?: string;
  /** Built webui (served statically). If unset, API/WS only */
  webRoot?: string;
  /** events polling interval (ms). Default 1000 */
  pollMs?: number;
  /** Log to observe connections/pushes (CLI passes console.log; tests leave it unset = silent). */
  onLog?: (msg: string) => void;
  /** If set, gate WebUI/API/WS behind auth (/login form + signed Cookie). operator has full rights,
   *  viewer is read-only (all POST and attended → 403). If unset, no auth as before.
   *  cmdServe passes it via --password / --viewer-password / env VERDICT_WEB_PASSWORD[_VIEWER]. */
  authPasswords?: AuthConfig;
  /** If set, runs can be started/stopped/resumed from the WebUI (server spawns the CLI as a child process).
   *  If unset, /api/run etc. are disabled. cmdServe injects the CLI path etc. */
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
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".webp": "image/webp",
  ".map": "application/json",
  ".woff2": "font/woff2",
};

interface AssessmentSummaryRow {
  id: string;
  phase: string;
  type: "web" | "api" | "asr";
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
        const dir = join(runsDir, ent.name);
        // asr = has an asset inventory · api = spec-seeded (no browser profile + API-only screens) · web = everything else
        const type: "web" | "api" | "asr" = existsSync(join(dir, "asset_inventory.json"))
          ? "asr"
          : !existsSync(join(dir, "browser-profile")) && state.screens.length > 0 && state.screens.every((s) => s.apis.length > 0 && !s.screenshot)
            ? "api"
            : "web";
        rows.push({
          id: state.id,
          phase: state.phase,
          type,
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
  // Newest-updated first (= running / most recent). The head of the list is the latest.
  rows.sort((a, b) => (a.updatedAt < b.updatedAt ? 1 : a.updatedAt > b.updatedAt ? -1 : 0));
  return rows;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, { "content-type": "application/json; charset=utf-8", "access-control-allow-origin": "*" });
  res.end(payload);
}

/** True if `full` is `rootAbs` or a descendant. Uses `sep` so Windows `\\` paths are not 403'd
 *  (a hard-coded "/" made every packaged-desktop static request return "forbidden"). */
export function isContainedPath(rootAbs: string, full: string, separator = sep): boolean {
  return full === rootAbs || full.startsWith(rootAbs + separator);
}

function serveStatic(res: ServerResponse, webRoot: string, urlPath: string): void {
  const rootAbs = normalize(webRoot);
  let rel = decodeURIComponent((urlPath.split("?")[0] ?? "/"));
  if (rel === "/" || rel === "") rel = "/index.html";
  const full = normalize(join(rootAbs, rel));
  if (!isContainedPath(rootAbs, full)) {
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

// DESIGN §8.3 — minimal WebUI operations: pause/resume / handoff resolve / screen exclude.
// + Phase-1 control plane: start a run (/api/run) / stop / resume (via supervisor).
function handleControl(req: IncomingMessage, res: ServerResponse, opts: ServerOptions, supervisor?: Supervisor): void {
  const url = req.url ?? "";

  // Start a run: body = { command, manifest, options }. supervisor spawns the CLI and returns a new id.
  if (url === "/api/run") {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 3 * 1024 * 1024) {
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
      if (input.command !== "pilot" && input.command !== "assess" && input.command !== "redteam" && input.command !== "asr") {
        return sendJson(res, 400, { error: "command must be 'pilot', 'assess', 'redteam', or 'asr'" });
      }
      if (input.spec !== undefined) {
        try {
          if (input.command !== "pilot") throw new Error("API specifications use AI-led diagnosis");
          validateOpenApiDocument(input.spec);
        } catch (e) { return sendJson(res, 400, { error: String(e instanceof Error ? e.message : e) }); }
      }
      const manifestTarget = (input.manifest as { target?: unknown } | null)?.target;
      if (!input.manifest || typeof input.manifest !== "object" || !manifestTarget) {
        return sendJson(res, 400, { error: "manifest.target is required" });
      }
      try {
        parseTargetUrl(String(manifestTarget)); // reject a schemeless/non-http(s) target here (else the child crashes or builds an empty scope)
      } catch (e) {
        return sendJson(res, 400, { error: e instanceof Error ? e.message : String(e) });
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

  // Stop / resume the run process (/api/run namespace; distinct from /api/assessments pause/resume (state)).
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

  // Launch a Burp active scan (REST) against an existing run → auto-import on completion (no XML export needed).
  // The child process (burp-scan CLI) upserts findings into runs/<id>/state.sqlite → reflected in the WebUI via WS projection.
  const burpCtl = url.match(/^\/api\/run\/([^/]+)\/burp-scan$/);
  if (burpCtl) {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    const id = decodeURIComponent(burpCtl[1] ?? "");
    if (!existsSync(join(opts.runsDir, id, "state.sqlite"))) return sendJson(res, 404, { error: "assessment not found" });
    if (supervisor.isRunning(id)) return sendJson(res, 409, { error: "a run is already active for this assessment" });
    supervisor.burpScan(id);
    return sendJson(res, 200, { ok: true });
  }

  // 💬 Ask: read-only Q&A over this assessment (findings/screens/scope). Uses the configured LLM
  // (VERDICT_LLM_PROVIDER — OpenAI-compatible or claude CLI), not a hardcoded Claude spawn.
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

  // Upload a Burp Pro XML report → import into an existing run → AI re-verify High+.
  // The server does not merge in-process; it saves the XML and spawns the CLI (burp-import) (import + verification
  // are consolidated on the CLI side / server = control plane). The child upserts findings → reflected in the WebUI via WS projection. body = raw XML (large).
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
  // Guard writes here: even if the DB is temporarily locked and unwritable (contended by a spawned pilot),
  // just close the store and return 503 — throwing would take down the whole server via the request handler.
  const mutateAndReply = (id: string, store: AssessmentStore, fn: () => void): void => {
    try {
      fn();
    } catch (e) {
      try {
        store.close();
      } catch {
        /* ignore already-closed etc. */
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

  // Bulk exclude (a site-tree parent node = exclude the whole subtree at once). body = { screenIds: [...] }.
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

  // Live reconfigure of a running scan. body = { addHosts?, addInScopePathPrefixes?, rateMs?, maxScreens?, note? }.
  // Appends a control_command event the pilot applies at its next between-screens checkpoint (operator-only; viewer POSTs are 403'd above).
  m = url.match(/^\/api\/assessments\/([^/]+)\/reconfigure$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 64 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      let cmd: ControlCommand;
      try {
        const j = JSON.parse(body) as Record<string, unknown>;
        const strs = (v: unknown): string[] | undefined =>
          Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim().length > 0) : undefined;
        cmd = {};
        const addHosts = strs(j.addHosts);
        if (addHosts?.length) cmd.addHosts = addHosts;
        const addPaths = strs(j.addInScopePathPrefixes);
        if (addPaths?.length) cmd.addInScopePathPrefixes = addPaths;
        if (typeof j.rateMs === "number" && Number.isFinite(j.rateMs) && j.rateMs >= 0) cmd.rateMs = j.rateMs;
        if (typeof j.maxScreens === "number" && Number.isFinite(j.maxScreens) && j.maxScreens > 0) cmd.maxScreens = Math.floor(j.maxScreens);
        if (typeof j.note === "string" && j.note.trim().length > 0) cmd.note = j.note.slice(0, 500);
      } catch {
        try {
          store.close();
        } catch {
          /* noop */
        }
        return sendJson(res, 400, { error: "invalid JSON body" });
      }
      if (Object.keys(cmd).length === 0) {
        try {
          store.close();
        } catch {
          /* noop */
        }
        return sendJson(res, 400, { error: "no applicable fields (addHosts / addInScopePathPrefixes / rateMs / maxScreens / note)" });
      }
      mutateAndReply(id, store, () => store.appendControlCommand(id, cmd));
    });
    return;
  }

  // Add a target URL to a running (or resumable) scan for extra investigation. body = { url, extendScope? }.
  // Refuses to silently widen scope (authorized-targets invariant): an out-of-scope host needs extendScope:true
  // (the operator confirming it is within their authorization). Appends a target_injected event the pilot enrolls
  // at its next drain checkpoint; on an idle run it is picked up on the next Resume. Operator-only (viewer POSTs 403'd above).
  m = url.match(/^\/api\/assessments\/([^/]+)\/add-target$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 8 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      const closeQuietly = (): void => {
        try {
          store.close();
        } catch {
          /* noop */
        }
      };
      let target: URL;
      let extendScope = false;
      try {
        const j = JSON.parse(body) as { url?: unknown; extendScope?: unknown };
        if (typeof j.url !== "string" || j.url.trim().length === 0) throw new Error("missing url");
        target = parseTargetUrl(j.url.trim()); // rejects schemeless / non-http(s) with an actionable message
        extendScope = j.extendScope === true;
      } catch (e) {
        closeQuietly();
        return sendJson(res, 400, { error: `invalid target: ${String(e instanceof Error ? e.message : e).slice(0, 160)}` });
      }
      const state = store.loadAssessment(id);
      if (!state) {
        closeQuietly();
        return sendJson(res, 404, { error: "not found" });
      }
      let scope = state.scope;
      if (!isInScope(target.href, scope)) {
        if (!extendScope) {
          closeQuietly();
          return sendJson(res, 400, { error: `out of scope: ${target.host}${target.pathname}. Set extendScope:true to widen (confirm the host is within your authorization).` });
        }
        const widened = widenScopeForUrl(scope, target);
        if (!widened) {
          closeQuietly();
          return sendJson(res, 400, { error: `cannot widen scope to ${target.href}: blocked by an out-of-scope rule` });
        }
        scope = widened;
      }
      mutateAndReply(id, store, () => {
        if (scope !== state.scope) store.updateScope(id, scope); // persist the widening (live re-sync + resume both read it)
        store.appendTargetInjection(id, target.href);
      });
    });
    return;
  }

  // Live session injection (Option B): the operator logged in mid-scan (e.g. via the desktop's embedded browser),
  // capturing a cookie file — inject it into the RUNNING pilot. body = { cookieFile }. Only the PATH is queued (as a
  // control_command the pilot applies at its next checkpoint); the cookie stays in the local file. The path MUST be
  // inside runsDir (the pilot reads it) — reject anything outside (no arbitrary file read). Operator-only (viewer 403'd above).
  m = url.match(/^\/api\/assessments\/([^/]+)\/continue-session$/);
  if (m) {
    if (!supervisor) return sendJson(res, 400, { error: "run launcher disabled" });
    const id = decodeURIComponent(m[1] ?? "");
    if (!/^[a-zA-Z0-9_-]+$/.test(id)) return sendJson(res, 400, { error: "invalid assessment id" });
    let body = "";
    req.on("data", (chunk) => { body += chunk; if (body.length > 8192) req.destroy(); });
    req.on("end", () => {
      const store = openStore(id);
      if (!store) return sendJson(res, 404, { error: "assessment not found" });
      try {
        const input = JSON.parse(body) as { cookieFile: string; handoffId?: string; role?: string };
        if (typeof input.cookieFile !== "string") throw new Error("cookieFile required");
        sendJson(res, 200, continueSession(opts.runsDir, id, input, store, supervisor));
      } catch (e) {
        sendJson(res, 400, { error: e instanceof SessionContinuationError ? e.message : "Could not continue; check the captured session and saved run", ...(e instanceof SessionContinuationError && e.roles ? { roles: e.roles } : {}) });
      } finally { store.close(); }
    });
    return;
  }

  m = url.match(/^\/api\/assessments\/([^/]+)\/inject-session$/);
  if (m) {
    const id = decodeURIComponent(m[1] ?? "");
    const store = openStore(id);
    if (!store) return sendJson(res, 404, { error: "not found" });
    let body = "";
    let tooBig = false;
    req.on("data", (c) => {
      body += c;
      if (body.length > 8 * 1024) {
        tooBig = true;
        req.destroy();
      }
    });
    req.on("end", () => {
      if (tooBig) return;
      const closeQuietly = (): void => {
        try {
          store.close();
        } catch {
          /* noop */
        }
      };
      let cookieFile: string;
      try {
        const j = JSON.parse(body) as { cookieFile?: unknown };
        if (typeof j.cookieFile !== "string" || !j.cookieFile.trim()) throw new Error("cookieFile required");
        cookieFile = resolve(j.cookieFile.trim());
      } catch (e) {
        closeQuietly();
        return sendJson(res, 400, { error: `invalid body: ${String(e instanceof Error ? e.message : e).slice(0, 120)}` });
      }
      const runsAbs = resolve(opts.runsDir);
      if (cookieFile !== runsAbs && !cookieFile.startsWith(runsAbs + sep)) {
        closeQuietly();
        return sendJson(res, 400, { error: "cookieFile must be inside the runs directory" });
      }
      if (!existsSync(cookieFile)) {
        closeQuietly();
        return sendJson(res, 400, { error: "cookieFile does not exist" });
      }
      mutateAndReply(id, store, () => store.appendControlCommand(id, { injectCookieFile: cookieFile, note: "operator injected a live session" }));
    });
    return;
  }

  sendJson(res, 404, { error: "unknown control endpoint" });
}

/** Widen a scope just enough to bring `u` in-scope: add its host (and, if the scope is path-restricted, its path prefix).
 *  Returns null if an out-of-scope rule still blocks it (never silently overrides an explicit exclusion). */
function widenScopeForUrl(scope: ScopePolicy, u: URL): ScopePolicy | null {
  const host = u.host.toLowerCase();
  let s: ScopePolicy = {
    ...scope,
    inScopeHosts: [...new Set([...scope.inScopeHosts, host])],
    outOfScopeHosts: scope.outOfScopeHosts.filter((h) => h.toLowerCase() !== host),
  };
  if (isInScope(u.href, s)) return s;
  // path-restricted scope: also add this URL's path prefix
  s = { ...s, inScopePathPrefixes: [...new Set([...s.inScopePathPrefixes, u.pathname])] };
  return isInScope(u.href, s) ? s : null; // still blocked (e.g. an outOfScopePathPrefix) → refuse
}

function handleHttp(req: IncomingMessage, res: ServerResponse, opts: ServerOptions, supervisor?: Supervisor, relay?: Relay): void {
  const url = req.url ?? "/";
  // Auth gate (only when authPasswords is set). /login and POST /auth pass through; everything else requires the Cookie.
  const cfg = opts.authPasswords;
  let role: Role = "operator"; // when auth is off, treat as full rights (as before)
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
    // Serve the public brand assets referenced by the login page (logo, favicon) even when unauthenticated
    //   — otherwise the gate 302s to /login and the login page's logo/favicon break.
    if (req.method === "GET" && opts.webRoot && (url === "/verdict-title.png" || url === "/favicon.png")) {
      serveStatic(res, opts.webRoot, url);
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
    // viewer is read-only: mutating (all POST goes through handleControl) is operator-only.
    if (role === "viewer" && req.method === "POST") {
      sendJson(res, 403, { error: "forbidden: viewer is read-only" });
      return;
    }
  }
  // Own role (so the WebUI can conditionally show operator-only buttons). If no auth, authEnabled:false.
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
  // attended×LiveHands: the list of role sessions held by the child (agent) reverse-connected to this run.
  const sess = url.match(/^\/api\/assessments\/([^/?]+)\/sessions$/);
  if (sess) {
    sendJson(res, 200, relay?.rolesFor(decodeURIComponent(sess[1] ?? "")) ?? []);
    return;
  }
  // Ask history: the persisted conversation for this run (so history survives a reload). (POST → handleControl.)
  const chatHist = url.match(/^\/api\/assessments\/([^/?]+)\/chat$/);
  if (chatHist) {
    const id = decodeURIComponent(chatHist[1] ?? "");
    let history: Array<{ role: string; content: string }> = [];
    if (/^[a-z0-9_-]+$/i.test(id)) {
      try {
        history = JSON.parse(readFileSync(join(opts.runsDir, id, "chat.json"), "utf8")) as typeof history;
      } catch {
        history = [];
      }
    }
    sendJson(res, 200, { messages: history });
    return;
  }
  // Screen screenshot: serve runs/<id>/artifacts/screens/<screenId>.png (for WebUI display).
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
  // Finding screenshot: serve runs/<id>/artifacts/findings/<findingId>.png (visual evidence, captured at record time).
  const fshot = url.match(/^\/api\/assessments\/([^/]+)\/findings\/([^/?]+)\/screenshot/);
  if (fshot) {
    const sid = decodeURIComponent(fshot[1] ?? "");
    const fid = decodeURIComponent(fshot[2] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(sid) || !/^[a-z0-9_-]+$/i.test(fid)) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const file = join(opts.runsDir, sid, "artifacts", "findings", `${fid}.png`);
    if (existsSync(file) && statSync(file).isFile()) {
      res.writeHead(200, { "content-type": "image/png", "cache-control": "no-cache", "access-control-allow-origin": "*" });
      res.end(readFileSync(file));
    } else {
      res.writeHead(404);
      res.end("no screenshot");
    }
    return;
  }
  // Evidence artifact: return the req/resp for the evId a finding cites (headers already masked). evId is unique, so search across screens.
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
      requestRaw: readText("request.http.txt"), // full request (raw HTTP)
      responseRaw: readText("response.http.txt")?.slice(0, 24000) ?? null,
    });
    return;
  }
  // Download report / screen inventory (generate the latest on the fly). md/html/pdf/csv.
  const rep = url.match(/^\/api\/assessments\/([^/?]+)\/(report|inventory)(?:\?|$)/);
  if (rep) {
    const fmt = new URL(url, "http://localhost").searchParams.get("format");
    void serveReport(res, opts.runsDir, decodeURIComponent(rep[1] ?? ""), rep[2] as "report" | "inventory", fmt);
    return;
  }
  // ASR asset inventory (runs/<id>/asset_inventory.json) — read by the WebUI Assets tab. Missing → empty inventory.
  const assetsM = url.match(/^\/api\/assessments\/([^/?]+)\/assets(?:\?|$)/);
  if (assetsM) {
    const aid = decodeURIComponent(assetsM[1] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(aid)) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const invFile = join(opts.runsDir, aid, "asset_inventory.json");
    if (!existsSync(invFile) || !statSync(invFile).isFile()) {
      sendJson(res, 404, { error: "not an ASR run" }); // no inventory → the WebUI treats this as a web/API run
      return;
    }
    try {
      sendJson(res, 200, JSON.parse(readFileSync(invFile, "utf8")));
    } catch {
      sendJson(res, 200, { version: 1, generatedAt: "", apex: "", assets: [] }); // exists but mid-write
    }
    return;
  }
  // ASR host screenshot: runs/<id>/artifacts/hosts/<host>.png. Hostnames contain dots, so the id check allows
  // [a-z0-9.-] (and rejects "..") rather than the screen route's stricter alnum set — traversal is impossible (no slash).
  const hostShot = url.match(/^\/api\/assessments\/([^/]+)\/hosts\/([^/?]+)\/screenshot/);
  if (hostShot) {
    const aid = decodeURIComponent(hostShot[1] ?? "");
    const host = decodeURIComponent(hostShot[2] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(aid) || !/^[a-z0-9.-]+$/i.test(host) || host.includes("..")) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const file = join(opts.runsDir, aid, "artifacts", "hosts", `${host}.png`);
    if (existsSync(file) && statSync(file).isFile()) {
      res.writeHead(200, { "content-type": "image/png", "cache-control": "no-cache", "access-control-allow-origin": "*" });
      res.end(readFileSync(file));
    } else {
      res.writeHead(404);
      res.end("no screenshot");
    }
    return;
  }
  // Run log (the spawned child's stdout/stderr) — for the ASR Log tab. Empty 200 while nothing's been written yet.
  const runLog = url.match(/^\/api\/assessments\/([^/?]+)\/run-log(?:\?|$)/);
  if (runLog) {
    const aid = decodeURIComponent(runLog[1] ?? "");
    if (!/^[a-z0-9_-]+$/i.test(aid)) {
      res.writeHead(400);
      res.end("bad id");
      return;
    }
    const file = join(opts.runsDir, aid, "run.log");
    const body = existsSync(file) && statSync(file).isFile() ? readFileSync(file) : "";
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8", "cache-control": "no-cache" });
    res.end(body);
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
  sendJson(res, 200, { service: "verdict-server", runsDir: opts.runsDir });
}

const CHAT_SYSTEM = `You are a security-assessment assistant embedded in VERDICT's web UI. Answer the operator's questions about THIS assessment using ONLY the assessment data provided below (findings, screens, scope, stats). Cite finding ids (e.g. f-003) and screen ids when relevant. Be concise and concrete. If something is not in the data, say so plainly — do NOT invent vulnerabilities, severities, or facts. For risk/impact or remediation you may reason generally, but ground claims in the recorded evidence.`;

/** Format assessment state into context text for Claude (finding bodies + screen list + scope). */
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

/** 💬 Ask body: conversation + assessment snapshot → configured LLM (Settings / VERDICT_LLM_*). Prefers the Light model. */
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
    const llm = makeLlmClient(
      resolveLlmConfig(process.env, {
        claudeDefaultModel: "claude-sonnet-5",
        // Ask is cheap Q&A — Light if set, else Deep / Claude default.
        explicitModel: process.env.VERDICT_LLM_FAST_MODEL || undefined,
      }),
    );
    const r = await llm.complete({
      system: `${CHAT_SYSTEM}\n\n# Assessment data\n${buildChatContext(state)}`,
      prompt: `${transcript}\n\nAssistant:`,
      timeoutMs: 120_000,
    });
    // Persist the full conversation so the Ask history survives a reload (part of the run's record).
    try {
      writeFileSync(join(runsDir, id, "chat.json"), `${JSON.stringify([...messages, { role: "assistant", content: r.text }], null, 2)}\n`);
    } catch {
      /* non-fatal: the answer is still returned even if persistence fails */
    }
    sendJson(res, 200, { answer: r.text, model: r.model });
  } catch (e) {
    sendJson(res, 500, { error: `chat failed: ${String(e).slice(0, 200)}` });
  }
}

const REPORT_ALLOWED: Record<"report" | "inventory", string[]> = {
  report: ["md", "html", "pdf", "csv"],
  inventory: ["csv", "html"],
};

/** Read raw HTTP req/resp from artifacts/<screen>/<evId>/ (for report embedding). evId is unique, so search all screens. */
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

/** Generate and serve the report/screen inventory in the requested format (render the latest on the fly). pdf uses Chromium print. */
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

  // Reports are attachments in every format; inventory HTML retains its preview.
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
    } else if (kind === "report" && fmt === "csv") {
      body = renderFindingsCsv(model);
      type = "text/csv; charset=utf-8";
      filename = "findings.csv";
    } else if (kind === "report" && fmt === "pdf") {
      body = await htmlToPdf(renderReportHtml(model), { noSandbox: true });
      type = "application/pdf";
      filename = "report.pdf";
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
    sendJson(res, 500, { error: `render failed: ${String(e).split("\n")[0]!.slice(0, 300)}` });
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
    if (lastSeq !== 0 && view.lastSeq === lastSeq) return; // no change
    if (lastSeq === 0) {
      send({ type: "snapshot", view });
    } else {
      const newEvents = state.events.filter((e) => e.seq > lastSeq);
      send({ type: "events", events: newEvents, view });
      if (newEvents.length > 0) log(`⇢ ${id}: +${newEvents.length} event(s) → seq ${view.lastSeq}`);
    }
    lastSeq = view.lastSeq;
  };

  tick(); // initial snapshot
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

  // noServer + manual upgrade routing to host multiple WS paths on the same server.
  //   /ws         state projection (Cookie auth)   /ws/session  operator's attended login (Cookie auth)
  //   /ws/agent   child (pilot) reverse-connection (token auth = inside relay)
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
    const role = cfg ? roleForReq(req, cfg, Date.now()) : "operator"; // no-auth is treated as operator
    if (pathname === "/ws") {
      if (!role) return void socket.destroy(); // read projection is fine for either operator/viewer once authenticated
      wss.handleUpgrade(req, socket, head, (ws) => wss.emit("connection", ws, req));
    } else if (sessionWss && pathname === "/ws/session") {
      if (role !== "operator") return void socket.destroy(); // attended takeover is operator-only (viewer not allowed)
      sessionWss.handleUpgrade(req, socket, head, (ws) => sessionWss.emit("connection", ws, req));
    } else if (agentWss && pathname === "/ws/agent") {
      agentWss.handleUpgrade(req, socket, head, (ws) => agentWss.emit("connection", ws, req)); // token is verified inside relay
    } else {
      socket.destroy();
    }
  });

  await new Promise<void>((resolve) => httpServer.listen(opts.port ?? 0, host, resolve));
  const addr = httpServer.address();
  const port = typeof addr === "object" && addr ? addr.port : (opts.port ?? 0);
  supervisor?.setControlBase(`ws://127.0.0.1:${port}`); // the child reverse-connects locally

  let closing = false;
  return {
    port,
    url: `http://${host}:${port}`,
    async close() {
      if (closing) return;
      closing = true;
      relay?.closeAll();
      await supervisor?.closeAll(); // stop child runs
      // Force-close open WS / keep-alive connections (otherwise httpServer.close won't complete).
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
