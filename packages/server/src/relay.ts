// Cross-process relay hub for attended×LiveHands.
// The child (pilot) **reverse-connects** to /ws/agent?id=&token= and pushes a screencast per role,
// and the operator's WebUI connects to /ws/session?id=&role=. serve relays both sides as a hub.
//   child → serve : {t:"sessions",roles:[{role,url}]} / {t:"frame",role,data,meta} / {t:"url",role,url} / {t:"copied",role,text}
//   serve → child : {t:"start",role} / {t:"stop",role} / {t:"input",role,msg}
//   operator → serve (/ws/session): {t:"mouse|key|paste|copy|nav|done", ...} → forwarded to the child as {t:"input",role,msg}
import type { IncomingMessage } from "node:http";
import type { WebSocket } from "ws";

interface AgentConn {
  ws: WebSocket;
  /** done=false means "awaiting login (needs operator input)". Becomes true on the operator's {t:"done"}. */
  roles: Map<string, { url: string; done: boolean }>;
  viewers: Map<string, Set<WebSocket>>;
}

function qp(req: IncomingMessage): URLSearchParams {
  return new URL(req.url ?? "", "http://localhost").searchParams;
}

export class Relay {
  private readonly agents = new Map<string, AgentConn>();
  private readonly tokens = new Map<string, string>();

  /** Register a per-run token at spawn time (authenticates the child's reverse-connection). */
  issueToken(id: string, token: string): void {
    this.tokens.set(id, token);
  }
  revokeToken(id: string): void {
    this.tokens.delete(id);
  }

  /** The list of roles available with a child (agent) connected to this run (used by the WebUI to decide whether to show the Sessions tab).
   *  awaiting=true means "awaiting login (needs operator input)" → the WebUI highlights the Sessions tab. */
  rolesFor(id: string): Array<{ role: string; url: string; awaiting: boolean }> {
    const a = this.agents.get(id);
    if (!a) return [];
    return [...a.roles.entries()].map(([role, v]) => ({ role, url: v.url, awaiting: !v.done }));
  }

  /** The child's (pilot) reverse-connection /ws/agent?id=&token= */
  handleAgent(ws: WebSocket, req: IncomingMessage, log: (m: string) => void): void {
    const p = qp(req);
    const id = p.get("id") ?? "";
    const token = p.get("token") ?? "";
    if (!id || this.tokens.get(id) !== token) {
      ws.close();
      return;
    }
    const conn: AgentConn = { ws, roles: new Map(), viewers: new Map() };
    this.agents.set(id, conn);
    log(`▶ agent connected ← ${id}`);
    ws.on("message", (raw) => {
      let m: { t?: string; role?: string; url?: string; roles?: Array<{ role: string; url?: string }> };
      try {
        m = JSON.parse(String(raw)) as typeof m;
      } catch {
        return;
      }
      if (m.t === "sessions") {
        conn.roles = new Map((m.roles ?? []).map((r) => [r.role, { url: r.url ?? "", done: false }])); // right after registration, everyone is awaiting login
      } else if (m.role && (m.t === "frame" || m.t === "url" || m.t === "copied")) {
        if (m.t === "url") {
          const e = conn.roles.get(m.role);
          if (e) e.url = m.url ?? e.url;
        }
        const vs = conn.viewers.get(m.role);
        if (vs) for (const v of vs) if (v.readyState === 1) v.send(String(raw));
      }
    });
    ws.on("close", () => {
      if (this.agents.get(id) === conn) this.agents.delete(id);
      log(`◼ agent left → ${id}`);
    });
    ws.on("error", () => {});
  }

  /** The operator's (WebUI) connection /ws/session?id=&role= */
  handleSession(ws: WebSocket, req: IncomingMessage): void {
    const p = qp(req);
    const id = p.get("id") ?? "";
    const role = p.get("role") ?? "";
    const conn = this.agents.get(id);
    if (!conn || !role) {
      ws.send(JSON.stringify({ t: "fatal", message: "no live agent for this run" }));
      ws.close();
      return;
    }
    let set = conn.viewers.get(role);
    if (!set) {
      set = new Set();
      conn.viewers.set(role, set);
    }
    set.add(ws);
    if (conn.ws.readyState === 1) conn.ws.send(JSON.stringify({ t: "start", role }));
    const cur = conn.roles.get(role);
    if (cur) ws.send(JSON.stringify({ t: "url", url: cur.url }));
    ws.on("message", (raw) => {
      let msg: Record<string, unknown>;
      try {
        msg = JSON.parse(String(raw)) as Record<string, unknown>;
      } catch {
        return;
      }
      if (msg.t === "done") {
        const e = conn.roles.get(role); // operator finished logging in → clear awaiting-login (remove the Sessions tab highlight)
        if (e) e.done = true;
      }
      if (conn.ws.readyState === 1) conn.ws.send(JSON.stringify({ t: "input", role, msg }));
    });
    ws.on("close", () => {
      const vs = conn.viewers.get(role);
      vs?.delete(ws);
      if (vs && vs.size === 0 && conn.ws.readyState === 1) conn.ws.send(JSON.stringify({ t: "stop", role }));
    });
    ws.on("error", () => {});
  }

  closeAll(): void {
    for (const a of this.agents.values()) {
      try {
        a.ws.close();
      } catch {
        /* ignore */
      }
    }
    this.agents.clear();
  }
}
