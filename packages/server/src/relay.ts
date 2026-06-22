// attended×LiveHands のクロスプロセス中継ハブ。docs/LIVE_TAKEOVER.md。
// 子(pilot)が /ws/agent?id=&token= に**逆接続**して role 毎の screencast を上げ、
// 操作者の WebUI が /ws/session?id=&role= に繋ぐ。serve がハブとして双方を中継する。
//   child → serve : {t:"sessions",roles:[{role,url}]} / {t:"frame",role,data,meta} / {t:"url",role,url} / {t:"copied",role,text}
//   serve → child : {t:"start",role} / {t:"stop",role} / {t:"input",role,msg}
//   operator → serve(/ws/session): {t:"mouse|key|paste|copy|nav|done", ...} → child へ {t:"input",role,msg} で転送
import type { IncomingMessage } from "node:http";
import type { WebSocket } from "ws";

interface AgentConn {
  ws: WebSocket;
  /** done=false は「ログイン待ち(operator の入力が必要)」。operator の {t:"done"} で true になる。 */
  roles: Map<string, { url: string; done: boolean }>;
  viewers: Map<string, Set<WebSocket>>;
}

function qp(req: IncomingMessage): URLSearchParams {
  return new URL(req.url ?? "", "http://localhost").searchParams;
}

export class Relay {
  private readonly agents = new Map<string, AgentConn>();
  private readonly tokens = new Map<string, string>();

  /** spawn 時に run ごとのトークンを登録(子の逆接続を認証する)。 */
  issueToken(id: string, token: string): void {
    this.tokens.set(id, token);
  }
  revokeToken(id: string): void {
    this.tokens.delete(id);
  }

  /** その run に子(agent)が接続済みで利用可能な role 一覧(WebUI が Sessions タブを出す判断に使う)。
   *  awaiting=true は「ログイン待ち(operator 入力が必要)」→ WebUI は Sessions タブを強調する。 */
  rolesFor(id: string): Array<{ role: string; url: string; awaiting: boolean }> {
    const a = this.agents.get(id);
    if (!a) return [];
    return [...a.roles.entries()].map(([role, v]) => ({ role, url: v.url, awaiting: !v.done }));
  }

  /** 子(pilot)の逆接続 /ws/agent?id=&token= */
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
        conn.roles = new Map((m.roles ?? []).map((r) => [r.role, { url: r.url ?? "", done: false }])); // 登録直後は全員ログイン待ち
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

  /** 操作者(WebUI)の接続 /ws/session?id=&role= */
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
        const e = conn.roles.get(role); // operator がログイン完了 → ログイン待ち解除(Sessions タブの強調を消す)
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
