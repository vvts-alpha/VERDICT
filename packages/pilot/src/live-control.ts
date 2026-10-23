// The child (pilot) side of attended×LiveHands. Connects **back** to serve (the Node 24 global WebSocket client),
// streams a per-role CDP screencast up, and relays operator input down. Manual-login completion is resolved by the
// operator's "Done" (= replacing the old terminal Enter gate).
import type { PlaywrightDriver } from "@veritas/crawler";

type Cdp = Awaited<ReturnType<PlaywrightDriver["cdpSession"]>>;

interface InMsg {
  t?: string;
  kind?: "move" | "down" | "up" | "wheel";
  key?: string;
  code?: string;
  text?: string;
  x?: number;
  y?: number;
  button?: "none" | "left" | "middle" | "right" | "back" | "forward";
  buttons?: number;
  deltaX?: number;
  deltaY?: number;
  modifiers?: number;
  url?: string;
}

// CDP modifiers: Alt=1 Ctrl=2 Meta=4 Shift=8
const KEY_MAP: Record<string, { key: string; code: string; windowsVirtualKeyCode: number; text?: string }> = {
  Enter: { key: "Enter", code: "Enter", windowsVirtualKeyCode: 13, text: "\r" },
  Backspace: { key: "Backspace", code: "Backspace", windowsVirtualKeyCode: 8 },
  Tab: { key: "Tab", code: "Tab", windowsVirtualKeyCode: 9 },
  Escape: { key: "Escape", code: "Escape", windowsVirtualKeyCode: 27 },
  Delete: { key: "Delete", code: "Delete", windowsVirtualKeyCode: 46 },
  ArrowLeft: { key: "ArrowLeft", code: "ArrowLeft", windowsVirtualKeyCode: 37 },
  ArrowUp: { key: "ArrowUp", code: "ArrowUp", windowsVirtualKeyCode: 38 },
  ArrowRight: { key: "ArrowRight", code: "ArrowRight", windowsVirtualKeyCode: 39 },
  ArrowDown: { key: "ArrowDown", code: "ArrowDown", windowsVirtualKeyCode: 40 },
  Home: { key: "Home", code: "Home", windowsVirtualKeyCode: 36 },
  End: { key: "End", code: "End", windowsVirtualKeyCode: 35 },
};

async function dispatchKey(cdp: Cdp, ev: InMsg): Promise<void> {
  const modifiers = ev.modifiers ?? 0;
  const type = ev.kind === "down" ? "keyDown" : "keyUp";
  const special = ev.key ? KEY_MAP[ev.key] : undefined;
  if (special) return void (await cdp.send("Input.dispatchKeyEvent", { type, modifiers, ...special }));
  const ctrlOrMeta = (modifiers & 2) !== 0 || (modifiers & 4) !== 0;
  if (ctrlOrMeta && ev.key) {
    await cdp.send("Input.dispatchKeyEvent", {
      type,
      modifiers,
      key: ev.key,
      code: ev.code ?? "",
      windowsVirtualKeyCode: ev.key.length === 1 ? ev.key.toUpperCase().charCodeAt(0) : 0,
    });
    return;
  }
  if (ev.kind === "down" && ev.text && ev.text.length >= 1) await cdp.send("Input.insertText", { text: ev.text });
}

async function dispatchMouse(cdp: Cdp, ev: InMsg): Promise<void> {
  const x = ev.x ?? 0;
  const y = ev.y ?? 0;
  if (ev.kind === "wheel") return void (await cdp.send("Input.dispatchMouseEvent", { type: "mouseWheel", x, y, deltaX: ev.deltaX ?? 0, deltaY: ev.deltaY ?? 0 }));
  const type = ev.kind === "down" ? "mousePressed" : ev.kind === "up" ? "mouseReleased" : "mouseMoved";
  await cdp.send("Input.dispatchMouseEvent", {
    type,
    x,
    y,
    button: ev.button ?? "none",
    buttons: ev.buttons ?? 0,
    clickCount: ev.kind === "down" || ev.kind === "up" ? 1 : 0,
  });
}

interface RoleCtl {
  driver: PlaywrightDriver;
  cdp: Cdp;
  started: boolean;
  /** true = the operator must still press Done for this role (login gate pending). False for sessions
   *  already verified live at startup (resume probes / cookie / creds auto-login). */
  awaiting: boolean;
  doneResolve?: () => void;
}

export class LiveControl {
  private ws: WebSocket | null = null;
  private readonly roles = new Map<string, RoleCtl>();
  private readonly connected: Promise<void>;
  private closed = false;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    private readonly url: string,
    private readonly onLog?: (m: string) => void,
  ) {
    this.connected = this.connect();
  }

  private connect(): Promise<void> {
    return new Promise<void>((resolve) => {
      const ws = new WebSocket(this.url);
      this.ws = ws;
      ws.onopen = (): void => {
        this.onLog?.("🔌 live-control connected to serve");
        this.sendSessions();
        resolve();
      };
      ws.onmessage = (e: MessageEvent): void => {
        let m: { t?: string; role?: string; msg?: InMsg };
        try {
          m = JSON.parse(String(e.data));
        } catch {
          return;
        }
        void this.onMessage(m);
      };
      // A dropped loopback WS (server restart, OS suspend/resume) used to kill the Sessions tab silently —
      // the screencast/CDP hooks are browser-bound, not socket-bound, so reconnecting re-announces the
      // roster and resumes forwarding with no re-registration needed.
      ws.onclose = (): void => {
        resolve(); // the run proceeds even if the connection fails
        if (!this.closed) this.reconnectTimer ??= setTimeout(() => void this.retry(), 3_000);
      };
      ws.onerror = (): void => resolve();
    });
  }

  private async retry(): Promise<void> {
    this.reconnectTimer = null;
    if (this.closed) return;
    try {
      await this.connect(); // resolves on open AND on close — check readiness to tell them apart
      if (this.ws?.readyState === 1) this.onLog?.("🔌 live-control reconnected to serve");
    } catch {
      if (!this.closed) this.reconnectTimer ??= setTimeout(() => void this.retry(), 3_000);
    }
  }

  private send(o: unknown): void {
    if (this.ws && this.ws.readyState === 1) this.ws.send(JSON.stringify(o));
  }

  private sendSessions(): void {
    this.send({ t: "sessions", roles: [...this.roles.entries()].map(([role, c]) => ({ role, url: c.driver.currentUrl(), awaiting: c.awaiting })) });
  }

  /** Register the role's raw context so it can receive a screencast.
   *  `awaiting` marks "operator must still press Done to log in" — verified-live sessions register
   *  with awaiting:false so they appear (take-overable) without the false login highlight. */
  async register(role: string, driver: PlaywrightDriver, awaiting = true): Promise<void> {
    await this.connected;
    // Replacing a RoleCtl must not strand a pending waitForDone — resolve the stale waiter so its
    // continuation runs (it just re-reads cookie/bearer) instead of leaking forever.
    this.roles.get(role)?.doneResolve?.();
    const cdp = await driver.cdpSession();
    const rc: RoleCtl = { driver, cdp, started: false, awaiting };
    this.roles.set(role, rc);
    cdp.on("Page.screencastFrame", (ev: { data: string; metadata: unknown; sessionId: number }) => {
      this.send({ t: "frame", role, data: ev.data, meta: ev.metadata });
      void cdp.send("Page.screencastFrameAck", { sessionId: ev.sessionId }).catch(() => {});
    });
    this.sendSessions();
  }

  /** Whether a role is registered (has a live CDP hook) — register() first if this returns false. */
  hasRole(role: string): boolean {
    return this.roles.has(role);
  }

  /** Drop a role whose context is confirmed dead — otherwise it lingers on the tab as a dead screencast.
   *  login()'s respawn path re-registers on recovery. */
  unregister(role: string): void {
    const rc = this.roles.get(role);
    if (!rc) return;
    rc.doneResolve?.(); // unblock any waiter — the session is gone, not coming back
    this.roles.delete(role);
    this.sendSessions();
  }

  /** Re-flag an already-registered role as needing operator login (keepalive detected expiry on a session
   *  that registered with awaiting:false — without this the tab never re-highlights it). */
  markAwaiting(role: string): void {
    const rc = this.roles.get(role);
    if (rc && !rc.awaiting) {
      rc.awaiting = true;
      this.sendSessions();
    }
  }

  /** Wait for that role's operator "Done" (the attended login gate; replaces Enter). */
  waitForDone(role: string): Promise<void> {
    const rc = this.roles.get(role);
    if (!rc) return Promise.resolve();
    return new Promise<void>((resolve) => {
      rc.doneResolve = resolve;
    });
  }

  private async onMessage(m: { t?: string; role?: string; msg?: InMsg }): Promise<void> {
    const rc = m.role ? this.roles.get(m.role) : undefined;
    if (!rc || !m.role) return;
    if (m.t === "start" && !rc.started) {
      rc.started = true;
      await cdpStart(rc.cdp);
    } else if (m.t === "stop" && rc.started) {
      rc.started = false;
      await rc.cdp.send("Page.stopScreencast").catch(() => {});
    } else if (m.t === "input" && m.msg) {
      await this.handleInput(m.role, rc, m.msg);
    }
  }

  private async handleInput(role: string, rc: RoleCtl, msg: InMsg): Promise<void> {
    if (msg.t === "mouse") await dispatchMouse(rc.cdp, msg);
    else if (msg.t === "key") await dispatchKey(rc.cdp, msg);
    else if (msg.t === "paste" && typeof msg.text === "string") await rc.cdp.send("Input.insertText", { text: msg.text });
    else if (msg.t === "copy") {
      const r = (await rc.cdp.send("Runtime.evaluate", { expression: "String(window.getSelection ? window.getSelection() : '')", returnByValue: true })) as unknown as {
        result?: { value?: string };
      };
      this.send({ t: "copied", role, text: r.result?.value ?? "" });
    } else if (msg.t === "nav" && typeof msg.url === "string") {
      await rc.driver.gotoUrl(msg.url).catch(() => {});
      this.send({ t: "url", role, url: rc.driver.currentUrl() });
    } else if (msg.t === "done") {
      rc.awaiting = false;
      rc.doneResolve?.();
    }
  }

  close(): void {
    this.closed = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    try {
      this.ws?.close();
    } catch {
      /* ignore */
    }
  }
}

async function cdpStart(cdp: Cdp): Promise<void> {
  await cdp.send("Page.startScreencast", { format: "jpeg", quality: 60, maxWidth: 1280, maxHeight: 800, everyNthFrame: 1 }).catch(() => {});
}
