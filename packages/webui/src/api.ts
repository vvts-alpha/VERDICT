// Hooks that subscribe to AssessmentState from the server. Receive snapshot / events over WS and hold the StateView.

import { useEffect, useRef, useState } from "react";
import type { StateView, WsMessage } from "@veritas/core";

export type ConnState = "connecting" | "open" | "closed";

/** POST a minimal control action (§8.3) to the server. The result is reflected in the UI via a WS push. */
export async function postControl(path: string): Promise<void> {
  try {
    await fetch(path, { method: "POST" });
  } catch {
    /* WS re-syncs on the next tick */
  }
}

/** Control POST with a JSON body (e.g. bulk exclude). The result is reflected in the UI via a WS push. */
export async function postControlBody(path: string, body: unknown): Promise<void> {
  try {
    await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  } catch {
    /* WS re-syncs on the next tick */
  }
}

/** If ?id= is present, show that assessment. If not, null → App shows the list (Index). */
export function useAssessmentId(): string | null {
  return new URLSearchParams(window.location.search).get("id");
}

export interface Me {
  role: "operator" | "viewer";
  authEnabled: boolean;
}

let _mePromise: Promise<Me> | null = null;

/** Your own role (/api/me). operator = full access / viewer = read-only. No-auth or a failed fetch is treated as operator (all actions allowed, as before). */
export function useRole(): Me & { canWrite: boolean } {
  const [me, setMe] = useState<Me>({ role: "operator", authEnabled: false });
  useEffect(() => {
    let alive = true;
    if (!_mePromise) _mePromise = fetch("/api/me").then((r) => r.json()).catch(() => ({ role: "operator", authEnabled: false }) as Me);
    void _mePromise.then((m) => {
      if (alive) setMe(m);
    });
    return () => {
      alive = false;
    };
  }, []);
  return { ...me, canWrite: me.role === "operator" };
}

export function useStateView(id: string | null): { view: StateView | null; conn: ConnState } {
  const [view, setView] = useState<StateView | null>(null);
  const [conn, setConn] = useState<ConnState>("connecting");
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!id) return;
    let disposed = false;
    let retry: number | undefined;

    const connect = (): void => {
      const proto = window.location.protocol === "https:" ? "wss" : "ws";
      const ws = new WebSocket(`${proto}://${window.location.host}/ws?id=${encodeURIComponent(id)}`);
      wsRef.current = ws;
      setConn("connecting");
      ws.onopen = () => setConn("open");
      ws.onmessage = (ev) => {
        const msg = JSON.parse(ev.data as string) as WsMessage;
        if (msg.type === "snapshot" || msg.type === "events") setView(msg.view);
      };
      ws.onclose = () => {
        setConn("closed");
        if (!disposed) retry = window.setTimeout(connect, 1500);
      };
      ws.onerror = () => ws.close();
    };

    connect();
    return () => {
      disposed = true;
      if (retry) window.clearTimeout(retry);
      wsRef.current?.close();
    };
  }, [id]);

  return { view, conn };
}
