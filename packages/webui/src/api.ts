// Hooks that subscribe to AssessmentState from the server. Receive snapshot / events over WS and hold the StateView.

import { useEffect, useRef, useState } from "react";
import type { StateView, WsMessage } from "@veritas/core";

export type ConnState = "connecting" | "open" | "closed";

/** POST a minimal control action (§8.3) to the server. Success is reflected in the UI via a WS push.
 *  Returns `true` on 2xx, otherwise an error string — callers surface it instead of failing silently. */
export async function postControl(path: string): Promise<true | string> {
  try {
    const r = await fetch(path, { method: "POST" });
    return r.ok ? true : `HTTP ${r.status}`;
  } catch {
    return "server unreachable"; // WS re-syncs on the next tick if the action still went through
  }
}

/** Control POST with a JSON body (e.g. bulk exclude). Same contract as postControl. */
export async function postControlBody(path: string, body: unknown): Promise<true | string> {
  try {
    const r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    return r.ok ? true : `HTTP ${r.status}`;
  } catch {
    return "server unreachable";
  }
}

/** If ?id= is present, show that assessment. If not, null → App shows the list (Index). */
export function useAssessmentId(): string | null {
  return new URLSearchParams(window.location.search).get("id");
}

export interface MeUser {
  id: string;
  username: string;
  role: "admin" | "user";
}

export interface Me {
  role: "operator" | "viewer" | "admin" | "user";
  authEnabled: boolean;
  /** Account-based auth (veritas serve --multi-user); user carries the signed-in account. */
  multiUser?: boolean;
  user?: MeUser;
}

let _mePromise: Promise<Me> | null = null;

/** Your own identity (/api/me). operator = full access / viewer = read-only (shared-password mode);
 *  admin/user = account roles (multi-user mode). No-auth or a failed fetch is treated as operator
 *  (all actions allowed, as before). */
export function useRole(): Me & { canWrite: boolean; canAdmin: boolean } {
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
  return { ...me, canWrite: me.role !== "viewer", canAdmin: me.role === "admin" };
}

/** JSON call for the account/admin endpoints. Throws Error(server message) on non-2xx. */
export async function apiCall<T>(path: string, method = "GET", body?: unknown): Promise<T> {
  const r = await fetch(path, {
    method,
    ...(body !== undefined ? { headers: { "content-type": "application/json" }, body: JSON.stringify(body) } : {}),
  });
  const j = (await r.json().catch(() => null)) as (T & { error?: string }) | null;
  if (!r.ok) throw new Error(j?.error ?? `HTTP ${r.status}`);
  return j as T;
}

/** End the session and return to the login page. Multi-user revokes the server-side session via POST;
 *  the legacy shared-password gate clears its cookie via GET /logout. */
export async function signOut(multiUser: boolean): Promise<void> {
  if (multiUser) {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
    } catch { /* navigate either way — the cookie is gone or the server is unreachable */ }
    window.location.assign("/login");
    return;
  }
  window.location.assign("/logout");
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
        let msg: WsMessage;
        try {
          msg = JSON.parse(ev.data as string) as WsMessage;
        } catch {
          return; // a malformed frame must not kill the stream
        }
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
