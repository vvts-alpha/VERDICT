// AssessmentState を server から購読する hooks。WS で snapshot / events を受け、StateView を保持。

import { useEffect, useRef, useState } from "react";
import type { StateView, WsMessage } from "@veritas/core";

export type ConnState = "connecting" | "open" | "closed";

/** 最小操作(§8.3)を server に POST。結果は WS push で UI に反映される。 */
export async function postControl(path: string): Promise<void> {
  try {
    await fetch(path, { method: "POST" });
  } catch {
    /* WS が次の tick で再同期 */
  }
}

/** ?id= があればそのアセスメントを表示。無ければ null → App は一覧(Index)を表示する。 */
export function useAssessmentId(): string | null {
  return new URLSearchParams(window.location.search).get("id");
}

export interface Me {
  role: "operator" | "viewer";
  authEnabled: boolean;
}

let _mePromise: Promise<Me> | null = null;

/** 自分のロール(/api/me)。operator=全権 / viewer=閲覧のみ。無認証や取得失敗は operator 扱い(従来どおり全操作可)。 */
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
