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
