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

/** ?id= があれば固定。無ければ /api/assessments(サーバは直近書込順)の先頭を 3 秒ごとに追従。
 *  → serve を起動したまま pilot/assess を後から始めても、最新の実行中アセスメントが自動で映る。 */
export function useAssessmentId(): string | null {
  const pinned = new URLSearchParams(window.location.search).get("id");
  const [id, setId] = useState<string | null>(pinned);
  useEffect(() => {
    if (pinned) return;
    let alive = true;
    const poll = (): void => {
      fetch("/api/assessments")
        .then((r) => r.json())
        .then((list: Array<{ id: string }>) => {
          if (alive && list[0]) setId(list[0].id);
        })
        .catch(() => {
          /* server 未起動など */
        });
    };
    poll();
    const t = window.setInterval(poll, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [pinned]);
  return id;
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
