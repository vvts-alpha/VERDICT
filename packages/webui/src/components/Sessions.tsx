// attended×LiveHands: 子(pilot)が逆接続した role セッションを screencast 表示し、操作者がログイン → Done。
// /api/assessments/:id/sessions で role 一覧、/ws/session?id=&role= で frame 受信 + 入力送信。
import { useEffect, useRef, useState, type KeyboardEvent, type MouseEvent, type ClipboardEvent, type WheelEvent } from "react";

interface RoleSession {
  role: string;
  url: string;
}

function mods(e: { altKey: boolean; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean }): number {
  return (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
}

export function Sessions({ id }: { id: string }) {
  const [roles, setRoles] = useState<RoleSession[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const buttonsRef = useRef(0);

  // role 一覧をポーリング(子が接続/切断すると増減)
  useEffect(() => {
    let alive = true;
    const poll = (): void => {
      fetch(`/api/assessments/${encodeURIComponent(id)}/sessions`)
        .then((r) => r.json())
        .then((rs: RoleSession[]) => {
          if (!alive) return;
          setRoles(rs);
          setActive((a) => a ?? rs[0]?.role ?? null);
        })
        .catch(() => {});
    };
    poll();
    const t = window.setInterval(poll, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [id]);

  // active role の screencast に接続
  useEffect(() => {
    if (!active) return;
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/session?id=${encodeURIComponent(id)}&role=${encodeURIComponent(active)}`);
    wsRef.current = ws;
    setStatus("connecting…");
    ws.onopen = () => setStatus("connected");
    ws.onclose = () => setStatus("disconnected");
    ws.onmessage = (e) => {
      const m = JSON.parse(e.data as string);
      if (m.t === "frame") {
        const c = canvasRef.current;
        if (!c) return;
        const img = new Image();
        img.onload = () => {
          if (c.width !== img.width || c.height !== img.height) {
            c.width = img.width;
            c.height = img.height;
          }
          c.getContext("2d")?.drawImage(img, 0, 0);
        };
        img.src = "data:image/jpeg;base64," + m.data;
      } else if (m.t === "fatal") {
        setStatus(m.message);
      }
    };
    return () => ws.close();
  }, [active, id]);

  const send = (o: unknown): void => {
    const ws = wsRef.current;
    if (ws && ws.readyState === 1) ws.send(JSON.stringify(o));
  };
  const pt = (e: MouseEvent<HTMLCanvasElement> | WheelEvent<HTMLCanvasElement>): { x: number; y: number } => {
    const c = canvasRef.current!;
    const r = c.getBoundingClientRect();
    return { x: Math.round((e.clientX - r.left) * (c.width / r.width)), y: Math.round((e.clientY - r.top) * (c.height / r.height)) };
  };

  return (
    <div className="sess">
      {roles.length === 0 ? (
        <p className="idxempty">No live session. (attended runs launched from “+ New” with attended on appear here.)</p>
      ) : (
        <>
          <div className="sess-tabs">
            {roles.map((r) => (
              <button key={r.role} type="button" className={active === r.role ? "active" : ""} onClick={() => setActive(r.role)}>
                {r.role}
              </button>
            ))}
            <span className="sess-stat">{status}</span>
            <button type="button" className="sess-done" onClick={() => { send({ t: "done" }); setStatus("✅ done sent — agent continues"); }}>
              ✅ Done (logged in)
            </button>
          </div>
          <div className="sess-wrap">
            <canvas
              ref={canvasRef}
              className="sess-canvas"
              width={1280}
              height={800}
              tabIndex={0}
              onMouseMove={(e) => send({ t: "mouse", kind: "move", ...pt(e), buttons: buttonsRef.current })}
              onMouseDown={(e) => { e.preventDefault(); e.currentTarget.focus(); buttonsRef.current = 1; send({ t: "mouse", kind: "down", button: "left", buttons: 1, ...pt(e) }); }}
              onMouseUp={(e) => { buttonsRef.current = 0; send({ t: "mouse", kind: "up", button: "left", buttons: 0, ...pt(e) }); }}
              onContextMenu={(e) => e.preventDefault()}
              onWheel={(e) => send({ t: "mouse", kind: "wheel", ...pt(e), deltaX: e.deltaX, deltaY: e.deltaY })}
              onKeyDown={(e: KeyboardEvent<HTMLCanvasElement>) => {
                const cmd = e.ctrlKey || e.metaKey;
                if (cmd && (e.key === "v" || e.key === "V")) return;
                if (cmd && (e.key === "c" || e.key === "C")) { e.preventDefault(); send({ t: "copy" }); return; }
                e.preventDefault();
                send({ t: "key", kind: "down", key: e.key, code: e.code, text: !cmd && e.key.length === 1 ? e.key : "", modifiers: mods(e) });
              }}
              onKeyUp={(e: KeyboardEvent<HTMLCanvasElement>) => {
                const cmd = e.ctrlKey || e.metaKey;
                if (cmd && "vVcC".includes(e.key)) return;
                e.preventDefault();
                send({ t: "key", kind: "up", key: e.key, code: e.code, modifiers: mods(e) });
              }}
              onPaste={(e: ClipboardEvent<HTMLCanvasElement>) => {
                const text = e.clipboardData.getData("text");
                if (text) { e.preventDefault(); send({ t: "paste", text }); setStatus(`pasted ${text.length}`); }
              }}
            />
          </div>
        </>
      )}
    </div>
  );
}
