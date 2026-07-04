// attended×LiveHands: screencast the role sessions that the child (pilot) connected back, so the operator logs in → Done.
// /api/assessments/:id/sessions for the role list; /ws/session?id=&role= to receive frames + send input.
import { useEffect, useRef, useState, type KeyboardEvent, type MouseEvent, type ClipboardEvent, type WheelEvent } from "react";
import { useRole } from "../api";

interface RoleSession {
  role: string;
  url: string;
  awaiting?: boolean; // true = awaiting login (operator input required)
}

function mods(e: { altKey: boolean; ctrlKey: boolean; metaKey: boolean; shiftKey: boolean }): number {
  return (e.altKey ? 1 : 0) | (e.ctrlKey ? 2 : 0) | (e.metaKey ? 4 : 0) | (e.shiftKey ? 8 : 0);
}

export function Sessions({ id }: { id: string }) {
  const { canWrite } = useRole();
  const [roles, setRoles] = useState<RoleSession[]>([]);
  const [active, setActive] = useState<string | null>(null);
  const [status, setStatus] = useState("");
  const [url, setUrl] = useState(""); // URL to navigate the live session to (for recovering from a blank page)
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const buttonsRef = useRef(0);

  // Poll the role list (grows/shrinks as the child connects/disconnects)
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

  // Connect to the active role's screencast (attended takeover is operator-only = viewers don't connect)
  useEffect(() => {
    if (!active || !canWrite) return;
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
      } else if (m.t === "url") {
        setUrl(m.url); // the backend returns the current URL after a nav
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

  if (!canWrite) {
    return <p className="idxempty">Attended sessions (live browser takeover) are operator-only. Viewers have read-only access.</p>;
  }

  return (
    <div className="sess">
      {roles.length === 0 ? (
        <p className="idxempty">No live session. (attended runs launched from “+ New” with attended on appear here.)</p>
      ) : (
        <>
          <div className="sess-tabs">
            {roles.map((r) => (
              <button
                key={r.role}
                type="button"
                className={`${active === r.role ? "active" : ""}${r.awaiting ? " needs-input" : ""}`}
                onClick={() => setActive(r.role)}
                title={r.awaiting ? "waiting for login" : "logged in"}
              >
                {r.awaiting ? "🔴 " : ""}{r.role}
              </button>
            ))}
            <span className="sess-stat">{status}</span>
            <button type="button" className="sess-done" onClick={() => { send({ t: "done" }); setStatus("✅ done sent — agent continues"); }}>
              ✅ Done (logged in)
            </button>
          </div>
          <form
            className="sess-nav"
            onSubmit={(e) => {
              e.preventDefault();
              const u = url.trim();
              if (u) {
                send({ t: "nav", url: u });
                setStatus(`→ navigating to ${u}`);
              }
            }}
            title="navigate the live session browser here — use this to recover from a blank/stuck page"
          >
            <input
              className="sess-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://app.example.com/login  — navigate the live session here (blank-screen recovery)"
              spellCheck={false}
              autoComplete="off"
            />
            <button type="submit" className="sess-go">Go ↵</button>
          </form>
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
