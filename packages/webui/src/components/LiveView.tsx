import { useEffect, useRef, useState } from "react";

// View-only live screencast of the auto-scan browser (the "watch it work" panel). The running pilot streams its
// headless browser over the LiveHands reverse-WS as role "scan"; here we just render the JPEG frames on a canvas.
// No input is sent (unlike the attended Sessions takeover) — this is observation only. Streaming is lazy: the child
// only screencasts while this tab is open (the relay tells it to start on connect, stop on disconnect).
export function LiveView({ id }: { id: string }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [status, setStatus] = useState<"connecting" | "live" | "waiting" | "closed">("connecting");
  const [gotFrame, setGotFrame] = useState(false);

  useEffect(() => {
    const proto = window.location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${window.location.host}/ws/session?id=${encodeURIComponent(id)}&role=scan`);
    let alive = true;
    ws.onopen = () => alive && setStatus("waiting");
    ws.onclose = () => alive && setStatus("closed");
    ws.onerror = () => alive && setStatus("closed");
    ws.onmessage = (e) => {
      let m: { t?: string; data?: string; message?: string };
      try {
        m = JSON.parse(String(e.data)) as typeof m;
      } catch {
        return;
      }
      if (m.t === "fatal") {
        setStatus("closed"); // no live agent for this run (not running, or an older run)
        return;
      }
      if (m.t === "frame" && m.data) {
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
        if (alive) {
          setStatus("live");
          setGotFrame(true);
        }
      }
    };
    return () => {
      alive = false;
      ws.close();
    };
  }, [id]);

  return (
    <div className="liveview">
      <div className="liveview-bar">
        <span className={`liveview-dot ${status}`} />
        <span className="muted">
          {status === "live"
            ? "live — watching the scan browser"
            : status === "waiting"
              ? "connected — waiting for the scan to drive the browser…"
              : status === "connecting"
                ? "connecting…"
                : "not streaming — the scan is not running (start or resume it to watch live)"}
        </span>
      </div>
      <div className="liveview-stage">
        <canvas ref={canvasRef} className="liveview-canvas" style={{ display: gotFrame ? "block" : "none" }} />
        {!gotFrame ? <div className="liveview-empty">The live view appears here while an assessment is running.</div> : null}
      </div>
    </div>
  );
}
