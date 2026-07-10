import { useEffect, useRef, useState } from "react";

// ASR Log tab — polls the run's child output (runs/<id>/run.log, timestamped by the supervisor) and renders it with
// the same .log / .logline / .log-ts / .log-msg markup as the web diagnostic log. Auto-scrolls to the newest line.
export function AsrLog({ id }: { id: string }) {
  const [text, setText] = useState("");
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let alive = true;
    const load = (): void => {
      fetch(`/api/assessments/${encodeURIComponent(id)}/run-log`)
        .then((r) => (r.ok ? r.text() : ""))
        .then((t) => {
          if (alive) setText(t);
        })
        .catch(() => {});
    };
    load();
    const iv = window.setInterval(load, 2000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, [id]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [text]);

  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length === 0) return <p className="muted log-empty">waiting for output…</p>;
  return (
    <div className="log">
      {lines.map((line, i) => {
        const m = /^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$/.exec(line);
        return (
          <div key={i} className="logline">
            <span className="log-ts">{m ? m[1] : ""}</span>
            <span className="log-msg">{m ? m[2] : line}</span>
          </div>
        );
      })}
      <div ref={endRef} />
    </div>
  );
}
