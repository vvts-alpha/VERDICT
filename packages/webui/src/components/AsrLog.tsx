import { useEffect, useRef } from "react";

// ASR Log tab — renders the run's child output (runs/<id>/run.log, timestamped by the supervisor) with the SAME
// .log / .logline / .log-ts / .log-msg markup + per-line-type colouring as the web diagnostic log. The fetch/count
// live in AsrView (so the tab shows "Log (N)" like the web viewer even before it's opened); this is a pure renderer.

export interface LogLine {
  ts: string;
  msg: string;
  /** log-line type class (colours the line like the web log's lt-* classes) */
  cls: string;
}

/** Classify a run.log line by its leading glyph → an lt-* class (mirrors the web log's colour coding). */
function lineType(msg: string): string {
  const c = msg.trimStart().charAt(0);
  if (c === "▶" || c === "▷") return "lt-phase_changed"; // stage/phase transition (accent)
  if (c === "✓") return "lt-ok"; // a live host / success (ok)
  if (c === "!" || c === "⚠") return "lt-alert"; // takeover / warning
  if (c === "·") return "lt-dead"; // no-response host (muted)
  return "";
}

// Noise from the spawned child's stderr that isn't ASR activity: node warnings + their stack-trace continuation lines.
// (The supervisor now spawns with --disable-warning, so new runs are clean; this also scrubs pre-existing run.logs.)
function isNoise(msg: string): boolean {
  const t = msg.trim();
  if (!t) return true;
  if (/ExperimentalWarning|node --trace-warnings|^\(Use `node/.test(t)) return true;
  if (/^at\s+\S.*:\d+:\d+\)?$/.test(t)) return true; // stack-trace frame
  return false;
}

/** Parse timestamped run.log text into renderable, noise-filtered lines. Shared by AsrView (count) + AsrLog (render). */
export function parseLogLines(text: string): LogLine[] {
  const out: LogLine[] = [];
  for (const line of text.split("\n")) {
    const m = /^\[(\d{2}:\d{2}:\d{2})\]\s?(.*)$/.exec(line);
    const ts = m?.[1] ?? "";
    const msg = m?.[2] ?? line;
    if (isNoise(msg)) continue;
    out.push({ ts, msg, cls: lineType(msg) });
  }
  return out;
}

export function AsrLog({ lines }: { lines: LogLine[] }) {
  const endRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "end" });
  }, [lines.length]);

  if (lines.length === 0) return <p className="muted log-empty">No activity yet.</p>;
  return (
    <div className="log">
      {lines.map((l, i) => (
        <div key={i} className={`logline ${l.cls}`}>
          <span className="log-ts">{l.ts}</span>
          <span className="log-msg">{l.msg}</span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}
