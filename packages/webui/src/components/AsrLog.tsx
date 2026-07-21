// ASR Log tab — renders the run's child output (runs/<id>/run.log, timestamped by the supervisor) with the SAME
// .log / .logline / .log-ts / .log-msg markup + per-line-type colouring AND ordering as the web diagnostic log
// (newest-first). The fetch/count/300-cap live in AsrView; this is a pure renderer.

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
  if (lines.length === 0) return <p className="muted log-empty">No activity yet.</p>;
  const rows = [...lines].reverse(); // newest first — what's happening now on top, exactly like the web Log
  return (
    <div className="log">
      {rows.map((l, i) => (
        <div key={i} className={`logline ${l.cls}`}>
          <span className="log-ts">{l.ts}</span>
          <span className="log-msg">{l.msg}</span>
        </div>
      ))}
    </div>
  );
}
