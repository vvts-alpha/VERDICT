import type { StateEvent } from "@veritas/core";

// Diagnostic log: what's happening (Claude's note / probe / plan / finding / phase transition …), newest first.
export function eventLine(e: StateEvent): string {
  switch (e.type) {
    case "note":
      return e.payload.message;
    case "phase_changed":
      return `▷ phase ${e.payload.from} → ${e.payload.to}`;
    case "finding_created":
      return `★ finding ${e.payload.findingId}`;
    case "screen_discovered":
      return `+ screen ${e.payload.screenId}`;
    case "screen_scan_status_changed":
      return `${e.payload.screenId}: ${e.payload.from} → ${e.payload.to}`;
    case "handoff_requested":
      return `⚠ handoff requested (${e.payload.reason})`;
    case "handoff_resolved":
      return `✓ handoff resolved`;
    case "control_changed":
      return e.payload.paused ? "⏸ paused" : "▶ resumed";
    case "halted":
      return `■ halted: ${e.payload.reason}`;
    case "assessment_created":
      return `● assessment created`;
    default:
      return e.type;
  }
}

function hhmmss(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toTimeString().slice(0, 8);
}

export function Log({ events }: { events: StateEvent[] }) {
  if (events.length === 0) {
    return <p className="muted log-empty">No activity yet.</p>;
  }
  const rows = [...events].reverse(); // newest first (what's happening now is on top)
  return (
    <div className="log">
      {rows.map((e) => (
        <div key={e.seq} className={`logline lt-${e.type}`}>
          <span className="log-ts">{hhmmss(e.ts)}</span>
          <span className="log-msg">{eventLine(e)}</span>
        </div>
      ))}
    </div>
  );
}
