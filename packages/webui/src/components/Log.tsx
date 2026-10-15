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
    return <p className="p-4 text-muted-foreground">No activity yet.</p>;
  }
  const rows = [...events].slice(-300).reverse(); // newest first + capped (same bound as the store projection)
  return (
    <div className="flex flex-col">
      {rows.map((e) => (
        <div key={e.seq} className="flex gap-3 border-b border-border px-1 py-1 text-xs hover:bg-muted">
          <span className="shrink-0 font-mono tabular-nums text-muted-foreground">{hhmmss(e.ts)}</span>
          <span className={`break-words font-mono whitespace-pre-wrap ${e.type === "finding_created" ? "font-semibold text-warning" : e.type === "phase_changed" ? "text-primary" : e.type === "halted" ? "text-destructive" : "text-foreground"}`}>{eventLine(e)}</span>
        </div>
      ))}
    </div>
  );
}
