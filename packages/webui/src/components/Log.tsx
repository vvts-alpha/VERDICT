import type { StateEvent } from "@veritas/core";
import { useT, type T } from "../i18n";

// Default translator for non-component callers — interpolate vars, no JA lookup.
const ident: T = (s, vars) => {
  let out = s;
  if (vars) for (const [k, v] of Object.entries(vars)) out = out.replaceAll(`{${k}}`, String(v));
  return out;
};

// Diagnostic log: what's happening (Claude's note / probe / plan / finding / phase transition …), newest first.
// `t` localizes the fixed template words; identifiers (ids, urls, check classes) stay verbatim.
export function eventLine(e: StateEvent, t: T = ident): string {
  switch (e.type) {
    case "note":
      return e.payload.message;
    case "phase_changed":
      return t("▷ phase {from} → {to}", { from: e.payload.from, to: e.payload.to });
    case "finding_created":
      return t("★ finding {id}", { id: e.payload.findingId });
    case "screen_discovered":
      return t("+ screen {id}", { id: e.payload.screenId });
    case "screen_scan_status_changed":
      return t("{id}: {from} → {to}", { id: e.payload.screenId, from: e.payload.from, to: e.payload.to });
    case "handoff_requested":
      return t("⚠ handoff requested ({reason})", { reason: e.payload.reason });
    case "handoff_resolved":
      return t("✓ handoff resolved");
    case "control_changed":
      return e.payload.paused ? t("⏸ paused") : t("▶ resumed");
    case "halted":
      return t("■ halted: {reason}", { reason: e.payload.reason });
    case "assessment_created":
      return t("● assessment created");
    case "check_recorded":
      return t("check {checkClass} → {status} ({target}{subject})", {
        checkClass: e.payload.check.checkClass,
        status: e.payload.check.status,
        target: e.payload.check.target,
        subject: e.payload.check.subject ? `, ${e.payload.check.subject}` : "",
      });
    case "authz_comparison_recorded":
      return t("authz comparison {id} → {outcome}", { id: e.payload.comparison.id, outcome: e.payload.comparison.outcome });
    case "survey_role_progress":
      return t("survey role {role}: {state}{reason}", {
        role: e.payload.role,
        state: e.payload.state,
        reason: e.payload.reason ? ` — ${e.payload.reason}` : "",
      });
    default:
      return e.type;
  }
}

function hhmmss(ts: string): string {
  const d = new Date(ts);
  return Number.isNaN(d.getTime()) ? "" : d.toTimeString().slice(0, 8);
}

export function Log({ events }: { events: StateEvent[] }) {
  const t = useT();
  if (events.length === 0) {
    return <p className="p-4 text-muted-foreground">{t("No activity yet.")}</p>;
  }
  const rows = [...events].slice(-300).reverse(); // newest first + capped (same bound as the store projection)
  return (
    <div className="flex flex-col">
      {rows.map((e) => (
        <div key={e.seq} className="flex gap-3 border-b border-border px-1 py-1 text-xs hover:bg-muted">
          <span className="shrink-0 font-mono tabular-nums text-muted-foreground">{hhmmss(e.ts)}</span>
          <span className={`break-words font-mono whitespace-pre-wrap ${e.type === "finding_created" ? "font-semibold text-warning" : e.type === "phase_changed" ? "text-primary" : e.type === "halted" ? "text-destructive" : "text-foreground"}`}>{eventLine(e, t)}</span>
        </div>
      ))}
    </div>
  );
}
