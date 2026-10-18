import type { StateView } from "@veritas/core";
import { eventLine } from "./Log";
import { screenHonestyMap } from "./screen-status";

const ORDER = ["finding", "suspected", "unverified", "scanning", "queued", "clean", "unknown-records", "excluded", "blocked", "error"] as const;
const COLOR: Record<string, string> = {
  finding: "var(--warn)",
  suspected: "var(--warn)",
  unverified: "var(--warn)",
  scanning: "var(--fg)",
  queued: "var(--line)",
  clean: "var(--ok)",
  "unknown-records": "var(--muted)",
  excluded: "var(--muted)",
  blocked: "var(--err)",
  error: "var(--err)",
};

// Progress bar (breakdown of scan status) + the screen being diagnosed now + the latest log. See where the run is at a glance.
// Counts use the ledger-honest effective status: a legacy "clean" claim with no check records shows
// as unknown-records (neutral), and a clean with unfulfilled plan/gap rows counts as unverified.
export function Progress({ view }: { view: StateView }) {
  const by = new Map(view.screenScans.map((s) => [s.screenId, s.status] as const));
  const honesty = screenHonestyMap(view);
  const counts: Record<string, number> = {};
  for (const s of view.screenScans) {
    const st = honesty.get(s.screenId)?.status ?? s.status;
    counts[st] = (counts[st] ?? 0) + 1;
  }
  const total = view.screenScans.length || 1;

  const scanningId = [...by.entries()].find(([, st]) => st === "scanning")?.[0];
  const scanning = view.screens.find((s) => s.screenId === scanningId);
  const last = view.events.at(-1);
  const lastLog = last ? eventLine(last) : "";
  // Roles whose latest survey state leaves coverage incomplete — a role blocked before any check ran
  // owns no ledger rows, so this projection (full-log, not the 300-event window) is the only place
  // its reason can surface.
  const roleIssues = view.roleProgress.filter((r) => r.state === "blocked" || r.pending > 0);

  return (
    <div className="border-b border-border bg-card px-3 py-2">
      <div className="flex h-2 overflow-hidden rounded-sm bg-inset" role="img" aria-label="Diagnosis progress by status">
        {ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => {
          const c = counts[s] ?? 0;
          return (
            <span
              key={s}
              style={{ width: `${(c / total) * 100}%`, background: COLOR[s] }}
              title={`${s}: ${c}`}
            />
          );
        })}
      </div>
      <div className="mt-1 flex gap-1 text-[11px] text-muted-foreground" aria-label="Diagnosis breakdown">
        {ORDER.filter((status) => (counts[status] ?? 0) > 0).map((status) => (
          <span key={status}>{status === "clean" ? "tested, no findings" : status === "finding" ? "tested, findings" : status === "suspected" ? "tested, unconfirmed leads" : status === "unverified" ? "inconclusive (check gaps)" : status === "unknown-records" ? "claimed (no records)" : status}: {counts[status]} · </span>
        ))}
      </div>
      <div className="mt-1 flex items-baseline gap-1 text-[11px] text-muted-foreground">
        {scanning ? (
          <span>
            ▶ now: <b className="font-mono text-foreground">{scanning.urlTemplate}</b>
          </span>
        ) : (
          <span>{view.phase}</span>
        )}
        {lastLog ? <span className="truncate"> · {lastLog.slice(0, 120)}</span> : null}
      </div>
      {roleIssues.map((r) => (
        <div key={r.role} className={`mt-0.5 text-[11px] ${r.state === "blocked" ? "text-warning" : "text-muted-foreground"}`} title={r.reason}>
          role <span className="font-mono">{r.role}</span>: {r.state === "blocked" ? "blocked" : "unfinished"}
          {r.pending > 0 ? ` (${r.pending} pending${r.gated > 0 ? `, ${r.gated} gated` : ""})` : ""}
          {r.reason ? ` — ${r.reason}` : ""}
        </div>
      ))}
    </div>
  );
}
