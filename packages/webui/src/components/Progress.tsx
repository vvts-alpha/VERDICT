import type { StateView } from "@veritas/core";
import { eventLine } from "./Log";

const ORDER = ["finding", "suspected", "scanning", "queued", "clean", "excluded", "blocked", "error"] as const;
const COLOR: Record<string, string> = {
  finding: "var(--warn)",
  suspected: "var(--warn)",
  scanning: "var(--accent)",
  queued: "var(--line)",
  clean: "var(--ok)",
  excluded: "var(--muted)",
  blocked: "var(--err)",
  error: "var(--err)",
};

// Progress bar (breakdown of scan status) + the screen being diagnosed now + the latest log. See where the run is at a glance.
export function Progress({ view }: { view: StateView }) {
  const by = new Map(view.screenScans.map((s) => [s.screenId, s.status] as const));
  const counts: Record<string, number> = {};
  for (const st of by.values()) counts[st] = (counts[st] ?? 0) + 1;
  const total = view.screenScans.length || 1;

  const scanningId = [...by.entries()].find(([, st]) => st === "scanning")?.[0];
  const scanning = view.screens.find((s) => s.screenId === scanningId);
  const last = view.events.at(-1);
  const lastLog = last ? eventLine(last) : "";

  return (
    <div className="progress">
      <div className="pbar">
        {ORDER.filter((s) => (counts[s] ?? 0) > 0).map((s) => {
          const c = counts[s] ?? 0;
          return (
            <span
              key={s}
              className="pseg"
              style={{ width: `${(c / total) * 100}%`, background: COLOR[s] }}
              title={`${s}: ${c}`}
            />
          );
        })}
      </div>
      <div className="pmeta muted" aria-label="Diagnosis breakdown">
        {ORDER.filter((status) => (counts[status] ?? 0) > 0).map((status) => (
          <span key={status}>{status === "clean" ? "tested, no findings" : status === "finding" ? "tested, findings" : status === "suspected" ? "tested, unconfirmed leads" : status}: {counts[status]} · </span>
        ))}
      </div>
      <div className="pmeta muted">
        {scanning ? (
          <span>
            ▶ now: <b className="mono">{scanning.urlTemplate}</b>
          </span>
        ) : (
          <span>{view.phase}</span>
        )}
        {lastLog ? <span className="plast"> · {lastLog.slice(0, 120)}</span> : null}
      </div>
    </div>
  );
}
