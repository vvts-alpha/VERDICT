import type { StateView } from "@veritas/core";
import { eventLine } from "./Log";

const ORDER = ["finding", "scanning", "queued", "clean", "excluded", "blocked", "error"] as const;
const COLOR: Record<string, string> = {
  finding: "var(--warn)",
  scanning: "var(--accent)",
  queued: "#3a4250",
  clean: "var(--ok)",
  excluded: "#555",
  blocked: "var(--err)",
  error: "var(--err)",
};

// 進捗バー(scan 状態の内訳)+ 今診断中の画面 + 直近ログ。run 中の現在地が一目で分かる。
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
