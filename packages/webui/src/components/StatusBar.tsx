import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";

export function StatusBar({
  view,
  conn,
  onTogglePause,
}: {
  view: StateView;
  conn: ConnState;
  onTogglePause: () => void;
}) {
  const c = view.coverage;
  return (
    <header className="statusbar">
      <span className="brand">Umbra Hands</span>
      <span>
        phase: <b>{view.phase}</b>
      </span>
      <span>
        screens: <b>{c.total}</b>
      </span>
      <span>
        scanned:{" "}
        <b>
          {c.terminal}/{c.total}
        </b>
      </span>
      <span>
        findings: <b>{view.findings.length}</b>
      </span>
      <span>
        handoffs: <b>{view.handoffs.filter((h) => h.status === "pending").length}</b>
      </span>
      <button type="button" className="pausebtn" onClick={onTogglePause}>
        {view.paused ? "▶ resume" : "⏸ pause"}
      </button>
      <span className={`conn ${conn}`}>● {view.paused ? "paused" : conn}</span>
    </header>
  );
}
