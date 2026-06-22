import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";

// レポート / 画面一覧のダウンロード。GET エンドポイントなので Cookie が自動送出される。
// html/pdf は新タブでプレビュー(inline)、md/csv は添付 DL(server が Content-Disposition を付与)。
function DownloadMenu({ id }: { id: string }) {
  const rep = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/report?format=${f}`;
  const inv = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/inventory?format=${f}`;
  return (
    <details className="dl">
      <summary>⬇ Export</summary>
      <div className="dl-menu">
        <span className="dl-h">Report</span>
        <a href={rep("html")} target="_blank" rel="noreferrer">HTML</a>
        <a href={rep("pdf")} target="_blank" rel="noreferrer">PDF</a>
        <a href={rep("md")}>Markdown</a>
        <a href={rep("csv")}>Findings CSV</a>
        <span className="dl-h">Screen inventory</span>
        <a href={inv("html")} target="_blank" rel="noreferrer">Inventory HTML</a>
        <a href={inv("csv")}>Screens CSV</a>
      </div>
    </details>
  );
}

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
      <a className="brand" href="?" title="Back to projects">AMRAAM</a>
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
        tokens:{" "}
        <b>{view.budget.tokensUsed >= 1000 ? `${(view.budget.tokensUsed / 1000).toFixed(1)}k` : view.budget.tokensUsed}</b>
      </span>
      <span>
        handoffs: <b>{view.handoffs.filter((h) => h.status === "pending").length}</b>
      </span>
      <button type="button" className="pausebtn" onClick={onTogglePause}>
        {view.paused ? "▶ resume" : "⏸ pause"}
      </button>
      <DownloadMenu id={view.id} />
      <span className={`conn ${conn}`}>● {view.paused ? "paused" : conn}</span>
    </header>
  );
}
