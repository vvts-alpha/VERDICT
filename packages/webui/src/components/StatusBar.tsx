import { useRef, useState } from "react";
import type { ReactNode } from "react";
import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";
import { useRole } from "../api";

// Upload a Burp Pro XML report to import net-new issues (the API version of the CLI burp-import).
// On success, the server calls upsertFinding → emits WS events, so findings grow automatically.
function BurpImport({ id }: { id: string }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string>("");
  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // reset so the same file can be picked again in a row
    if (!file) return;
    setStatus(`⏳ importing ${file.name}…`);
    try {
      const r = await fetch(`/api/assessments/${encodeURIComponent(id)}/burp-import`, {
        method: "POST",
        headers: { "content-type": "application/xml" },
        body: file,
      });
      const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!r.ok) {
        setStatus(`⚠ ${j.error ?? `HTTP ${r.status}`}`);
        return;
      }
      setStatus("✓ importing — net-new findings appear, High+ get AI re-verified");
    } catch (err) {
      setStatus(`⚠ ${String(err).slice(0, 120)}`);
    }
  }
  return (
    <>
      <span className="dl-h">Import</span>
      <button type="button" className="dl-imp" onClick={() => fileRef.current?.click()}>
        ⬆ Burp XML report
      </button>
      <input ref={fileRef} type="file" accept=".xml,application/xml,text/xml" style={{ display: "none" }} onChange={onPick} />
      {status && <span className="dl-status">{status}</span>}
    </>
  );
}

// The Report section of an Export menu — the assessment report in every format (HTML/PDF/Markdown/Findings CSV),
// generated on the fly from the store's findings by `/report`. SHARED so every viewer's Export offers the identical
// Report block: the web/API viewer (DownloadMenu, below) and the ASR viewer (AsrView's AsrExport) both render this,
// so "Report" never drifts per view. GET endpoints → cookies sent automatically; html/pdf preview inline, md/csv download.
export function ReportLinks({ id }: { id: string }) {
  const rep = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/report?format=${f}`;
  return (
    <>
      <span className="dl-h">Report</span>
      <a href={rep("html")} target="_blank" rel="noreferrer">HTML</a>
      <a href={rep("pdf")} target="_blank" rel="noreferrer">PDF</a>
      <a href={rep("md")}>Markdown</a>
      <a href={rep("csv")}>Findings CSV</a>
    </>
  );
}

// Download the report / screen inventory. These are GET endpoints, so cookies are sent automatically.
// html/pdf preview in a new tab (inline); md/csv download as attachments (the server sets Content-Disposition).
function DownloadMenu({ id, canWrite }: { id: string; canWrite: boolean }) {
  const inv = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/inventory?format=${f}`;
  return (
    <details className="dl">
      <summary>{canWrite ? "⬇ Export / Import" : "⬇ Export"}</summary>
      <div className="dl-menu">
        <ReportLinks id={id} />
        <span className="dl-h">Screen inventory</span>
        <a href={inv("html")} target="_blank" rel="noreferrer">Inventory HTML</a>
        <a href={inv("csv")}>Screens CSV</a>
        {canWrite ? <BurpImport id={id} /> : null}
      </div>
    </details>
  );
}

/**
 * The shared status-bar chrome — brand · role badge · sign-out · `● {conn}` dot — with slots for the middle metrics,
 * optional actions (pause), and an export menu. BOTH the web viewer (StatusBar, below) and the ASR viewer (AsrView)
 * render through this, so the header is byte-identical across target types: same role badge, same sign-out link, same
 * connection indicator. Add anything header-common here, never re-implement it per view.
 */
export function StatusBarShell({
  conn,
  paused,
  metrics,
  actions,
  exportMenu,
}: {
  conn: ConnState;
  paused?: boolean;
  metrics: ReactNode;
  actions?: ReactNode;
  exportMenu?: ReactNode;
}) {
  const { canWrite, authEnabled, role } = useRole();
  return (
    <header className="statusbar">
      <a className="brand" href="?" title="Back to projects"><img className="brand-logo" src="/verdict-title.png" alt="VERDICT" /></a>
      {authEnabled ? (
        <span className={`rolebadge ${role}`} title={canWrite ? "operator — full access" : "viewer — read-only"}>
          {role}
        </span>
      ) : null}
      {metrics}
      {/* single spacer owns the right-alignment for the trailing controls group (pause · export · sign out · conn),
          so it right-aligns identically whether or not a view supplies a pause button (ASR has none). */}
      <span className="sb-spacer" />
      {actions}
      {exportMenu}
      {authEnabled ? (
        <a className="logout" href="/logout" title="sign out">
          sign out
        </a>
      ) : null}
      <span className={`conn ${conn}`}>● {paused ? "paused" : conn}</span>
    </header>
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
  const { canWrite } = useRole();
  return (
    <StatusBarShell
      conn={conn}
      paused={view.paused}
      metrics={
        <>
          <span>phase: <b>{view.phase}</b></span>
          <span>screens: <b>{c.total}</b></span>
          <span>scanned: <b>{c.terminal}/{c.total}</b></span>
          <span>findings: <b>{view.findings.length}</b></span>
          <span>tokens: <b>{view.budget.tokensUsed >= 1000 ? `${(view.budget.tokensUsed / 1000).toFixed(1)}k` : view.budget.tokensUsed}</b></span>
          <span>handoffs: <b>{view.handoffs.filter((h) => h.status === "pending").length}</b></span>
        </>
      }
      actions={
        canWrite ? (
          <button type="button" className="pausebtn" onClick={onTogglePause}>
            {view.paused ? "▶ resume" : "⏸ pause"}
          </button>
        ) : null
      }
      exportMenu={<DownloadMenu id={view.id} canWrite={canWrite} />}
    />
  );
}
