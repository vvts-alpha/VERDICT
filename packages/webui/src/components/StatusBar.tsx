import { useRef, useState } from "react";
import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";

// Burp Pro の XML レポートをアップロードして net-new issue を取り込む(CLI burp-import の API 版)。
// 成功すると server が upsertFinding → WS イベントを出すので、findings は自動で増える。
function BurpImport({ id }: { id: string }) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string>("");
  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // 同じファイルを連続で選べるようにリセット
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

// Burp 能動スキャン(REST)を既存 run に対して起動。完了時に子プロセスが自動で issue を取り込むので
// findings は WS 経由で勝手に増える(XML を手で export する必要なし)。Burp 接続は server 側 env(BURP_API)。
function BurpScanButton({ id }: { id: string }) {
  const [status, setStatus] = useState<string>("");
  const [busy, setBusy] = useState(false);
  async function onClick() {
    if (busy) return;
    setBusy(true);
    setStatus("▶ starting…");
    try {
      const r = await fetch(`/api/run/${encodeURIComponent(id)}/burp-scan`, { method: "POST" });
      const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!r.ok) {
        setStatus(`⚠ ${j.error ?? `HTTP ${r.status}`}`);
      } else {
        setStatus("✓ scanning in Burp — findings import automatically when done");
      }
    } catch (err) {
      setStatus(`⚠ ${String(err).slice(0, 100)}`);
    } finally {
      setBusy(false);
    }
  }
  return (
    <span className="burpscan" title="Run a Burp Pro active scan (REST) on this run's in-scope surface and auto-import results">
      <button type="button" className="burpscan-btn" onClick={onClick} disabled={busy}>
        🐛 Burp scan
      </button>
      {status && <span className="burpscan-status">{status}</span>}
    </span>
  );
}

// レポート / 画面一覧のダウンロード。GET エンドポイントなので Cookie が自動送出される。
// html/pdf は新タブでプレビュー(inline)、md/csv は添付 DL(server が Content-Disposition を付与)。
function DownloadMenu({ id }: { id: string }) {
  const rep = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/report?format=${f}`;
  const inv = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/inventory?format=${f}`;
  return (
    <details className="dl">
      <summary>⬇ Export / Import</summary>
      <div className="dl-menu">
        <span className="dl-h">Report</span>
        <a href={rep("html")} target="_blank" rel="noreferrer">HTML</a>
        <a href={rep("pdf")} target="_blank" rel="noreferrer">PDF</a>
        <a href={rep("md")}>Markdown</a>
        <a href={rep("csv")}>Findings CSV</a>
        <span className="dl-h">Screen inventory</span>
        <a href={inv("html")} target="_blank" rel="noreferrer">Inventory HTML</a>
        <a href={inv("csv")}>Screens CSV</a>
        <BurpImport id={id} />
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
      <BurpScanButton id={view.id} />
      <DownloadMenu id={view.id} />
      <span className={`conn ${conn}`}>● {view.paused ? "paused" : conn}</span>
    </header>
  );
}
