import { useEffect, useMemo, useState } from "react";
import type { Asset, AssetInventory } from "@veritas/core";
import { AssetTree, HostDetail, AssetFindings, SOURCE_META } from "./AssetTree";
import { AsrLog, parseLogLines } from "./AsrLog";

// The ASR assessment viewer — SAME shape as the web/API viewer (StatusBar + Progress + .body[left tree | tabs]),
// just ASR content and only the applicable tabs (Host / Findings / Log — no Scenarios/APIs/Sessions). The UI shape
// no longer differs by target type. Rendered by App for runs detected as ASR.
type Tab = "host" | "findings" | "log";

// Export menu (same .dl markup as the web StatusBar) — the asset inventory as JSON, and client-generated CSVs.
function AsrExport({ id, inv }: { id: string; inv: AssetInventory | null }) {
  const dl = (name: string, content: string): void => {
    const url = URL.createObjectURL(new Blob([content], { type: "text/csv" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };
  const csv = (rows: (string | number | null)[][]): string =>
    rows.map((r) => r.map((c) => `"${String(c ?? "").replace(/"/g, '""')}"`).join(",")).join("\r\n");
  const findingsCsv = (): string => {
    const rows: (string | number | null)[][] = [["host", "severity", "category", "title", "detail"]];
    for (const a of inv?.assets ?? []) for (const f of a.findings ?? []) rows.push([a.host, f.severity, f.category, f.title, f.detail]);
    return csv(rows);
  };
  const assetsCsv = (): string => {
    const rows: (string | number | null)[][] = [["host", "alive", "status", "scheme", "score", "band", "tech", "findings"]];
    for (const a of inv?.assets ?? []) rows.push([a.host, String(a.alive), a.status, a.scheme, a.score?.total ?? "", a.score?.band ?? "", a.tech.join(" "), a.findings?.length ?? 0]);
    return csv(rows);
  };
  return (
    <details className="dl">
      <summary>⬇ Export</summary>
      <div className="dl-menu">
        <span className="dl-h">Attack surface</span>
        <a href={`/api/assessments/${encodeURIComponent(id)}/assets`} target="_blank" rel="noreferrer">Inventory (JSON)</a>
        <button type="button" onClick={() => dl(`asr-${id}-assets.csv`, assetsCsv())}>Assets (CSV)</button>
        <button type="button" onClick={() => dl(`asr-${id}-findings.csv`, findingsCsv())}>Findings (CSV)</button>
      </div>
    </details>
  );
}

export function AsrView({ id }: { id: string }) {
  const [inv, setInv] = useState<AssetInventory | null>(null);
  const [err, setErr] = useState(false);
  const [selected, setSelected] = useState<string | null>(null);
  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null);
  const [tab, setTab] = useState<Tab>("host");
  const [logText, setLogText] = useState("");

  useEffect(() => {
    let alive = true;
    const load = (): void => {
      fetch(`/api/assessments/${encodeURIComponent(id)}/assets`)
        .then((r) => (r.ok ? r.json() : Promise.reject(new Error("no assets"))))
        .then((v: AssetInventory) => {
          if (alive) {
            setInv(v);
            setErr(false);
          }
        })
        .catch(() => {
          if (alive) setErr(true);
        });
    };
    load();
    const t = window.setInterval(load, 4000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [id]);

  // The run log is owned here (not in AsrLog) so the tab can show "Log (N)" like the web viewer, even before it's opened.
  useEffect(() => {
    let alive = true;
    const load = (): void => {
      fetch(`/api/assessments/${encodeURIComponent(id)}/run-log`)
        .then((r) => (r.ok ? r.text() : ""))
        .then((t) => {
          if (alive) setLogText(t);
        })
        .catch(() => {});
    };
    load();
    const t = window.setInterval(load, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [id]);
  const logLines = useMemo(() => parseLogLines(logText), [logText]);

  const assets = inv?.assets ?? [];
  const live = assets.filter((a) => a.alive).length;
  const findingsCount = assets.reduce((n, a) => n + (a.findings?.length ?? 0), 0);
  const discovered = inv?.discovered;
  // Discovery-source mix (S5): per-source counts + whether the run went ACTIVE (any brute-discovered host), and how
  // many hosts have been promoted to a pilot run.
  const bySource: Record<string, number> = {};
  for (const a of assets) bySource[a.source] = (bySource[a.source] ?? 0) + 1;
  const hasActive = (bySource["active"] ?? 0) > 0;
  const promotedCount = assets.filter((a) => a.promoted).length;
  const sourceMix = Object.entries(bySource)
    .sort((x, y) => y[1] - x[1])
    .map(([s, n]) => `${SOURCE_META[s]?.label ?? s} ${n}`)
    .join(" · ");

  const onSelect = (asset: Asset, key: string): void => {
    setSelectedAsset(asset);
    setSelected(key);
    setTab("host");
  };
  const jumpTo = (host: string): void => {
    const a = assets.find((x) => x.host === host);
    if (a) {
      setSelectedAsset(a);
      setSelected(host);
      setTab("host");
    }
  };

  return (
    <div className="page">
      <header className="statusbar">
        <a className="brand" href="?" title="Back to projects">
          <img className="brand-logo" src="/verdict-title.png" alt="VERDICT" />
        </a>
        <span>ASR</span>
        {inv?.apex ? (
          <span>
            apex: <b>{inv.apex}</b>
          </span>
        ) : null}
        <span>
          hosts: <b>{assets.length}</b>
        </span>
        <span>
          live: <b>{live}</b>
        </span>
        <span>
          findings: <b>{findingsCount}</b>
        </span>
        {promotedCount > 0 ? (
          <span title="hosts promoted to a pilot run">
            piloted: <b>{promotedCount}</b>
          </span>
        ) : null}
        {assets.length > 0 ? (
          <span className="asr-srcmix">
            <span
              className={hasActive ? "active-tag" : "passive-tag"}
              title={hasActive ? "this run included an active DNS brute (--brute)" : "passive discovery only (crt.sh / subfinder / import)"}
            >
              {hasActive ? "active" : "passive"}
            </span>
            <span className="muted" title="hosts by discovery source">{sourceMix}</span>
          </span>
        ) : null}
        <span style={{ marginLeft: "auto" }} />
        <AsrExport id={id} inv={inv} />
        <span className={`conn ${err ? "closed" : "open"}`} style={{ marginLeft: 12 }}>● {err ? "error" : "live"}</span>
      </header>

      <div className="progress">
        <div className="pbar">
          {discovered ? (
            <>
              <span className="pseg" style={{ width: `${(live / Math.max(discovered, assets.length)) * 100}%`, background: "var(--ok)" }} title={`live: ${live}`} />
              <span className="pseg" style={{ width: `${((assets.length - live) / Math.max(discovered, assets.length)) * 100}%`, background: "#3a4250" }} title={`no response: ${assets.length - live}`} />
            </>
          ) : null}
        </div>
        <div className="pmeta muted">
          {discovered === undefined ? (
            <span>discovering… (crt.sh)</span>
          ) : assets.length < discovered ? (
            <span>
              probing <b className="mono">{assets.length} / {discovered}</b> hosts · {live} live
            </span>
          ) : (
            <span>
              done · <b className="mono">{assets.length}</b> hosts · {live} live
            </span>
          )}
        </div>
      </div>

      <div className="body">
        {inv && assets.length > 0 ? (
          <AssetTree inv={inv} selected={selected} onSelect={onSelect} />
        ) : (
          <div style={{ borderRight: "1px solid var(--line)", padding: 14, color: "var(--muted)", fontSize: 12.5 }}>
            {err ? "no assets" : !inv ? "loading…" : "scanning… (see Log)"}
          </div>
        )}
        <main className="scroll">
          <div className="tabs">
            <button type="button" className={tab === "host" ? "active" : ""} onClick={() => setTab("host")}>
              Host
            </button>
            <button type="button" className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>
              Findings ({findingsCount})
            </button>
            <button type="button" className={tab === "log" ? "active" : ""} onClick={() => setTab("log")}>
              Log ({logLines.length})
            </button>
          </div>
          <div className="tabbody">
            {tab === "host" ? <HostDetail id={id} asset={selectedAsset} /> : null}
            {tab === "findings" ? <AssetFindings assets={assets} onJump={jumpTo} /> : null}
            {tab === "log" ? <AsrLog lines={logLines} /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
