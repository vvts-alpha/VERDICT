import { useMemo, useState } from "react";
import type { Asset } from "@veritas/core";
import { SOURCE_META } from "./AssetTree";

// The Assets tab — every discovered host in one sortable table (host · status · port · score · band · findings · tech
// · source), so the whole surface can be scanned and ranked at a glance. Complements the left tree (kept as-is); a row
// click jumps the tree/Host tab to that asset. Sorting is client-side over the already-loaded inventory.

type SortKey = "host" | "status" | "port" | "score" | "band" | "findings";

const bandRank = (b: string | undefined): number => (b === "critical" ? 3 : b === "high" ? 2 : b === "medium" ? 1 : b === "low" ? 0 : -1);
// ASR probes 80/443 only, so the port is derived from the live scheme (— when the host didn't respond).
const portOf = (a: Asset): number | null => (!a.alive ? null : a.scheme === "https" ? 443 : a.scheme === "http" ? 80 : null);

export function AssetTable({ assets, selected, onJump }: { assets: Asset[]; selected: string | null; onJump: (host: string) => void }) {
  const [key, setKey] = useState<SortKey>("score");
  const [asc, setAsc] = useState(false); // default: highest score first

  const rows = useMemo(() => {
    const val = (a: Asset): number | string => {
      switch (key) {
        case "host": return a.host;
        case "status": return a.status ?? -1;
        case "port": return portOf(a) ?? -1;
        case "score": return a.score?.total ?? -1;
        case "band": return bandRank(a.score?.band);
        case "findings": return a.findings?.length ?? 0;
      }
    };
    return [...assets].sort((x, y) => {
      const vx = val(x);
      const vy = val(y);
      const cmp = typeof vx === "string" ? vx.localeCompare(vy as string) : (vx as number) - (vy as number);
      // stable tiebreak on host so equal rows don't jitter between polls
      return (asc ? cmp : -cmp) || x.host.localeCompare(y.host);
    });
  }, [assets, key, asc]);

  const sortBy = (k: SortKey): void => {
    if (k === key) setAsc((v) => !v);
    else {
      setKey(k);
      setAsc(k === "host"); // text ascends by default, numbers descend (biggest first)
    }
  };
  const Th = ({ k, label }: { k: SortKey; label: string }) => (
    <th className={`sortable ${key === k ? "sorted" : ""}`} onClick={() => sortBy(k)} title="click to sort">
      {label}
      {key === k ? <span className="sortarrow">{asc ? " ▲" : " ▼"}</span> : null}
    </th>
  );

  if (assets.length === 0) return <p className="muted log-empty">No assets yet.</p>;
  return (
    <div className="asr-table-wrap">
      <table className="asr-table">
        <thead>
          <tr>
            <Th k="host" label="Host" />
            <Th k="status" label="Status" />
            <Th k="port" label="Port" />
            <Th k="score" label="Score" />
            <Th k="band" label="Band" />
            <Th k="findings" label="Findings" />
            <th>Tech</th>
            <th>Source</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((a) => (
            <tr
              key={a.host}
              className={`${a.alive ? "" : "dead"} ${selected === a.host ? "sel" : ""}`}
              onClick={() => onJump(a.host)}
              title="jump to host"
            >
              <td className="mono host">{a.host}</td>
              <td className="mono">{a.status ?? "—"}</td>
              <td className="mono">{portOf(a) ?? "—"}</td>
              <td className="mono">{a.score?.total ?? "—"}</td>
              <td>{a.score?.band ? <span className={`bandpill band-${a.score.band}`}>{a.score.band}</span> : "—"}</td>
              <td className="mono num">{a.findings?.length ?? 0}</td>
              <td className="muted">{a.tech.length ? a.tech.join(" · ") : "—"}</td>
              <td className="muted">{SOURCE_META[a.source]?.label ?? a.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
