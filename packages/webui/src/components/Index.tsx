// プロジェクト(アセスメント)一覧。`/`(?id 無し)で表示。各行クリックで ?id=<id> へ。
// "+ New" で run を起動、各行で Stop/Resume(server が CLI を spawn する制御面)。
import { useEffect, useState, type MouseEvent } from "react";
import type { TargetInput } from "@veritas/core";
import { NewAssessment } from "./NewAssessment";
import { useRole } from "../api";

interface Row {
  id: string;
  phase: string;
  screens: number;
  findings: number;
  target: TargetInput;
  createdAt: string;
  updatedAt: string;
  running: boolean;
}

function targetName(t: TargetInput): string {
  if (t.kind === "single_url") {
    try {
      return new URL(t.url).host;
    } catch {
      return t.url;
    }
  }
  const base = t.path.split(/[/\\]/).pop() ?? t.path;
  return base.replace(/\.(json|ya?ml)$/i, "");
}

function targetSub(t: TargetInput): string {
  return t.kind === "single_url" ? t.url : t.path;
}

function fmt(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Index() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const { canWrite, authEnabled, role } = useRole();

  useEffect(() => {
    let alive = true;
    const poll = (): void => {
      fetch("/api/assessments")
        .then((r) => r.json())
        .then((l: Row[]) => {
          if (alive) {
            setRows(l);
            setErr(null);
          }
        })
        .catch(() => {
          if (alive) setErr("Can't reach server");
        });
    };
    poll();
    const t = window.setInterval(poll, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  const runCtl = (id: string, action: "stop" | "resume") => (e: MouseEvent): void => {
    e.stopPropagation();
    void fetch(`/api/run/${encodeURIComponent(id)}/${action}`, { method: "POST" });
  };

  if (creating) {
    return (
      <div className="idx">
        <NewAssessment onCancel={() => setCreating(false)} />
      </div>
    );
  }

  return (
    <div className="idx">
      <header className="idxhead">
        <span className="brand">AMRAAM</span>
        <span className="idxtitle">Projects</span>
        <span className="idxcount">{rows ? `${rows.length}` : ""}</span>
        {authEnabled ? (
          <span className={`rolebadge ${role}`} title={canWrite ? "operator — full access" : "viewer — read-only"}>
            {role}
          </span>
        ) : null}
        {canWrite ? (
          <button type="button" className="idxnew" onClick={() => setCreating(true)}>
            + New
          </button>
        ) : null}
        {authEnabled ? (
          <a className="logout" href="/logout" title="sign out">
            sign out
          </a>
        ) : null}
      </header>
      {err ? <p className="idxempty">{err}</p> : null}
      {rows && rows.length === 0 ? (
        <p className="idxempty">
          No assessments yet. Run <code>pilot</code> or <code>assess</code> and they show up here.
        </p>
      ) : null}
      {rows && rows.length > 0 ? (
        <table className="idxtable">
          <thead>
            <tr>
              <th>Target</th>
              <th>Phase</th>
              <th className="num">Screens</th>
              <th className="num">Findings</th>
              <th>Updated</th>
              <th>ID</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr
                key={r.id}
                className="idxrow"
                onClick={() => {
                  window.location.search = `?id=${encodeURIComponent(r.id)}`;
                }}
              >
                <td>
                  <div className="tname">
                    {r.running ? <span className="rundot" title="running" /> : null}
                    {targetName(r.target)}
                  </div>
                  <div className="tsub">{targetSub(r.target)}</div>
                </td>
                <td>
                  <span className={`phasepill ${r.phase}`}>{r.phase}</span>
                </td>
                <td className="num">{r.screens}</td>
                <td className={`num ${r.findings > 0 ? "hasf" : ""}`}>{r.findings}</td>
                <td className="when">{fmt(r.updatedAt)}</td>
                <td className="mono idcell">{r.id}</td>
                <td className="ctl">
                  {!canWrite ? (
                    r.running ? <span className="rundot" title="running" /> : null
                  ) : r.running ? (
                    <button type="button" className="stopbtn" onClick={runCtl(r.id, "stop")}>
                      ◼ Stop
                    </button>
                  ) : (
                    <button type="button" className="resumebtn" onClick={runCtl(r.id, "resume")}>
                      ▶ Resume
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      {!rows && !err ? <p className="idxempty">Loading…</p> : null}
    </div>
  );
}
