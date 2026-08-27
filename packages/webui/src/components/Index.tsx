// Project (assessment) list. Shown at `/` (no ?id). Clicking a row goes to ?id=<id>.
// "+ New" launches a run; each row has Stop/Resume (the control plane where the server spawns the CLI).
import { useEffect, useState, type MouseEvent } from "react";
import type { TargetInput } from "@veritas/core";
import { NewLauncher } from "./NewLauncher";
import { useRole } from "../api";

interface Row {
  id: string;
  phase: string;
  type: "web" | "api" | "asr";
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

/** Running inside the Electron desktop shell? (the title bar there already shows the VERDICT brand). */
const isDesktop = typeof window !== "undefined" && !!(window as unknown as { verdictDesktop?: unknown }).verdictDesktop;

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
        <NewLauncher onCancel={() => setCreating(false)} />
      </div>
    );
  }

  return (
    <div className="idx">
      <header className="idxhead">
        {isDesktop ? null : <img className="brand-logo" src="/verdict-title.png" alt="VERDICT" />}
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
        <div className="idxblank">
          <div className="idxblank-title">No assessments yet</div>
          <p className="idxblank-sub">Point VERDICT at a target and it maps the app, then hunts for vulnerabilities — autonomously.</p>
          {canWrite ? (
            <button type="button" className="idxnew idxblank-cta" onClick={() => setCreating(true)}>
              + New assessment
            </button>
          ) : (
            <p className="idxblank-sub">Ask an operator to start one.</p>
          )}
        </div>
      ) : null}
      {rows && rows.length > 0 ? (
        <table className="idxtable">
          <thead>
            <tr>
              <th>Target</th>
              <th>Type</th>
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
                  <div className="tsub">{r.type === "asr" ? `*.${targetName(r.target)}` : targetSub(r.target)}</div>
                </td>
                <td>
                  <span className={`typepill ${r.type}`}>{r.type}</span>
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
                    <button
                      type="button"
                      className="resumebtn"
                      onClick={runCtl(r.id, "resume")}
                      title={r.type === "asr" ? "re-runs discovery + probe (ASR re-scans from scratch — it has no partial resume)" : undefined}
                    >
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
