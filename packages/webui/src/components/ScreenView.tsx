import type { Screen, StateView } from "@veritas/core";
import { EvidenceList } from "./EvidenceList";
import { useRole } from "../api";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Details of the one screen selected in the tree. Order: "page info (screenshot → overview → API/params) → this screen's findings".
export function ScreenView({ view, screen, onExclude }: { view: StateView; screen?: Screen; onExclude: (id: string) => void }) {
  const { canWrite } = useRole();
  if (!screen) {
    return <p className="muted log-empty">← Select a screen from the tree.</p>;
  }
  const status = view.screenScans.find((s) => s.screenId === screen.screenId)?.status ?? "queued";
  const fs = view.findings
    .filter((f) => f.screenId === screen.screenId)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  return (
    <section className="screenview">
      <div className="sv-head">
        <span className="mono sv-url">{screen.urlTemplate}</span>
        <span className={`statuspill st-${status}`}>{status}</span>
        {canWrite ? (
          <button type="button" className="excludebtn" onClick={() => onExclude(screen.screenId)}>
            Exclude
          </button>
        ) : null}
      </div>
      <div className="sv-meta">
        {screen.screenType} · {screen.authState} · <span className="mono">{screen.screenId}</span>
      </div>

      {/* 1. Page screenshot */}
      {screen.screenshot ? (
        <img
          className="sv-shot"
          src={`/api/assessments/${encodeURIComponent(view.id)}/screens/${encodeURIComponent(screen.screenId)}/screenshot`}
          alt={screen.urlTemplate}
        />
      ) : (
        <div className="sv-shot noshot">
          no screenshot — backfill with <code>shots --id {view.id}</code>
        </div>
      )}

      {/* 2. Page overview (if available) */}
      {screen.description ? (
        <div className="sv-section">
          <h4>Overview</h4>
          <p className="sv-desc">{screen.description}</p>
        </div>
      ) : null}

      {screen.labels.length > 0 ? (
        <div className="labels">
          {screen.labels.map((l) => (
            <span key={l} className="label">
              {l}
            </span>
          ))}
        </div>
      ) : null}

      {/* 3. APIs / params (page info) */}
      {screen.apis.length > 0 ? (
        <div className="sv-section">
          <h4>APIs</h4>
          <ul className="apis">
            {screen.apis.map((a) => (
              <li key={`${a.method} ${a.urlTemplate}`} className="mono">
                <b>{a.method}</b> {a.urlTemplate} <span className="muted">[{a.auth}]</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {screen.params.length > 0 ? (
        <div className="sv-section">
          <h4>Params</h4>
          <table className="kv">
            <thead>
              <tr>
                <th>name</th>
                <th>in</th>
                <th>type</th>
              </tr>
            </thead>
            <tbody>
              {screen.params.map((p) => (
                <tr key={`${p.in}:${p.name}`}>
                  <td className="mono">{p.name}</td>
                  <td>{p.in}</td>
                  <td>{p.guessedType}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}

      {screen.observedUrls.length > 0 ? (
        <div className="sv-section">
          <h4>Observed URLs</h4>
          <ul className="observed">
            {screen.observedUrls.slice(0, 8).map((u) => (
              <li key={u} className="mono muted">
                {u}
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* 4. Finally, this screen's findings */}
      {fs.length > 0 ? (
        <div className="sv-section sv-findings">
          <h4>Findings on this screen ({fs.length})</h4>
          {fs.map((f) => (
            <div key={f.id} className={`finding sev-${f.severity}`}>
              <div className="finding-head">
                <span className={`sevpill sev-${f.severity}`}>{f.severity}</span>
                <span className="finding-title">{f.title}</span>
              </div>
              <p className="finding-desc">{f.description}</p>
              {f.reproSteps ? (
                <details>
                  <summary>repro</summary>
                  <pre>{f.reproSteps}</pre>
                </details>
              ) : null}
              {f.evidenceIds.length > 0 ? <EvidenceList assessmentId={view.id} evidenceIds={f.evidenceIds} /> : null}
            </div>
          ))}
        </div>
      ) : null}
    </section>
  );
}
