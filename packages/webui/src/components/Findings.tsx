import { useState } from "react";
import type { StateView } from "@veritas/core";
import { EvidenceList } from "./EvidenceList";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVS = ["critical", "high", "medium", "low", "info"];

export function Findings({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const [sev, setSev] = useState<string | null>(null);
  const all = view.findings;

  if (all.length === 0) {
    return (
      <section className="findings-tab">
        <h2>Findings (0)</h2>
        <p className="muted">No findings yet.</p>
      </section>
    );
  }

  const counts: Record<string, number> = {};
  for (const f of all) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const shown = (sev ? all.filter((f) => f.severity === sev) : all)
    .slice()
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  return (
    <section className="findings-tab">
      <h2>Findings ({all.length})</h2>
      <div className="filterbar">
        <button type="button" className={sev === null ? "active" : ""} onClick={() => setSev(null)}>
          all ({all.length})
        </button>
        {SEVS.filter((s) => counts[s]).map((s) => (
          <button
            type="button"
            key={s}
            className={`sevf sevf-${s}${sev === s ? " active" : ""}`}
            onClick={() => setSev(sev === s ? null : s)}
          >
            {s} ({counts[s] ?? 0})
          </button>
        ))}
      </div>
      <div className="findings">
        {shown.map((f) => {
          const sid = f.screenId;
          return (
            <div key={f.id} className={`finding sev-${f.severity}`}>
              <div className="finding-head">
                <span className={`sevpill sev-${f.severity}`}>{f.severity}</span>
                <span className="finding-title">{f.title}</span>
                <span className="finding-id">
                  {f.id}
                  {sid ? (
                    <button type="button" className="screenlink" onClick={() => onJump(sid)}>
                      {sid}
                    </button>
                  ) : null}
                </span>
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
          );
        })}
      </div>
    </section>
  );
}
