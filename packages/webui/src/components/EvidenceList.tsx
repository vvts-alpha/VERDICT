import { useState } from "react";

interface Ev {
  request?: { method?: string; url?: string; headers?: Record<string, string>; body?: string | null } | null;
  response?: { status?: number; finalUrl?: string; headers?: Record<string, string> } | null;
  meta?: { kind?: string; note?: string } | null;
  body?: string;
  requestRaw?: string | null; // full request (raw HTTP)
  responseRaw?: string | null;
}

const HDR_KEYS = ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"];

// Click an evId cited by a finding → show req/resp (headers masked) inline. MULTIPLE items can be open at once
// (so a finding's negative control + its positive replays sit side by side); "expand all" opens them together.
export function EvidenceList({ assessmentId, evidenceIds }: { assessmentId: string; evidenceIds: string[] }) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [data, setData] = useState<Record<string, Ev>>({});

  const fetchEv = (ev: string): void => {
    if (data[ev]) return; // already loaded
    fetch(`/api/assessments/${encodeURIComponent(assessmentId)}/evidence/${encodeURIComponent(ev)}`)
      .then((r) => r.json())
      .then((d: Ev) => setData((prev) => ({ ...prev, [ev]: d })))
      .catch(() => setData((prev) => ({ ...prev, [ev]: {} })));
  };

  const toggle = (ev: string): void => {
    const willOpen = !open.has(ev);
    setOpen((prev) => {
      const next = new Set(prev);
      if (willOpen) next.add(ev);
      else next.delete(ev);
      return next;
    });
    if (willOpen) fetchEv(ev);
  };

  const allOpen = evidenceIds.length > 0 && evidenceIds.every((ev) => open.has(ev));
  const toggleAll = (): void => {
    if (allOpen) {
      setOpen(new Set());
      return;
    }
    setOpen(new Set(evidenceIds));
    for (const ev of evidenceIds) fetchEv(ev);
  };

  return (
    <div className="evlist">
      <div className="evlabel muted">
        evidence ({evidenceIds.length})
        {evidenceIds.length > 1 ? (
          <button type="button" className="evtoggleall" onClick={toggleAll}>
            {allOpen ? "collapse all" : "expand all"}
          </button>
        ) : null}
      </div>
      {evidenceIds.map((ev) => {
        const d = data[ev];
        const isOpen = open.has(ev);
        const hdrs = d?.response?.headers ?? {};
        const hdrLine = HDR_KEYS.filter((k) => hdrs[k]).map((k) => `${k}: ${hdrs[k]}`).join("  ·  ");
        return (
          <div key={ev} className="evitem">
            <button type="button" className={`evbtn${isOpen ? " open" : ""}`} onClick={() => toggle(ev)}>
              {isOpen ? "▾" : "▸"} {ev}
              {d?.meta?.kind ? <span className="muted"> · {d.meta.kind}</span> : null}
            </button>
            {isOpen ? (
              !d ? (
                <div className="evbody muted">loading …</div>
              ) : (
                <div className="evbody">
                  <div className="evreq mono">
                    <span className="evarrow">▷ request</span>
                    {d.requestRaw ? (
                      // full request (raw HTTP: request line + all headers + body)
                      <pre className="evpre">{d.requestRaw}</pre>
                    ) : (
                      <>
                        {" "}
                        <b>{d.request?.method}</b> {d.request?.url}
                        {d.request?.headers && Object.keys(d.request.headers).length ? (
                          <pre className="evpre">
                            {Object.entries(d.request.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}
                          </pre>
                        ) : null}
                        {d.request?.body ? <pre className="evpre">{d.request.body}</pre> : null}
                      </>
                    )}
                  </div>
                  <div className="evres mono">
                    <span className="evarrow">◁ res</span> <b>{d.response?.status}</b> {d.response?.finalUrl ?? ""}
                    {hdrLine ? <div className="evhdr muted">{hdrLine}</div> : null}
                    {d.body ? <pre className="evpre">{d.body.slice(0, 4000)}</pre> : null}
                  </div>
                </div>
              )
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
