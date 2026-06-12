import { useState } from "react";

interface Ev {
  request?: { method?: string; url?: string; body?: string | null } | null;
  response?: { status?: number; finalUrl?: string; headers?: Record<string, string> } | null;
  meta?: { kind?: string; note?: string } | null;
  body?: string;
}

const HDR_KEYS = ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"];

// finding が引用する evId をクリック→ req/resp(headers マスク済)をインライン表示。証拠を UI で検証。
export function EvidenceList({ assessmentId, evidenceIds }: { assessmentId: string; evidenceIds: string[] }) {
  const [open, setOpen] = useState<string | null>(null);
  const [data, setData] = useState<Record<string, Ev>>({});

  const toggle = (ev: string): void => {
    if (open === ev) {
      setOpen(null);
      return;
    }
    setOpen(ev);
    if (!data[ev]) {
      fetch(`/api/assessments/${encodeURIComponent(assessmentId)}/evidence/${encodeURIComponent(ev)}`)
        .then((r) => r.json())
        .then((d: Ev) => setData((prev) => ({ ...prev, [ev]: d })))
        .catch(() => setData((prev) => ({ ...prev, [ev]: {} })));
    }
  };

  return (
    <div className="evlist">
      <div className="evlabel muted">evidence ({evidenceIds.length})</div>
      {evidenceIds.map((ev) => {
        const d = data[ev];
        const isOpen = open === ev;
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
                    <span className="evarrow">▷ req</span> <b>{d.request?.method}</b> {d.request?.url}
                    {d.request?.body ? <pre className="evpre">{d.request.body}</pre> : null}
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
