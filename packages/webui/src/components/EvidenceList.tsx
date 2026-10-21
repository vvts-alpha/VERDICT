import { useState } from "react";
import { ChevronRight } from "lucide-react";
import { useT } from "../i18n";
import { Button } from "./ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";

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
  const t = useT();
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
    <div className="mt-2 space-y-1">
      <div className="text-[10px] uppercase tracking-wide text-muted-foreground">
        {t("evidence ({n})", { n: evidenceIds.length })}
        {evidenceIds.length > 1 ? (
          <Button type="button" variant="ghost" size="xs" onClick={toggleAll}>{allOpen ? t("collapse all") : t("expand all")}</Button>
        ) : null}
      </div>
      {evidenceIds.map((ev) => {
        const d = data[ev];
        const isOpen = open.has(ev);
        const hdrs = d?.response?.headers ?? {};
        const hdrLine = HDR_KEYS.filter((k) => hdrs[k]).map((k) => `${k}: ${hdrs[k]}`).join("  ·  ");
        const pre = "mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-inset p-2 font-mono";
        return (
          <Collapsible key={ev} open={isOpen} onOpenChange={() => toggle(ev)}>
            <CollapsibleTrigger asChild>
              <Button type="button" variant="outline" size="xs" className="h-auto w-full justify-start py-1 font-mono" aria-label={t("{action} evidence {id}", { action: isOpen ? t("Collapse") : t("Expand"), id: ev })}>
                <ChevronRight className={`size-3 transition-transform ${isOpen ? "rotate-90" : ""}`} /> {ev}
                {d?.meta?.kind ? <span className="text-muted-foreground"> · {d.meta.kind}</span> : null}
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="rounded-b border border-t-0 border-border bg-inset p-2 font-mono text-xs">
              {!d ? <div className="text-muted-foreground">{t("loading …")}</div> : (
                <>
                  <div className="break-all">
                    <span className="text-muted-foreground">{t("▷ request")}</span>
                    {d.requestRaw ? (
                      // full request (raw HTTP: request line + all headers + body)
                      <pre className={pre}>{d.requestRaw}</pre>
                    ) : (
                      <>
                        {" "}
                        <b>{d.request?.method}</b> {d.request?.url}
                        {d.request?.headers && Object.keys(d.request.headers).length ? <pre className={pre}>{Object.entries(d.request.headers).map(([k, v]) => `${k}: ${v}`).join("\n")}</pre> : null}
                        {d.request?.body ? <pre className={pre}>{d.request.body}</pre> : null}
                      </>
                    )}
                  </div>
                  <div className="mt-2 break-all">
                    <span className="text-muted-foreground">{t("◁ res")}</span> <b>{d.response?.status}</b> {d.response?.finalUrl ?? ""}
                    {hdrLine ? <div className="text-muted-foreground">{hdrLine}</div> : null}
                    {d.body ? <pre className={pre}>{d.body.slice(0, 4000)}</pre> : null}
                  </div>
                </>
              )}
            </CollapsibleContent>
          </Collapsible>
        );
      })}
    </div>
  );
}
