import { useState } from "react";
import type { StateView } from "@veritas/core";
import { EvidenceList } from "./EvidenceList";
import { SeverityBadge, severityBorder } from "./SeverityBadge";
import { ChevronRight } from "lucide-react";
import { Badge } from "./ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Input } from "./ui/input";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVS = ["critical", "high", "medium", "low", "info"];

export function Findings({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const [sev, setSev] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const all = view.findings;

  if (all.length === 0) {
    return (
      <section>
        <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Findings (0)</h2>
        <p className="text-muted-foreground">No findings yet.</p>
      </section>
    );
  }

  const counts: Record<string, number> = {};
  for (const f of all) counts[f.severity] = (counts[f.severity] ?? 0) + 1;
  const needle = q.trim().toLowerCase();
  const shown = (sev ? all.filter((f) => f.severity === sev) : all)
    .filter((f) => !needle || `${f.id} ${f.title}\n${f.description}`.toLowerCase().includes(needle))
    .slice()
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">Findings ({all.length})</h2>
      <div className="mb-3 flex flex-wrap gap-2">
        <Button type="button" size="xs" variant={sev === null ? "default" : "outline"} onClick={() => setSev(null)}>all ({all.length})</Button>
        {SEVS.filter((s) => counts[s]).map((s) => (
          <Button type="button" size="xs" variant={sev === s ? "default" : "outline"} key={s} onClick={() => setSev(sev === s ? null : s)}>
            {s} ({counts[s] ?? 0})
          </Button>
        ))}
        <Input className="ml-auto h-7 min-w-44 max-w-60 text-xs" type="search" value={q} onChange={(e) => setQ(e.target.value)} placeholder="filter text…" aria-label="Filter findings by text" />
      </div>
      <div className="flex flex-col gap-3">
        {shown.map((f) => {
          const sid = f.screenId;
          return (
            <Card size="sm" key={f.id} className={`gap-2 border-l-[3px] py-3 ${severityBorder[f.severity]}`}>
              <div className="flex flex-wrap items-center gap-2 px-3">
                <SeverityBadge severity={f.severity} />
                {f.verdict === "suspected" ? <Badge className="bg-suspected text-on-warning">suspected</Badge> : null}
                <span className="font-semibold">{f.title}</span>
                <span className="ml-auto font-mono text-[11px]">
                  {f.id}
                  {sid ? <Button type="button" variant="link" size="xs" onClick={() => onJump(sid)}>{sid}</Button> : null}
                </span>
              </div>
              <p className="px-3 whitespace-pre-wrap">{f.description}</p>
              {f.reproSteps ? (
                <Collapsible className="px-3 text-muted-foreground">
                  <CollapsibleTrigger type="button" className="group flex cursor-pointer items-center gap-1">
                    <ChevronRight className="size-3 transition-transform group-data-[state=open]:rotate-90" /> repro
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <pre className="mt-2 whitespace-pre-wrap rounded bg-inset p-2 font-mono">{f.reproSteps}</pre>
                  </CollapsibleContent>
                </Collapsible>
              ) : null}
              {f.screenshot ? (
                <Collapsible defaultOpen className="px-3 text-muted-foreground">
                  <CollapsibleTrigger type="button" className="group flex cursor-pointer items-center gap-1">
                    <ChevronRight className="size-3 transition-transform group-data-[state=open]:rotate-90" /> screenshot
                  </CollapsibleTrigger>
                  <CollapsibleContent>
                    <a href={`/api/assessments/${encodeURIComponent(view.id)}/findings/${encodeURIComponent(f.id)}/screenshot`} target="_blank" rel="noreferrer">
                      <img className="mt-2 max-h-[360px] max-w-full rounded border border-border" src={`/api/assessments/${encodeURIComponent(view.id)}/findings/${encodeURIComponent(f.id)}/screenshot`} alt={`${f.id} screenshot`} />
                    </a>
                  </CollapsibleContent>
                </Collapsible>
              ) : null}
              {f.evidenceIds.length > 0 ? <div className="px-3"><EvidenceList assessmentId={view.id} evidenceIds={f.evidenceIds} /></div> : null}
            </Card>
          );
        })}
      </div>
    </section>
  );
}
