import type { Screen, StateView } from "@veritas/core";
import { EvidenceList } from "./EvidenceList";
import { useRole } from "../api";
import { SeverityBadge, severityBorder } from "./SeverityBadge";
import { ChevronRight } from "lucide-react";
import { Badge } from "./ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Details of the one screen selected in the tree. Order: "page info (screenshot → overview → API/params) → this screen's findings".
export function ScreenView({ view, screen, onExclude }: { view: StateView; screen?: Screen; onExclude: (id: string) => void }) {
  const { canWrite } = useRole();
  if (!screen) {
    return <p className="p-4 text-muted-foreground">← Select a screen from the tree.</p>;
  }
  const status = view.screenScans.find((s) => s.screenId === screen.screenId)?.status ?? "queued";
  const fs = view.findings
    .filter((f) => f.screenId === screen.screenId)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  return (
    <section>
      <div className="flex flex-wrap items-center gap-3">
        <span className="break-all font-mono text-base font-semibold">{screen.urlTemplate}</span>
        <Badge variant="outline" className={`ml-auto ${status === "finding" ? "border-warning text-warning" : status === "clean" ? "border-success text-success" : status === "scanning" ? "border-primary text-primary" : status === "error" || status === "blocked" ? "border-destructive text-destructive" : "text-muted-foreground"}`}>{status}</Badge>
        {canWrite ? <Button type="button" variant="outline" size="xs" onClick={() => onExclude(screen.screenId)}>Exclude</Button> : null}
      </div>
      <div className="my-2 text-xs text-muted-foreground">
        {screen.screenType} · {screen.authState} · <span className="font-mono">{screen.screenId}</span>
      </div>

      {/* 1. Page screenshot */}
      {screen.screenshot ? (
        <img
          className="block w-full max-w-[940px] rounded border border-border bg-inset"
          src={`/api/assessments/${encodeURIComponent(view.id)}/screens/${encodeURIComponent(screen.screenId)}/screenshot`}
          alt={screen.urlTemplate}
        />
      ) : (
        <div className="w-full max-w-[940px] rounded border border-border bg-inset p-12 text-center text-muted-foreground">
          no screenshot — backfill with <code className="font-mono">shots --id {view.id}</code>
        </div>
      )}

      {/* 2. Page overview (if available) */}
      {screen.description ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Overview</h4>
          <p>{screen.description}</p>
        </div>
      ) : null}

      {screen.labels.length > 0 ? (
        <div className="flex flex-wrap gap-2 py-2">
          {screen.labels.map((l) => <Badge key={l} variant="secondary">{l}</Badge>)}
        </div>
      ) : null}

      {/* 3. APIs / params (page info) */}
      {screen.apis.length > 0 ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">APIs</h4>
          <ul className="list-disc pl-4">
            {screen.apis.map((a) => (
              <li key={`${a.method} ${a.urlTemplate}`} className="font-mono">
                <b>{a.method}</b> {a.urlTemplate} <span className="text-muted-foreground">[{a.auth}]</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {screen.params.length > 0 ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Params</h4>
          <Table className="text-xs">
            <TableHeader>
              <TableRow>
                <TableHead>name</TableHead>
                <TableHead>in</TableHead>
                <TableHead>type</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {screen.params.map((p) => (
                <TableRow key={`${p.in}:${p.name}`}>
                  <TableCell className="font-mono">{p.name}</TableCell>
                  <TableCell>{p.in}</TableCell>
                  <TableCell>{p.guessedType}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      ) : null}

      {screen.observedUrls.length > 0 ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Observed URLs</h4>
          <ul className="list-disc pl-4">
            {screen.observedUrls.slice(0, 8).map((u) => (
              <li key={u} className="break-all font-mono text-muted-foreground">{u}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* 4. Finally, this screen's findings */}
      {fs.length > 0 ? (
        <div className="mt-5 space-y-3">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">Findings on this screen ({fs.length})</h4>
          {fs.map((f) => (
            <Card size="sm" key={f.id} className={`gap-2 border-l-[3px] py-3 ${severityBorder[f.severity]}`}>
              <div className="flex items-center gap-2 px-3">
                <SeverityBadge severity={f.severity} />
                <span className="font-semibold">{f.title}</span>
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
              {f.evidenceIds.length > 0 ? <div className="px-3"><EvidenceList assessmentId={view.id} evidenceIds={f.evidenceIds} /></div> : null}
            </Card>
          ))}
        </div>
      ) : null}
    </section>
  );
}
