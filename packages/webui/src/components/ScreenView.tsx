import type { Screen, StateView } from "@veritas/core";
import { EvidenceList } from "./EvidenceList";
import { useRole } from "../api";
import { useT } from "../i18n";
import { SeverityBadge, severityBorder } from "./SeverityBadge";
import { ChevronRight } from "lucide-react";
import { Badge } from "./ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "./ui/collapsible";
import { Button } from "./ui/button";
import { Card } from "./ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";
import { screenHonestyMap } from "./screen-status";

const SEV_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// Check-execution status → badge styling (same attention mapping as the report's coverage table).
const CHECK_CLS: Record<string, string> = {
  found: "border-destructive text-destructive",
  suspected: "border-warning text-warning",
  "tested-clean": "border-success text-success",
  "not-applicable": "text-muted-foreground",
  unverified: "border-warning text-warning",
  blocked: "border-destructive text-destructive",
  planned: "text-muted-foreground",
  running: "border-primary text-primary",
};

// Details of the one screen selected in the tree. Order: "page info (screenshot → overview → API/params) → this screen's findings".
export function ScreenView({ view, screen, onExclude }: { view: StateView; screen?: Screen; onExclude: (id: string) => void }) {
  const { canWrite } = useRole();
  const t = useT();
  if (!screen) {
    return <p className="p-4 text-muted-foreground">{t("← Select a screen from the tree.")}</p>;
  }
  const status = view.screenScans.find((s) => s.screenId === screen.screenId)?.status ?? "queued";
  const fs = view.findings
    .filter((f) => f.screenId === screen.screenId)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));
  // This screen's check-execution ledger — status/role/input/reason/evidence per executed check.
  const checks = view.checkExecutions.filter((c) => c.screenId === screen.screenId);
  // A conclusive status with zero ledger rows is a legacy/log-derived claim — disclose it as unknown
  // detail instead of letting it read as verified coverage (a finding-backed screen shows its finding).
  const legacy = checks.length === 0 && (status === "clean" || ((status === "finding" || status === "suspected") && fs.length === 0));
  // Same honesty the tree/summary use: legacy claims show "… (no records)" neutral; a raw "clean"
  // whose ledger still holds gaps/unfulfilled plans shows unverified, not green.
  const honesty = screenHonestyMap(view).get(screen.screenId);
  const effStatus = honesty?.status ?? status;

  return (
    <section>
      <div className="flex flex-wrap items-center gap-3">
        <span className="break-all font-mono text-base font-semibold">{screen.urlTemplate}</span>
        <Badge
          variant="outline"
          className={`ml-auto ${effStatus === "finding" ? "border-warning text-warning" : effStatus === "clean" ? "border-success text-success" : effStatus === "unverified" ? "border-warning text-warning" : effStatus === "scanning" ? "border-primary text-primary" : effStatus === "error" || effStatus === "blocked" ? "border-destructive text-destructive" : "text-muted-foreground"}`}
          title={honesty?.legacy ? t("status claim — no check records (detail unknown)") : honesty && status === "clean" && effStatus === "unverified" ? t("scan status said clean — {gaps} check gap(s), {unfulfilled} unfulfilled plan slot(s) remain", { gaps: honesty.gaps, unfulfilled: honesty.unfulfilled }) : undefined}
        >
          {effStatus === "unknown-records" ? t("{status} (no records)", { status }) : t(effStatus)}
        </Badge>
        {canWrite ? <Button type="button" variant="outline" size="xs" onClick={() => onExclude(screen.screenId)}>{t("Exclude")}</Button> : null}
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
          {t("no screenshot — backfill with")} <code className="font-mono">shots --id {view.id}</code>
        </div>
      )}

      {/* 2. Page overview (if available) */}
      {screen.description ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("Overview")}</h4>
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
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("APIs")}</h4>
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
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("Params")}</h4>
          <Table className="text-xs">
            <TableHeader>
              <TableRow>
                <TableHead>{t("name")}</TableHead>
                <TableHead>{t("in")}</TableHead>
                <TableHead>{t("type")}</TableHead>
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
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("Observed URLs")}</h4>
          <ul className="list-disc pl-4">
            {screen.observedUrls.slice(0, 8).map((u) => (
              <li key={u} className="break-all font-mono text-muted-foreground">{u}</li>
            ))}
          </ul>
        </div>
      ) : null}

      {/* 4. Check executions — what was actually run on this screen (status, role, input, reason,
             evidence). Unverified/blocked rows stay visible next to any finding — they are the honest
             coverage gaps, not silently-clean surface. */}
      {checks.length > 0 ? (
        <div className="mt-5">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("Check executions ({n})", { n: checks.length })}</h4>
          <div className="space-y-2">
            {checks.map((c) => (
              <Card size="sm" key={c.id} className="gap-1.5 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge variant="outline" className={CHECK_CLS[c.status] ?? "text-muted-foreground"}>{t(c.status)}</Badge>
                  <Badge variant="secondary">{c.checkClass}</Badge>
                  <span className="min-w-0 break-all font-mono text-xs">{c.target}</span>
                  {c.tool ? <span className="text-[10px] text-muted-foreground">{c.tool}</span> : null}
                </div>
                <div className="flex flex-wrap gap-x-3 text-[11px] text-muted-foreground">
                  {c.param ? <span>{t("input")} <span className="font-mono">{c.param}</span></span> : null}
                  {c.subject ? <span>{t("as")} <span className="font-mono">{c.subject}</span>{c.principal ? <span className="font-mono"> ({c.principal})</span> : null}</span> : null}
                  {c.tenant ? <span>{t("tenant")} <span className="font-mono">{c.tenant}</span></span> : null}
                  {c.resource ? <span>{t("resource")} <span className="font-mono">{c.resource}</span></span> : null}
                  {c.baselineOk === false ? <span className="text-warning">{t("no valid baseline")}</span> : null}
                  {c.findingIds.length > 0 ? <span>→ {c.findingIds.join(", ")}</span> : null}
                </div>
                {c.reason ? <p className="text-xs text-muted-foreground">{c.reason}</p> : null}
                {c.evidenceIds.length > 0 ? <EvidenceList assessmentId={view.id} evidenceIds={c.evidenceIds} /> : null}
              </Card>
            ))}
          </div>
        </div>
      ) : legacy ? (
        <div className="mt-5 rounded border border-warning/40 bg-warning/10 p-3 text-xs">
          {t("scan status {status} recorded without structured check executions — coverage detail unknown (legacy run or log note; no evidence records).", { status })}
        </div>
      ) : null}

      {/* 5. Finally, this screen's findings */}
      {fs.length > 0 ? (
        <div className="mt-5 space-y-3">
          <h4 className="mb-2 text-xs font-medium uppercase tracking-wide text-muted-foreground">{t("Findings on this screen ({n})", { n: fs.length })}</h4>
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
                    <ChevronRight className="size-3 transition-transform group-data-[state=open]:rotate-90" /> {t("repro")}
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
