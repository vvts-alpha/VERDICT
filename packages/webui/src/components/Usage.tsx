// Usage dashboard — per-project provider-reported token spend (input/output split).
// Reads /api/assessments (already owner-filtered server-side in multi-user mode). The Owner column
// appears only when accounts exist; a run recorded before in/out tracking shows "—" for the split.
import { useEffect, useState } from "react";
import type { TargetInput } from "@veritas/core";
import { useRole } from "../api";
import { useT } from "../i18n";
import { ChartColumn, RefreshCw } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import { Table, TableBody, TableCell, TableFooter, TableHead, TableHeader, TableRow } from "./ui/table";

interface UsageRow {
  id: string;
  phase: string;
  target: TargetInput;
  updatedAt: string;
  owner?: string | null;
  usage?: {
    tokensUsed: number;
    inputTokens?: number;
    outputTokens?: number;
    cacheReadTokens?: number;
    cacheCreationTokens?: number;
    totalRequests: number;
  };
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

function num(n: number | undefined): string {
  return n === undefined ? "—" : n.toLocaleString();
}

/** Compact 1.4M/442k formatting for the summary cards. */
function compact(n: number | undefined): string {
  if (n === undefined) return "—";
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toLocaleString();
}

type U = NonNullable<UsageRow["usage"]>;
/** Prompt-side tokens served from cache — never below 0 even if a provider over-reports. */
const cacheRead = (u: U): number => u.cacheReadTokens ?? 0;
/** Uncached prompt work = all prompt-side tokens minus cache reads (Claude cache_creation counts as fresh work). */
const uncachedIn = (u: U): number | undefined => u.inputTokens === undefined ? undefined : Math.max(0, u.inputTokens - cacheRead(u));
/** cache_read / total prompt-side tokens — the "did the cache help" ratio. Undefined when no input was tracked. */
const hitRate = (u: U): number | undefined => u.inputTokens ? cacheRead(u) / u.inputTokens : undefined;
const pct = (v: number | undefined): string => v === undefined ? "—" : `${Math.round(v * 100)}%`;

export function Usage() {
  const { multiUser } = useRole();
  const t = useT();
  const [rows, setRows] = useState<UsageRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = (): void => {
    fetch("/api/assessments")
      .then((r) => r.json())
      .then((l: UsageRow[]) => {
        setRows(l);
        setErr(null);
      })
      .catch(() => setErr(t("Can't reach server")));
  };
  useEffect(() => {
    load();
    const iv = window.setInterval(load, 5000); // running scans keep accruing — refresh lazily
    return () => window.clearInterval(iv);
  }, []);

  const sum = (pick: (u: NonNullable<UsageRow["usage"]>) => number | undefined): number | undefined => {
    if (!rows) return undefined;
    let total = 0;
    let seen = false;
    for (const r of rows) {
      const v = r.usage ? pick(r.usage) : undefined;
      if (v !== undefined) {
        total += v;
        seen = true;
      }
    }
    return seen ? total : undefined;
  };

  return (
    <div className="mx-auto w-full max-w-[1100px] space-y-4 px-5 py-6">
      <header className="flex items-center justify-between border-b border-border pb-4">
        <h1 className="flex items-center gap-2 text-base font-semibold"><ChartColumn className="size-4" /> {t("Usage")}</h1>
        <Button type="button" variant="outline" size="sm" onClick={load}><RefreshCw /> {t("Refresh")}</Button>
      </header>
      {err ? <p role="alert" className="text-xs text-destructive">{err}</p> : null}
      {rows && rows.length > 0 ? (
        <div className="grid grid-cols-3 gap-3 sm:grid-cols-6">
          {(() => {
            const inSum = sum((u) => u.inputTokens);
            const crSum = sum((u) => u.cacheReadTokens);
            const cards: Array<[string, string]> = [
              [t("Total (input + output)"), compact(sum((u) => u.tokensUsed))],
              [t("Tasks"), String(rows.length)],
              [t("Input (uncached)"), compact(sum((u) => uncachedIn(u)))],
              [t("Cache hit"), compact(crSum)],
              [t("Output"), compact(sum((u) => u.outputTokens))],
              [t("Hit rate"), pct(inSum && crSum !== undefined ? crSum / inSum : undefined)],
            ];
            return cards.map(([label, value]) => (
              <div key={label} className="rounded-md border border-border bg-card px-3 py-2">
                <div className="font-mono text-base font-semibold leading-tight">{value}</div>
                <div className="mt-0.5 text-[11px] text-muted-foreground">{label}</div>
              </div>
            ));
          })()}
        </div>
      ) : null}
      <Card>
        <CardContent className="p-4">
          {rows && rows.length > 0 ? (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>{t("Project")}</TableHead>
                  <TableHead>{t("Phase")}</TableHead>
                  {multiUser ? <TableHead>{t("Owner")}</TableHead> : null}
                  <TableHead className="text-right" title={t("prompt-side tokens excluding cache reads")}>{t("Input (uncached)")}</TableHead>
                  <TableHead className="text-right" title={t("prompt-side tokens served from the provider cache")}>{t("Cache hit")}</TableHead>
                  <TableHead className="text-right">{t("Hit rate")}</TableHead>
                  <TableHead className="text-right">{t("Output")}</TableHead>
                  <TableHead className="text-right">{t("Total tokens")}</TableHead>
                  <TableHead className="text-right">{t("Requests")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell>
                      <a href={`?id=${encodeURIComponent(r.id)}`} className="font-semibold text-foreground hover:text-primary">{targetName(r.target)}</a>
                      <div className="mt-0.5 font-mono text-[11px] text-muted-foreground">{r.id}</div>
                    </TableCell>
                    <TableCell><Badge variant="outline" className="text-muted-foreground">{r.phase}</Badge></TableCell>
                    {multiUser ? <TableCell className="font-mono text-muted-foreground">{r.owner ?? "—"}</TableCell> : null}
                    <TableCell className="text-right font-mono">{num(r.usage ? uncachedIn(r.usage) : undefined)}</TableCell>
                    <TableCell className="text-right font-mono">{r.usage?.cacheReadTokens !== undefined ? num(r.usage.cacheReadTokens) : "—"}</TableCell>
                    <TableCell className="text-right font-mono text-muted-foreground">{pct(r.usage ? hitRate(r.usage) : undefined)}</TableCell>
                    <TableCell className="text-right font-mono">{num(r.usage?.outputTokens)}</TableCell>
                    <TableCell className="text-right font-mono font-medium">{num(r.usage?.tokensUsed)}</TableCell>
                    <TableCell className="text-right font-mono text-muted-foreground">{num(r.usage?.totalRequests)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
              <TableFooter>
                <TableRow>
                  <TableCell className="font-medium">{t("Total")}</TableCell>
                  <TableCell />
                  {multiUser ? <TableCell /> : null}
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => uncachedIn(u)))}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.cacheReadTokens))}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{(() => { const inSum = sum((u) => u.inputTokens); const crSum = sum((u) => u.cacheReadTokens); return pct(inSum && crSum !== undefined ? crSum / inSum : undefined); })()}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.outputTokens))}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.tokensUsed))}</TableCell>
                  <TableCell className="text-right font-mono">{num(sum((u) => u.totalRequests))}</TableCell>
                </TableRow>
              </TableFooter>
            </Table>
          ) : rows ? (
            <p className="py-8 text-center text-sm text-muted-foreground">{t("No assessments yet — token usage appears here once a run starts.")}</p>
          ) : (
            <p className="py-4 text-xs text-muted-foreground">{t("Loading…")}</p>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            {t("Input/output are provider-reported (prompt vs completion). Input (uncached) = prompt-side tokens minus cache reads; hit rate = cache read / total prompt-side. \"—\" = recorded before this tracking existed or no cache detail reported.")}
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
