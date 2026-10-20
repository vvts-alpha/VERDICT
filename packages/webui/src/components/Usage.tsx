// Usage dashboard — per-project provider-reported token spend (input/output split).
// Reads /api/assessments (already owner-filtered server-side in multi-user mode). The Owner column
// appears only when accounts exist; a run recorded before in/out tracking shows "—" for the split.
import { useEffect, useState } from "react";
import type { TargetInput } from "@veritas/core";
import { useRole } from "../api";
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

export function Usage() {
  const { multiUser } = useRole();
  const [rows, setRows] = useState<UsageRow[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const load = (): void => {
    fetch("/api/assessments")
      .then((r) => r.json())
      .then((l: UsageRow[]) => {
        setRows(l);
        setErr(null);
      })
      .catch(() => setErr("Can't reach server"));
  };
  useEffect(() => {
    load();
    const t = window.setInterval(load, 5000); // running scans keep accruing — refresh lazily
    return () => window.clearInterval(t);
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
        <h1 className="flex items-center gap-2 text-base font-semibold"><ChartColumn className="size-4" /> Usage</h1>
        <Button type="button" variant="outline" size="sm" onClick={load}><RefreshCw /> Refresh</Button>
      </header>
      {err ? <p role="alert" className="text-xs text-destructive">{err}</p> : null}
      <Card>
        <CardContent className="p-4">
          {rows && rows.length > 0 ? (
            <Table className="text-xs">
              <TableHeader>
                <TableRow>
                  <TableHead>Project</TableHead>
                  <TableHead>Phase</TableHead>
                  {multiUser ? <TableHead>Owner</TableHead> : null}
                  <TableHead className="text-right">Input</TableHead>
                  <TableHead className="text-right">Output</TableHead>
                  <TableHead className="text-right">Total tokens</TableHead>
                  <TableHead className="text-right">Requests</TableHead>
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
                    <TableCell className="text-right font-mono">{num(r.usage?.inputTokens)}</TableCell>
                    <TableCell className="text-right font-mono">{num(r.usage?.outputTokens)}</TableCell>
                    <TableCell className="text-right font-mono font-medium">{num(r.usage?.tokensUsed)}</TableCell>
                    <TableCell className="text-right font-mono text-muted-foreground">{num(r.usage?.totalRequests)}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
              <TableFooter>
                <TableRow>
                  <TableCell className="font-medium">Total</TableCell>
                  <TableCell />
                  {multiUser ? <TableCell /> : null}
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.inputTokens))}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.outputTokens))}</TableCell>
                  <TableCell className="text-right font-mono font-semibold">{num(sum((u) => u.tokensUsed))}</TableCell>
                  <TableCell className="text-right font-mono">{num(sum((u) => u.totalRequests))}</TableCell>
                </TableRow>
              </TableFooter>
            </Table>
          ) : rows ? (
            <p className="py-8 text-center text-sm text-muted-foreground">No assessments yet — token usage appears here once a run starts.</p>
          ) : (
            <p className="py-4 text-xs text-muted-foreground">Loading…</p>
          )}
          <p className="mt-3 text-xs text-muted-foreground">
            Input/output are provider-reported (prompt vs completion; Claude cache buckets count as input). "—" = recorded before split tracking or estimated without provider usage.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
