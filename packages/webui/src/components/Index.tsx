// Project (assessment) list. Shown at `/` (no ?id). Clicking a row goes to ?id=<id>.
// "+ New" launches a run; each row has Stop/Resume (the control plane where the server spawns the CLI).
import { useEffect, useState } from "react";
import type { TargetInput } from "@veritas/core";
import { NewLauncher } from "./NewLauncher";
import type { LaunchInput } from "./NewAssessment";
import { useRole } from "../api";
import { useT } from "../i18n";
import { Copy, MoreHorizontal, Play, Square } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card, CardContent } from "./ui/card";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

interface Row {
  id: string;
  phase: string;
  type: "web" | "api";
  screens: number;
  findings: number;
  target: TargetInput;
  createdAt: string;
  updatedAt: string;
  running: boolean;
  /** Owning account's username in multi-user mode; null when unassigned (admin-only visibility). */
  owner?: string | null;
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

function targetSub(t: TargetInput): string {
  return t.kind === "single_url" ? t.url : t.path;
}

function fmt(iso: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const p = (n: number): string => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function Index() {
  const [rows, setRows] = useState<Row[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [creating, setCreating] = useState<{ initial?: LaunchInput } | null>(null);
  const { canWrite, multiUser, user } = useRole();
  const t = useT();

  useEffect(() => {
    let alive = true;
    const poll = (): void => {
      fetch("/api/assessments")
        .then((r) => r.json())
        .then((l: Row[]) => {
          if (alive) {
            setRows(l);
            setErr(null);
          }
        })
        .catch(() => {
          if (alive) setErr(t("Can't reach server"));
        });
    };
    poll();
    const iv = window.setInterval(poll, 3000);
    return () => {
      alive = false;
      window.clearInterval(iv);
    };
  }, []);

  const runCtl = (id: string, action: "stop" | "resume") => (): void => {
    void fetch(`/api/run/${encodeURIComponent(id)}/${action}`, { method: "POST" });
  };
  // Duplicate: reopen the launcher pre-filled with this run's saved manifest+options (the operator reviews,
  // adjusts, then launches a fresh run — no blind re-fire of the old config).
  const duplicate = (id: string) => (): void => {
    void fetch(`/api/assessments/${encodeURIComponent(id)}/launch-input`)
      .then(async (r) => {
        if (!r.ok) { setErr((await r.json().catch(() => ({}))).error ?? t("no launch input ({status})", { status: r.status })); return; }
        setCreating({ initial: (await r.json()) as LaunchInput });
      })
      .catch(() => setErr(t("Can't reach server")));
  };

  if (creating) {
    return <div className="mx-auto max-w-[1100px] px-5 py-6"><NewLauncher onCancel={() => setCreating(null)} initial={creating.initial} /></div>;
  }

  return (
    <div className="mx-auto max-w-[1100px] px-5 pt-6 pb-12">
      <header className="flex items-center justify-between border-b border-border px-1 pb-5">
        <div className="flex items-baseline gap-3">
          <h1 className="text-base font-semibold">{t("Projects")}</h1>
          <span className="text-muted-foreground">{rows?.length ?? ""}</span>
        </div>
        {canWrite ? <Button type="button" size="sm" onClick={() => setCreating({})}>{t("+ New")}</Button> : null}
      </header>
      {err ? <p role="alert" className="p-4 text-destructive">{err}</p> : null}
      {rows && rows.length === 0 ? (
        <Card className="mt-8">
          <CardContent className="flex flex-col items-center gap-3 py-12 text-center">
            <h2 className="text-lg font-semibold">{t("No assessments yet")}</h2>
            <p className="max-w-md text-muted-foreground">{t("Point VERDICT at a target and it maps the app, then hunts for vulnerabilities — autonomously.")}</p>
            {canWrite ? <Button type="button" onClick={() => setCreating({})}>{t("+ New assessment")}</Button> : <p className="text-muted-foreground">{t("Ask an operator to start one.")}</p>}
          </CardContent>
        </Card>
      ) : null}
      {rows && rows.length > 0 ? (
        <Table className="mt-3 text-xs">
          <TableHeader>
            <TableRow>
              <TableHead>{t("Target")}</TableHead>
              <TableHead>{t("Type")}</TableHead>
              <TableHead>{t("Phase")}</TableHead>
              <TableHead className="text-right">{t("Screens")}</TableHead>
              <TableHead className="text-right">{t("Findings")}</TableHead>
              {multiUser ? <TableHead>{t("Owner")}</TableHead> : null}
              <TableHead>{t("Updated")}</TableHead>
              <TableHead>{t("ID")}</TableHead>
              <TableHead><span className="sr-only">{t("Action")}</span></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((r) => (
              <TableRow key={r.id} className="cursor-pointer" onClick={() => { window.location.search = `?id=${encodeURIComponent(r.id)}`; }}>
                <TableCell className="min-w-48 whitespace-normal">
                  <a href={`?id=${encodeURIComponent(r.id)}`} className="font-semibold text-foreground hover:text-primary" onClick={(e) => e.stopPropagation()}>
                    {r.running ? <span className="mr-2 inline-block size-2 rounded-full bg-primary" title={t("running")} /> : null}
                    {targetName(r.target)}
                  </a>
                  <div className="mt-1 break-all font-mono text-[11px] text-muted-foreground">{targetSub(r.target)}</div>
                </TableCell>
                <TableCell><Badge variant="outline" className={r.type === "api" ? "border-success/40 text-success" : "border-primary/40 text-primary"}>{r.type}</Badge></TableCell>
                <TableCell><Badge variant="outline" className={r.phase === "report" ? "border-success/40 text-success" : r.phase === "phase1_recon" || r.phase === "phase2_scan" ? "border-primary/40 text-primary" : "text-muted-foreground"}>{r.phase}</Badge></TableCell>
                <TableCell className="text-right">{r.screens}</TableCell>
                <TableCell className={r.findings > 0 ? "text-right font-semibold text-warning" : "text-right"}>{r.findings}</TableCell>
                {multiUser ? (
                  <TableCell className="font-mono text-muted-foreground">
                    {r.owner ? (r.owner === user?.username ? t("{owner} (you)", { owner: r.owner }) : r.owner) : "—"}
                  </TableCell>
                ) : null}
                <TableCell className="text-muted-foreground">{fmt(r.updatedAt)}</TableCell>
                <TableCell className="font-mono text-[11px] text-muted-foreground">{r.id}</TableCell>
                <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                  {!canWrite ? (
                    r.running ? <span className="inline-block size-2 rounded-full bg-primary" title={t("running")} /> : null
                  ) : (
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button type="button" variant="ghost" size="icon-sm" aria-label={t("Actions for {id}", { id: r.id })} title={t("Actions")}><MoreHorizontal /></Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {r.running ? (
                          <DropdownMenuItem onSelect={runCtl(r.id, "stop")}><Square /> {t("Stop")}</DropdownMenuItem>
                        ) : (
                          <DropdownMenuItem onSelect={runCtl(r.id, "resume")}><Play /> {t("Resume")}</DropdownMenuItem>
                        )}
                        <DropdownMenuItem onSelect={duplicate(r.id)}><Copy /> {t("Duplicate…")}</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : null}
      {!rows && !err ? <p className="p-4 text-muted-foreground">{t("Loading…")}</p> : null}
    </div>
  );
}
