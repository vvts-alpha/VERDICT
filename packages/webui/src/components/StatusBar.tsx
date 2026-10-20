import { useRef, useState } from "react";
import type { ReactNode } from "react";
import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";
import { signOut, useRole } from "../api";
import { screenHonestyMap } from "./screen-status";
import { Download, Pause, Play, Upload } from "lucide-react";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel,
  DropdownMenuSeparator, DropdownMenuTrigger,
} from "./ui/dropdown-menu";

// Upload a Burp Pro XML report to import net-new issues (the API version of the CLI burp-import).
// On success, the server calls upsertFinding → emits WS events, so findings grow automatically.
// The file input + status MUST live outside the DropdownMenu: onSelect closes (unmounts) the menu,
// so an input inside it is destroyed before the picker fires change — the POST would never run.
function useBurpImport(id: string): { fileRef: React.RefObject<HTMLInputElement | null>; input: ReactNode; status: ReactNode } {
  const fileRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string>("");
  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // reset so the same file can be picked again in a row
    if (!file) return;
    setStatus(`⏳ importing ${file.name}…`);
    try {
      const r = await fetch(`/api/assessments/${encodeURIComponent(id)}/burp-import`, {
        method: "POST",
        headers: { "content-type": "application/xml" },
        body: file,
      });
      const j = (await r.json().catch(() => ({}))) as { ok?: boolean; error?: string };
      if (!r.ok) {
        setStatus(`⚠ ${j.error ?? `HTTP ${r.status}`}`);
        return;
      }
      setStatus("✓ importing — net-new findings appear, High+ get AI re-verified");
    } catch (err) {
      setStatus(`⚠ ${String(err).slice(0, 120)}`);
    }
  }
  return {
    fileRef,
    input: <input ref={fileRef} type="file" accept=".xml,application/xml,text/xml" className="hidden" onChange={onPick} />,
    status: status ? (
      <span role="status" className="max-w-56 truncate text-xs text-muted-foreground" title={status}>{status}</span>
    ) : null,
  };
}

// The Report section of an Export menu — the assessment report in every format (HTML/PDF/Markdown/Findings CSV),
// generated on the fly from the store's findings by `/report`. SHARED so every viewer's Export offers the identical
// Shared report block for assessment export menus,
// so "Report" never drifts per view. GET endpoints send cookies automatically; every report format downloads.
export function ReportLinks({ id }: { id: string }) {
  const rep = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/report?format=${f}`;
  return (
    <>
      <DropdownMenuLabel>Report</DropdownMenuLabel>
      <DropdownMenuItem asChild><a href={rep("html")} download={`${id}-report.html`}>HTML</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("pdf")} download={`${id}-report.pdf`}>PDF</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("md")}>Markdown</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("csv")}>Findings CSV</a></DropdownMenuItem>
    </>
  );
}

// Download the report / screen inventory. These are GET endpoints, so cookies are sent automatically.
// Reports download as attachments; the inventory HTML keeps its separate preview.
function DownloadMenu({ id, canWrite }: { id: string; canWrite: boolean }) {
  const inv = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/inventory?format=${f}`;
  const burp = useBurpImport(id);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="outline" size="xs"><Download /> {canWrite ? "Export / Import" : "Export"}</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          <ReportLinks id={id} />
          <DropdownMenuSeparator />
          <DropdownMenuLabel>Screen inventory</DropdownMenuLabel>
          <DropdownMenuItem asChild><a href={inv("html")} target="_blank" rel="noreferrer">Inventory HTML</a></DropdownMenuItem>
          <DropdownMenuItem asChild><a href={inv("csv")}>Screens CSV</a></DropdownMenuItem>
          {canWrite ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>Import</DropdownMenuLabel>
              <DropdownMenuItem onSelect={() => burp.fileRef.current?.click()}><Upload /> Burp XML report</DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      {burp.input}
      {burp.status}
    </>
  );
}

/**
 * The shared header chrome — breadcrumb · role badge · sign-out · `● {conn}` dot — with slots for
 * optional actions (pause) and an export menu. Assessment views render through this, so the header is
 * byte-identical across target types: same role badge, same sign-out link, same connection indicator.
 * Add anything header-common here, never re-implement it per view. (The brand/logo lives in the sidebar.)
 */
export function StatusBarShell({
  conn,
  paused,
  crumbs,
  stats,
  actions,
  exportMenu,
}: {
  conn?: ConnState;
  paused?: boolean;
  crumbs: ReactNode;
  /** Compact run metrics, rendered right after the context slot (may truncate on narrow widths). */
  stats?: ReactNode;
  actions?: ReactNode;
  exportMenu?: ReactNode;
}) {
  const { canWrite, authEnabled, role, multiUser, user } = useRole();
  const roleTitle = multiUser
    ? `${user?.username ?? "account"} — ${role === "admin" ? "administrator" : "user"} (${user?.method ?? "session"})`
    : canWrite
      ? "operator — full access"
      : "viewer — read-only";
  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border px-4 whitespace-nowrap">
      {crumbs}
      {stats}
      {/* single spacer owns the right-alignment for the trailing controls group (pause · export · sign out · conn),
          so it right-aligns identically whether or not a view supplies a pause button. */}
      <span className="ml-auto" />
      {actions}
      {exportMenu}
      {authEnabled ? (
        <Badge variant="outline" className={canWrite ? "border-primary/40 bg-primary/15 text-primary" : "text-muted-foreground"} title={roleTitle}>
          {multiUser && user ? `${user.username} · ${role}` : role}
        </Badge>
      ) : null}
      {authEnabled ? (
        multiUser ? (
          <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => void signOut(true)} title="sign out">
            sign out
          </button>
        ) : (
          <a className="text-xs text-muted-foreground hover:text-foreground" href="/logout" title="sign out">
            sign out
          </a>
        )
      ) : null}
      {conn ? (
        <span className={conn === "open" ? "text-success" : conn === "connecting" ? "text-warning" : "text-destructive"}>● {paused ? "paused" : conn}</span>
      ) : null}
    </header>
  );
}

/** Token counter: 115116300 → "115.1M", 15342 → "15.3k", 742 → "742". */
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(1)}k`;
  return String(n);
}

export function StatusBar({
  view,
  conn,
  onTogglePause,
  crumbs,
}: {
  view: StateView;
  conn: ConnState;
  onTogglePause: () => void;
  crumbs: ReactNode;
}) {
  const { canWrite } = useRole();
  return (
    <StatusBarShell
      conn={conn}
      paused={view.paused}
      crumbs={crumbs}
      stats={<RunStats view={view} />}
      actions={
        canWrite ? (
          <Button type="button" variant="secondary" size="xs" onClick={onTogglePause}>
            {view.paused ? <><Play /> resume</> : <><Pause /> pause</>}
          </Button>
        ) : null
      }
      exportMenu={<DownloadMenu id={view.id} canWrite={canWrite} />}
    />
  );
}

/** The run's numeric metrics as a compact inline status line — phase/progress/findings/attention first,
    so truncation at narrow widths drops only the least important numbers. Each item carries a tooltip. */
export function RunStats({ view }: { view: StateView }) {
  const c = view.coverage;
  // Ledger-honest counts: a conclusive claim with no check records is "claimed", not tested; a
  // clean screen whose ledger still holds gaps/unfulfilled plans counts under unverified.
  let tested = 0;
  let unverified = 0;
  let claimed = 0;
  for (const h of screenHonestyMap(view).values()) {
    if (h.status === "clean" || h.status === "finding" || h.status === "suspected") tested += 1;
    else if (h.status === "unverified") unverified += 1;
    else if (h.status === "unknown-records") claimed += 1;
  }
  const pending = view.handoffs.filter((h) => h.status === "pending").length;
  const items: { label: string; value: ReactNode; title?: string; warn?: boolean }[] = [
    { label: "phase", value: view.phase },
    { label: "tested", value: `${tested}/${c.total}`, title: "Screens whose diagnosis finished WITH recorded check executions; excludes omitted screens" },
    { label: "findings", value: view.findings.length, warn: view.findings.length > 0 },
    { label: "unfinished", value: c.remaining, title: "Queued, in progress, blocked, or failed; diagnosis is not complete", warn: c.remaining > 0 },
    { label: "unverified", value: unverified, title: "Screens whose diagnosis ended inconclusive — check-execution gaps or unfulfilled plans remain", warn: unverified > 0 },
    { label: "claimed", value: claimed, title: "Screens marked conclusive with no check records — a legacy/log claim, detail unknown" },
    { label: "screens", value: c.total },
    { label: "excluded", value: c.byStatus.excluded, title: "Screens omitted from diagnosis", warn: c.byStatus.excluded > 0 },
    { label: "tokens", value: fmtTokens(view.budget.tokensUsed) },
    { label: "handoffs", value: pending, warn: pending > 0 },
  ];
  return (
    <div className="flex min-w-0 items-center gap-x-3 overflow-hidden text-xs whitespace-nowrap" aria-label="Run metrics">
      {items.map((it) => (
        <span key={it.label} className="shrink-0" title={it.title}>
          <span className="text-muted-foreground">{it.label}</span>{" "}
          <span className={it.warn ? "font-medium text-warning" : "font-medium"}>{it.value}</span>
        </span>
      ))}
    </div>
  );
}
