import { useRef, useState } from "react";
import type { ReactNode } from "react";
import type { StateView } from "@veritas/core";
import type { ConnState } from "../api";
import { signOut, useRole } from "../api";
import { useT } from "../i18n";
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
  const t = useT();
  const fileRef = useRef<HTMLInputElement>(null);
  const [status, setStatus] = useState<string>("");
  async function onPick(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = ""; // reset so the same file can be picked again in a row
    if (!file) return;
    setStatus(t("⏳ importing {name}…", { name: file.name }));
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
      setStatus(t("✓ importing — net-new findings appear, High+ get AI re-verified"));
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
  const t = useT();
  const rep = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/report?format=${f}`;
  return (
    <>
      <DropdownMenuLabel>{t("Report")}</DropdownMenuLabel>
      <DropdownMenuItem asChild><a href={rep("html")} download={`${id}-report.html`}>HTML</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("pdf")} download={`${id}-report.pdf`}>PDF</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("md")}>Markdown</a></DropdownMenuItem>
      <DropdownMenuItem asChild><a href={rep("csv")}>{t("Findings CSV")}</a></DropdownMenuItem>
    </>
  );
}

// Download the report / screen inventory. These are GET endpoints, so cookies are sent automatically.
// Reports download as attachments; the inventory HTML keeps its separate preview.
function DownloadMenu({ id, canWrite }: { id: string; canWrite: boolean }) {
  const t = useT();
  const inv = (f: string): string => `/api/assessments/${encodeURIComponent(id)}/inventory?format=${f}`;
  const burp = useBurpImport(id);
  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button type="button" variant="outline" size="xs"><Download /> {canWrite ? t("Export / Import") : t("Export")}</Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="min-w-44">
          <ReportLinks id={id} />
          <DropdownMenuSeparator />
          <DropdownMenuLabel>{t("Screen inventory")}</DropdownMenuLabel>
          <DropdownMenuItem asChild><a href={inv("html")} target="_blank" rel="noreferrer">{t("Inventory HTML")}</a></DropdownMenuItem>
          <DropdownMenuItem asChild><a href={inv("csv")}>{t("Screens CSV")}</a></DropdownMenuItem>
          {canWrite ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuLabel>{t("Import")}</DropdownMenuLabel>
              <DropdownMenuItem onSelect={() => burp.fileRef.current?.click()}><Upload /> {t("Burp XML report")}</DropdownMenuItem>
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
  const t = useT();
  const roleTitle = multiUser
    ? `${user?.username ?? t("account")} — ${role === "admin" ? t("administrator") : t("user")}`
    : canWrite
      ? t("operator — full access")
      : t("viewer — read-only");
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
          <button type="button" className="text-xs text-muted-foreground hover:text-foreground" onClick={() => void signOut(true)} title={t("sign out")}>
            {t("sign out")}
          </button>
        ) : (
          <a className="text-xs text-muted-foreground hover:text-foreground" href="/logout" title={t("sign out")}>
            {t("sign out")}
          </a>
        )
      ) : null}
      {conn ? (
        <span className={conn === "open" ? "text-success" : conn === "connecting" ? "text-warning" : "text-destructive"}>
          ● {paused ? t("paused") : conn === "open" ? t("open") : conn === "connecting" ? t("connecting") : t("closed")}
        </span>
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
  const t = useT();
  return (
    <StatusBarShell
      conn={conn}
      paused={view.paused}
      crumbs={crumbs}
      stats={<RunStats view={view} />}
      actions={
        canWrite ? (
          <Button type="button" variant="secondary" size="xs" onClick={onTogglePause}>
            {view.paused ? <><Play /> {t("resume")}</> : <><Pause /> {t("pause")}</>}
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
  const t = useT();
  const c = view.coverage;
  // Ledger-honest counts: "tested" = diagnosis executed (any outcome — clean, found, or inconclusive);
  // a conclusive claim with no check records is "claimed", not tested; the unverified subset stays
  // visible as its own metric so inconclusive work can't masquerade as verdicted coverage.
  let tested = 0;
  let unverified = 0;
  let claimed = 0;
  for (const h of screenHonestyMap(view).values()) {
    if (h.status === "clean" || h.status === "finding" || h.status === "suspected" || h.status === "unverified") tested += 1;
    if (h.status === "unverified") unverified += 1;
    else if (h.status === "unknown-records") claimed += 1;
  }
  const pending = view.handoffs.filter((h) => h.status === "pending").length;
  const items: { label: string; value: ReactNode; title?: string; warn?: boolean }[] = [
    { label: t("phase"), value: view.phase },
    { label: t("tested"), value: `${tested}/${c.total}`, title: t("Screens whose diagnosis ran to completion — recorded check executions, any outcome (clean / found / inconclusive); excludes omitted screens") },
    { label: t("findings"), value: view.findings.length, warn: view.findings.length > 0 },
    { label: t("unfinished"), value: c.remaining, title: t("Queued, in progress, blocked, or failed; diagnosis is not complete"), warn: c.remaining > 0 },
    { label: t("unverified"), value: unverified, title: t("Tested screens whose checks ended inconclusive — check-execution gaps or unfulfilled plans remain"), warn: unverified > 0 },
    { label: t("claimed"), value: claimed, title: t("Screens marked conclusive with no check records — a legacy/log claim, detail unknown") },
    { label: t("screens"), value: c.total },
    { label: t("excluded"), value: c.byStatus.excluded, title: t("Screens omitted from diagnosis"), warn: c.byStatus.excluded > 0 },
    { label: t("tokens"), value: fmtTokens(view.budget.tokensUsed) },
    { label: t("handoffs"), value: pending, warn: pending > 0 },
  ];
  return (
    <div className="flex min-w-0 items-center gap-x-3 overflow-hidden text-xs whitespace-nowrap" aria-label={t("Run metrics")}>
      {items.map((it) => (
        <span key={it.label} className="shrink-0" title={it.title}>
          <span className="text-muted-foreground">{it.label}</span>{" "}
          <span className={it.warn ? "font-medium text-warning" : "font-medium"}>{it.value}</span>
        </span>
      ))}
    </div>
  );
}
