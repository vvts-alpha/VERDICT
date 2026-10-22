import { useState } from "react";
import type { MutationRow, StateView } from "@veritas/core";
import { useT } from "../i18n";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

const SENSITIVE = /pass|pwd|secret|token|answer|cred|repeat/i;

function ValueCell({ row }: { row: MutationRow }) {
  const [show, setShow] = useState(false);
  const sensitive = SENSITIVE.test(row.field);
  const masked = sensitive && !show;
  return (
    <TableCell className="font-mono">
      {masked ? (
        <button
          type="button"
          className="cursor-pointer rounded px-1 text-muted-foreground hover:bg-accent hover:text-foreground"
          title="click to reveal"
          onClick={() => setShow(true)}
        >
          ••••••
        </button>
      ) : (
        <span className="break-all">{row.value}</span>
      )}
    </TableCell>
  );
}

// Effective state VERDICT changed on the target — last write per (subject, field). Backed by the
// append-only mutation_recorded log; expand a row's evidence id to audit the write in artifacts.
export function Mutations({ view }: { view: StateView }) {
  const t = useT();
  const rows = view.mutations;
  if (rows.length === 0) {
    return <p className="p-4 text-muted-foreground">{t("No state changes recorded yet.")}</p>;
  }
  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">{t("State changes ({n})", { n: rows.length })}</h2>
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>{t("subject")}</TableHead>
            <TableHead>{t("field")}</TableHead>
            <TableHead>{t("current value")}</TableHead>
            <TableHead>{t("action")}</TableHead>
            <TableHead>{t("writes")}</TableHead>
            <TableHead>{t("evidence")}</TableHead>
            <TableHead>{t("at")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r, i) => (
            <TableRow key={`${r.subject}|${r.field}|${i}`}>
              <TableCell className="font-mono">{r.subject}</TableCell>
              <TableCell className="font-mono">{r.field}</TableCell>
              <ValueCell row={r} />
              <TableCell className="text-muted-foreground" title={r.url}>{r.action}</TableCell>
              <TableCell className="font-mono">{r.writes > 1 ? `×${r.writes}` : ""}</TableCell>
              <TableCell className="font-mono text-muted-foreground">{r.evidenceId ?? "—"}</TableCell>
              <TableCell className="text-muted-foreground">{r.at ? new Date(r.at).toLocaleTimeString() : "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}
