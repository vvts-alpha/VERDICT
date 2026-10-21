import type { StateView } from "@veritas/core";
import { useT } from "../i18n";
import { Button } from "./ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

// Aggregate APIs across all screens (method+endpoint+operation+auth → referencing screens). Tab for API-centric review.
// GraphQL: one endpoint carries many operations — they are DISTINCT rows keyed by operationKey, shown as the op name.
export function ApiList({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const t = useT();
  const map = new Map<string, { k: string; method: string; url: string; op?: string; opType?: string; auth: string; screens: string[] }>();
  for (const sc of view.screens) {
    for (const a of sc.apis) {
      const g = a.graphql;
      const key = g ? `${a.method} ${a.urlTemplate} ${g.operationKey}` : `${a.method} ${a.urlTemplate}`;
      const e = map.get(key) ?? { k: key, method: a.method, url: a.urlTemplate, auth: a.auth, screens: [] };
      if (g) {
        e.op = g.operationName ?? g.rootFields.join(",") ?? g.operationKey;
        e.opType = g.operationType;
      }
      if (!e.screens.includes(sc.screenId)) e.screens.push(sc.screenId);
      map.set(key, e);
    }
  }
  const rows = [...map.values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  if (rows.length === 0) {
    return <p className="p-4 text-muted-foreground">{t("No APIs discovered yet.")}</p>;
  }
  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">{t("APIs ({n})", { n: rows.length })}</h2>
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>{t("method")}</TableHead>
            <TableHead>{t("endpoint")}</TableHead>
            <TableHead>{t("operation")}</TableHead>
            <TableHead>{t("auth")}</TableHead>
            <TableHead>{t("screens")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={r.k}>
              <TableCell className="font-mono"><b>{r.method}</b></TableCell>
              <TableCell className="font-mono">{r.url}</TableCell>
              <TableCell className="font-mono text-muted-foreground">{r.op ? `${r.opType === "mutation" ? "mut" : r.opType === "subscription" ? "sub" : "qry"}:${r.op}` : "—"}</TableCell>
              <TableCell className="text-muted-foreground">{r.auth}</TableCell>
              <TableCell>
                {r.screens.map((s) => <Button key={s} type="button" variant="link" size="xs" onClick={() => onJump(s)}>{s}</Button>)}
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </section>
  );
}
