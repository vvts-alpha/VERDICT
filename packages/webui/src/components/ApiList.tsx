import type { StateView } from "@veritas/core";
import { Button } from "./ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

// Aggregate APIs across all screens (method+endpoint+auth → referencing screens). Tab for API-centric review.
export function ApiList({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const map = new Map<string, { method: string; url: string; auth: string; screens: string[] }>();
  for (const sc of view.screens) {
    for (const a of sc.apis) {
      const key = `${a.method} ${a.urlTemplate}`;
      const e = map.get(key) ?? { method: a.method, url: a.urlTemplate, auth: a.auth, screens: [] };
      if (!e.screens.includes(sc.screenId)) e.screens.push(sc.screenId);
      map.set(key, e);
    }
  }
  const rows = [...map.values()].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  if (rows.length === 0) {
    return <p className="p-4 text-muted-foreground">No APIs discovered yet.</p>;
  }
  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">APIs ({rows.length})</h2>
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>method</TableHead>
            <TableHead>endpoint</TableHead>
            <TableHead>auth</TableHead>
            <TableHead>screens</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => (
            <TableRow key={`${r.method} ${r.url}`}>
              <TableCell className="font-mono"><b>{r.method}</b></TableCell>
              <TableCell className="font-mono">{r.url}</TableCell>
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
