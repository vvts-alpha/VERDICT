import type { StateView } from "@veritas/core";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "./ui/table";

// Analyzed first-party JS bundles (one row per script URL): endpoints mined, secrets flagged, source-map exposure.
// Tab for JS-centric review — also the record that lets the agent skip re-analyzing a bundle.
export function JsAssets({ view }: { view: StateView }) {
  const rows = [...view.jsAssets].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  if (rows.length === 0) {
    return <p className="p-4 text-muted-foreground">No JS analyzed yet.</p>;
  }
  return (
    <section>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-primary">JS ({rows.length})</h2>
      <Table className="text-xs">
        <TableHeader>
          <TableRow>
            <TableHead>script</TableHead>
            <TableHead>size</TableHead>
            <TableHead>endpoints</TableHead>
            <TableHead>secrets</TableHead>
            <TableHead>DOM-XSS sinks</TableHead>
            <TableHead>map</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((r) => {
            const sinks = r.sinksFound ?? [];
            const hot = sinks.filter((k) => k.confidence !== "low");
            return (
              <TableRow key={r.url}>
                <TableCell className="font-mono">{r.url}</TableCell>
                <TableCell className="text-muted-foreground">{(r.bytes / 1024).toFixed(1)} KB</TableCell>
                <TableCell className="font-mono">{r.endpointsFound.length}</TableCell>
                <TableCell className={r.secretsFound.length > 0 ? "font-mono" : "text-muted-foreground"} title={r.secretsFound.map((s) => s.detail).join("\n")}>
                  {r.secretsFound.length === 0 ? "—" : r.secretsFound.map((s) => s.kind).join(", ")}
                </TableCell>
                <TableCell className={hot.length > 0 ? "font-mono text-warning" : sinks.length > 0 ? "font-mono" : "text-muted-foreground"} title={sinks.map((k) => `${k.confidence.toUpperCase()} ${k.sink}${k.source ? ` ← ${k.source}` : ""}${k.routeHint ? `  (${k.routeHint})` : ""} — ${k.rationale}`).join("\n") || undefined}>
                  {sinks.length === 0 ? "—" : hot.length > 0 ? `${hot.length} candidate${hot.length > 1 ? "s" : ""}` : `${sinks.length} low`}
                </TableCell>
                <TableCell className={r.sourceMap ? "font-mono" : "text-muted-foreground"}>{r.sourceMap ? "yes" : "—"}</TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </section>
  );
}
