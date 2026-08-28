import type { StateView } from "@veritas/core";

// Analyzed first-party JS bundles (one row per script URL): endpoints mined, secrets flagged, source-map exposure.
// Tab for JS-centric review — also the record that lets the agent skip re-analyzing a bundle.
export function JsAssets({ view }: { view: StateView }) {
  const rows = [...view.jsAssets].sort((a, b) => (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  if (rows.length === 0) {
    return <p className="muted log-empty">No JS analyzed yet.</p>;
  }
  return (
    <section className="apitab">
      <h2>JS ({rows.length})</h2>
      <table className="kv apitable">
        <thead>
          <tr>
            <th>script</th>
            <th>size</th>
            <th>endpoints</th>
            <th>secrets</th>
            <th>DOM-XSS sinks</th>
            <th>map</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const sinks = r.sinksFound ?? [];
            const hot = sinks.filter((k) => k.confidence !== "low");
            return (
              <tr key={r.url}>
                <td className="mono">{r.url}</td>
                <td className="muted">{(r.bytes / 1024).toFixed(1)} KB</td>
                <td className="mono">{r.endpointsFound.length}</td>
                <td className={r.secretsFound.length > 0 ? "mono" : "muted"} title={r.secretsFound.map((s) => s.detail).join("\n")}>
                  {r.secretsFound.length === 0 ? "—" : r.secretsFound.map((s) => s.kind).join(", ")}
                </td>
                <td
                  className={hot.length > 0 ? "mono hasf" : sinks.length > 0 ? "mono" : "muted"}
                  title={sinks.map((k) => `${k.confidence.toUpperCase()} ${k.sink}${k.source ? ` ← ${k.source}` : ""}${k.routeHint ? `  (${k.routeHint})` : ""} — ${k.rationale}`).join("\n") || undefined}
                >
                  {sinks.length === 0 ? "—" : hot.length > 0 ? `${hot.length} candidate${hot.length > 1 ? "s" : ""}` : `${sinks.length} low`}
                </td>
                <td className={r.sourceMap ? "mono" : "muted"}>{r.sourceMap ? "yes" : "—"}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
