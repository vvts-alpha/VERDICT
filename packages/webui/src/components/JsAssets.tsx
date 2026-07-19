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
            <th>map</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.url}>
              <td className="mono">{r.url}</td>
              <td className="muted">{(r.bytes / 1024).toFixed(1)} KB</td>
              <td className="mono">{r.endpointsFound.length}</td>
              <td className={r.secretsFound.length > 0 ? "mono" : "muted"} title={r.secretsFound.map((s) => s.detail).join("\n")}>
                {r.secretsFound.length === 0 ? "—" : r.secretsFound.map((s) => s.kind).join(", ")}
              </td>
              <td className={r.sourceMap ? "mono" : "muted"}>{r.sourceMap ? "yes" : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
