import type { StateView } from "@veritas/core";

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
    return <p className="muted log-empty">No APIs discovered yet.</p>;
  }
  return (
    <section className="apitab">
      <h2>APIs ({rows.length})</h2>
      <table className="kv apitable">
        <thead>
          <tr>
            <th>method</th>
            <th>endpoint</th>
            <th>auth</th>
            <th>screens</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={`${r.method} ${r.url}`}>
              <td className="mono">
                <b>{r.method}</b>
              </td>
              <td className="mono">{r.url}</td>
              <td className="muted">{r.auth}</td>
              <td>
                {r.screens.map((s) => (
                  <button key={s} type="button" className="screenlink" onClick={() => onJump(s)}>
                    {s}
                  </button>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
