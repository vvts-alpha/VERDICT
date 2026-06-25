import type { StateView } from "@veritas/core";

// 作戦 / Scenarios タブ — エージェントが「画面ごとに何を、どう攻めるつもりか(methodology の作戦)」と
// 「A04 横断シナリオの結果」を read-only で projection する。データ源は events(📋 PLAN / ✓ coverage /
// 🧩 scenario stage の note)+ findings。スキーマ変更なし。
//
// 注: PLAN の note は本文 200 字で切られているので plan は部分表示。

const PLAN_RE = /^📋 PLAN (s-\d+): \[([^\]]*)\]\s*([\s\S]*)$/;
const COV_RE = /^✓ (s-\d+) → (finding|clean) \[([^\]]*)\]/;
const FOCUS_RE = /^🧩 scenario stage: operator focus → ([\s\S]*)$/;

// A04(横断ロジック)系カテゴリ — scenario 段の成果として別枠表示する。
const A04 = new Set(["price-tampering", "qty-tampering", "workflow-bypass", "mass-assignment"]);

type Plan = { screenId: string; classes: string[]; plan: string };
type Cov = { verdict: string; entries: Array<{ cls: string; result: string }> };

function covClass(result: string): string {
  if (result === "found") return "cov-found";
  if (result === "tested-clean") return "cov-clean";
  if (result.startsWith("not-applicable")) return "cov-na";
  return "cov-other";
}

export function Scenarios({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const plans = new Map<string, Plan>();
  const covs = new Map<string, Cov>();
  let focus = "";
  for (const e of view.events) {
    if (e.type !== "note") continue;
    const m = e.payload.message;
    let r: RegExpExecArray | null;
    if ((r = PLAN_RE.exec(m))) {
      plans.set(r[1]!, { screenId: r[1]!, classes: r[2]!.split(",").map((s) => s.trim()).filter(Boolean), plan: (r[3] ?? "").trim() });
    } else if ((r = COV_RE.exec(m))) {
      covs.set(r[1]!, {
        verdict: r[2]!,
        entries: r[3]!
          .split(",")
          .map((x) => x.trim())
          .filter(Boolean)
          .map((x) => {
            const i = x.indexOf(":");
            return { cls: (i < 0 ? x : x.slice(0, i)).trim(), result: (i < 0 ? "" : x.slice(i + 1)).trim() };
          }),
      });
    } else if ((r = FOCUS_RE.exec(m))) {
      focus = r[1]!.trim();
    }
  }

  const urlOf = new Map(view.screens.map((s) => [s.screenId, s.urlTemplate]));
  const screenIds = [...new Set([...plans.keys(), ...covs.keys()])].sort();

  // A04 横断シナリオの成果 = scenario カテゴリ or 画面なし(cross-screen)の finding。
  const scen = view.findings.filter((f) => {
    const cat = /^\[([^\]]+)\]/.exec(f.title)?.[1] ?? "";
    return A04.has(cat) || f.screenId == null;
  });

  return (
    <section className="scenarios-tab">
      <h2>Scenarios / 作戦</h2>
      {focus ? (
        <div className="focus-banner" title="operator --focus, injected as the top priority of the scenario stage">
          🎯 Operator focus: <b>{focus}</b>
        </div>
      ) : null}

      <h3>Per-screen attack plans ({screenIds.length})</h3>
      {screenIds.length === 0 ? (
        <p className="muted">No plans yet — methodology runs after the survey maps the surface.</p>
      ) : (
        <div className="plan-list">
          {screenIds.map((sid) => {
            const p = plans.get(sid);
            const c = covs.get(sid);
            return (
              <div key={sid} className="plan-card">
                <div className="plan-head">
                  <button type="button" className="screenlink" onClick={() => onJump(sid)}>
                    {sid}
                  </button>
                  <span className="plan-url">{urlOf.get(sid) ?? ""}</span>
                  {c ? <span className={`verdict v-${c.verdict}`}>{c.verdict}</span> : <span className="verdict v-pending">planned</span>}
                </div>
                {p && p.classes.length > 0 ? (
                  <div className="plan-classes">
                    {p.classes.map((cl) => (
                      <span key={cl} className="cls-chip">
                        {cl}
                      </span>
                    ))}
                  </div>
                ) : null}
                {c && c.entries.length > 0 ? (
                  <div className="cov-row">
                    {c.entries.map((e) => (
                      <span key={e.cls} className={`cov-chip ${covClass(e.result)}`}>
                        {e.cls}
                        {e.result ? `: ${e.result}` : ""}
                      </span>
                    ))}
                  </div>
                ) : null}
                {p?.plan ? <p className="plan-text">{p.plan}</p> : null}
              </div>
            );
          })}
        </div>
      )}

      <h3>A04 cross-screen scenarios ({scen.length})</h3>
      {scen.length === 0 ? (
        <p className="muted">No multi-step / cross-screen scenario findings (yet).</p>
      ) : (
        <div className="scen-list">
          {scen.map((f) => {
            const cat = /^\[([^\]]+)\]/.exec(f.title)?.[1] ?? "scenario";
            return (
              <div key={f.id} className="scen-card">
                <div className="scen-head">
                  <span className={`sevpill sev-${f.severity}`}>{f.severity}</span>
                  <span className="cls-chip">{cat}</span>
                  <span className="scen-title">{f.title.replace(/^\[[^\]]+\]\s*/, "")}</span>
                  {f.screenId ? (
                    <button type="button" className="screenlink" onClick={() => onJump(f.screenId!)}>
                      {f.screenId}
                    </button>
                  ) : null}
                </div>
                <p className="finding-desc">{f.description}</p>
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
