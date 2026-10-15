import type { StateView } from "@veritas/core";
import { SeverityBadge } from "./SeverityBadge";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card } from "./ui/card";

// Scenarios tab — a read-only projection of "what the agent intends to attack per screen, and how (the methodology plan)"
// and "the results of A04 cross-screen scenarios". Data source is events (📋 PLAN / ✓ coverage /
// 🧩 scenario stage notes) + findings. No schema change.
//
// Note: a PLAN note's body is truncated at 200 chars, so the plan is shown partially.

const PLAN_RE = /^📋 PLAN (s-\d+): \[([^\]]*)\]\s*([\s\S]*)$/;
const COV_RE = /^✓ (s-\d+) → (finding|clean) \[([^\]]*)\]/;
const FOCUS_RE = /^🧩 scenario stage: operator focus → ([\s\S]*)$/;

// A04 (cross-screen logic) categories — shown separately as the output of the scenario stage.
const A04 = new Set(["price-tampering", "qty-tampering", "workflow-bypass", "mass-assignment"]);

type Plan = { screenId: string; classes: string[]; plan: string };
type Cov = { verdict: string; entries: Array<{ cls: string; result: string }> };

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

  // Output of A04 cross-screen scenarios = findings in a scenario category, or with no screen (cross-screen).
  const scen = view.findings.filter((f) => {
    const cat = /^\[([^\]]+)\]/.exec(f.title)?.[1] ?? "";
    return A04.has(cat) || f.screenId == null;
  });

  return (
    <section className="space-y-4">
      <h2 className="text-base font-semibold">Scenarios</h2>
      {focus ? (
        <div className="rounded border border-success/40 bg-success/15 p-3 text-success" title="operator --focus, injected as the top priority of the scenario stage">
          🎯 Operator focus: <b>{focus}</b>
        </div>
      ) : null}

      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Per-screen attack plans ({screenIds.length})</h3>
      {screenIds.length === 0 ? (
        <p className="text-muted-foreground">No plans yet — methodology runs after the survey maps the surface.</p>
      ) : (
        <div className="flex flex-col gap-2">
          {screenIds.map((sid) => {
            const p = plans.get(sid);
            const c = covs.get(sid);
            return (
              <Card size="sm" key={sid} className="gap-2 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Button type="button" variant="link" size="xs" onClick={() => onJump(sid)}>{sid}</Button>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground">{urlOf.get(sid) ?? ""}</span>
                  {c ? <Badge variant="outline" className={c.verdict === "finding" ? "border-destructive text-destructive" : "border-success text-success"}>{c.verdict}</Badge> : <Badge variant="outline">planned</Badge>}
                </div>
                {p && p.classes.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {p.classes.map((cl) => <Badge key={cl} variant="secondary">{cl}</Badge>)}
                  </div>
                ) : null}
                {c && c.entries.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {c.entries.map((e) => (
                      <Badge key={e.cls} variant="outline" className={e.result === "found" ? "border-destructive text-destructive" : e.result === "tested-clean" ? "border-success text-success" : "text-muted-foreground"}>
                        {e.cls}{e.result ? `: ${e.result}` : ""}
                      </Badge>
                    ))}
                  </div>
                ) : null}
                {p?.plan ? <p className="whitespace-pre-wrap break-words text-xs">{p.plan}</p> : null}
              </Card>
            );
          })}
        </div>
      )}

      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">A04 cross-screen scenarios ({scen.length})</h3>
      {scen.length === 0 ? (
        <p className="text-muted-foreground">No multi-step / cross-screen scenario findings (yet).</p>
      ) : (
        <div className="flex flex-col gap-2">
          {scen.map((f) => {
            const cat = /^\[([^\]]+)\]/.exec(f.title)?.[1] ?? "scenario";
            return (
              <Card size="sm" key={f.id} className="gap-2 p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={f.severity} />
                  <Badge variant="secondary">{cat}</Badge>
                  <span className="flex-1">{f.title.replace(/^\[[^\]]+\]\s*/, "")}</span>
                  {f.screenId ? <Button type="button" variant="link" size="xs" onClick={() => onJump(f.screenId!)}>{f.screenId}</Button> : null}
                </div>
                <p className="whitespace-pre-wrap">{f.description}</p>
              </Card>
            );
          })}
        </div>
      )}
    </section>
  );
}
