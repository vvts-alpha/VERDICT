import type { CheckExecution, StateView } from "@veritas/core";
import { planSatisfied } from "./screen-status";
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
type Entry = {
  cls: string;
  /** Dominant outcome status for the class (plan slots never claim a class). */
  status: string;
  /** Other outcome statuses present — multiplicity stays visible (found + unverified ≠ found). */
  others: Array<{ status: string; count: number }>;
  /** Outcome rows that ended without a conclusion (unverified / blocked / still running). */
  gaps: number;
  /** Plan slots with no satisfying terminal execution. */
  unfulfilled: number;
};
type Cov = { verdict: string; entries: Entry[]; provenance: "ledger" | "note" };

// Dominant-status precedence for a per-class rollup — a real hole outranks a clean run, and a gap
// (unverified/blocked) outranks "tested-clean" so incomplete checks never read as verified coverage.
const CHECK_RANK: Record<string, number> = {
  found: 7, suspected: 6, unverified: 5, blocked: 4,
  "tested-clean": 3, "not-applicable": 2, planned: 1, running: 0,
};

/** Per-screen coverage derived from the structured check ledger (the source of truth). Any recorded
 *  ledger row — even an unattributed one — suppresses the ✓ note's verdict: rows exist but no class
 *  verdict reads "unverified", never the note's self-reported clean. Per-class chips preserve
 *  outcome multiplicity: a found plus an unverified on the same class shows BOTH, and a
 *  tested-clean plus an unsatisfied plan slot can never read as fully clean. */
function ledgerCoverage(rows: CheckExecution[]): Cov {
  const byClass = new Map<string, CheckExecution[]>();
  for (const r of rows) {
    if (r.checkClass === "http-request") continue; // unattributed raw requests cover nothing
    const arr = byClass.get(r.checkClass) ?? [];
    arr.push(r);
    byClass.set(r.checkClass, arr);
  }
  if (byClass.size === 0) return { verdict: "unverified", entries: [], provenance: "ledger" };
  const cells = [...byClass.entries()].map(([cls, rs]) => {
    const plans = rs.filter((r) => r.status === "planned");
    const execs = rs.filter((r) => r.status !== "planned");
    const counts = new Map<string, number>();
    for (const e of execs) counts.set(e.status, (counts.get(e.status) ?? 0) + 1);
    const dominant = execs.length
      ? execs.reduce((a, b) => ((CHECK_RANK[b.status] ?? 0) > (CHECK_RANK[a.status] ?? 0) ? b : a)).status
      : "planned";
    counts.delete(dominant);
    return {
      cls,
      status: dominant,
      ran: execs.length,
      gaps: execs.filter((e) => e.status === "unverified" || e.status === "blocked" || e.status === "running").length,
      unfulfilled: plans.filter((p) => !execs.some((e) => planSatisfied(p, e))).length,
      others: [...counts.entries()].map(([status, count]) => ({ status, count })),
    };
  });
  const dominant = cells.reduce((a, b) => ((CHECK_RANK[b.status] ?? 0) > (CHECK_RANK[a.status] ?? 0) ? b : a)).status;
  const ran = cells.reduce((n, c) => n + c.ran, 0);
  const gaps = cells.reduce((n, c) => n + c.gaps, 0);
  const unfulfilled = cells.reduce((n, c) => n + c.unfulfilled, 0);
  const verdict =
    dominant === "found" ? "finding"
      : dominant === "suspected" ? "suspected"
        : gaps > 0 ? "unverified"
          : unfulfilled > 0 ? (ran > 0 ? "unverified" : "planned")
            : ran === 0 ? "planned"
              : "clean";
  return { verdict, entries: cells, provenance: "ledger" };
}

const ENTRY_CLS: Record<string, string> = {
  found: "border-destructive text-destructive",
  suspected: "border-warning text-warning",
  "tested-clean": "border-success text-success",
  unverified: "border-warning text-warning",
  blocked: "border-destructive/60 text-destructive",
};

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
            return { cls: (i < 0 ? x : x.slice(0, i)).trim(), status: (i < 0 ? "" : x.slice(i + 1)).trim(), others: [], gaps: 0, unfulfilled: 0 };
          }),
        provenance: "note",
      });
    } else if ((r = FOCUS_RE.exec(m))) {
      focus = r[1]!.trim();
    }
  }

  // Structured ledger wins over the ✓ note: a self-reported "tested-clean" note must never override
  // real check executions (it can claim clean while the ledger still shows unverified/blocked gaps).
  const ledgerByScreen = new Map<string, CheckExecution[]>();
  for (const c of view.checkExecutions) {
    const arr = ledgerByScreen.get(c.screenId) ?? [];
    arr.push(c);
    ledgerByScreen.set(c.screenId, arr);
  }
  for (const [sid, rows] of ledgerByScreen) covs.set(sid, ledgerCoverage(rows)); // ledger-derived coverage replaces any note-derived claim

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
                  {c ? (
                    <Badge
                      variant="outline"
                      title={c.provenance === "note" ? "self-reported note — no structured check records; detail unknown" : "derived from recorded check executions"}
                      className={c.provenance === "note" ? "text-muted-foreground" : c.verdict === "finding" ? "border-destructive text-destructive" : c.verdict === "clean" ? "border-success text-success" : c.verdict === "unverified" || c.verdict === "suspected" ? "border-warning text-warning" : "text-muted-foreground"}
                    >
                      {c.verdict}{c.provenance === "note" ? " (note)" : ""}
                    </Badge>
                  ) : <Badge variant="outline">planned</Badge>}
                </div>
                {p && p.classes.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {p.classes.map((cl) => <Badge key={cl} variant="secondary">{cl}</Badge>)}
                  </div>
                ) : null}
                {c && c.entries.length > 0 ? (
                  <div className="flex flex-wrap gap-1">
                    {c.entries.map((e) => (
                      <span key={e.cls} className="inline-flex flex-wrap gap-1">
                        <Badge
                          variant="outline"
                          title={c.provenance === "note" ? "self-reported note — no structured check records; detail unknown" : undefined}
                          className={c.provenance === "note" ? "text-muted-foreground" : (ENTRY_CLS[e.status] ?? "text-muted-foreground")}
                        >
                          {e.cls}{e.status ? `: ${e.status}` : ""}{c.provenance === "note" ? " (note)" : ""}
                        </Badge>
                        {e.others.map((o) => (
                          <Badge key={o.status} variant="outline" className={ENTRY_CLS[o.status] ?? "text-muted-foreground"}>
                            +{o.count} {o.status}
                          </Badge>
                        ))}
                        {e.unfulfilled > 0 ? (
                          <Badge variant="outline" className="text-muted-foreground" title="plan slot(s) with no satisfying terminal execution">
                            +{e.unfulfilled} plan
                          </Badge>
                        ) : null}
                      </span>
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
