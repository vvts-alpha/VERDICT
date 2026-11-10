import type { StateView } from "@veritas/core";
import { screenHonestyMap } from "./screen-status";
import { SeverityBadge } from "./SeverityBadge";
import { useT } from "../i18n";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { Card } from "./ui/card";

// Scenarios tab — a read-only projection of "what the agent intends to attack per screen, and how (the methodology plan)"
// and "the results of A04 cross-screen scenarios". Data source is events (📋 PLAN / ✓ coverage /
// 🧩 scenario stage notes) + findings. No schema change.
//
// Note: a PLAN note's body is truncated at 200 chars, so the plan is shown partially.

const PLAN_RE = /^📋 PLAN (s-\d+): \[([^\]]*)\]\s*([\s\S]*)$/;
const COV_RE = /^✓ (s-\d+) → (?:finding|clean) \[([^\]]*)\]/;
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

/** Projected core class rollups win over self-reported coverage notes. This selector never
 * interprets plan slots, failed attempts, or historical retries in the browser. */
export function scenarioCoverage(view: StateView): Map<string, Cov> {
  const covs = new Map<string, Cov>();
  for (const e of view.events) {
    if (e.type !== "note") continue;
    const r = COV_RE.exec(e.payload.message);
    if (!r) continue;
    covs.set(r[1]!, {
      verdict: "unknown-records", // note claims are breadcrumbs, never coverage verdicts
      entries: r[2]!
        .split(",")
        .map((x) => x.trim())
        .filter(Boolean)
        .map((x) => {
          const i = x.indexOf(":");
          return { cls: (i < 0 ? x : x.slice(0, i)).trim(), status: (i < 0 ? "" : x.slice(i + 1)).trim(), others: [], gaps: 0, unfulfilled: 0 };
        }),
      provenance: "note",
    });
  }
  // Even a lone http-request row displaces a "clean" note, but can never create a clean verdict.
  for (const sid of new Set(view.checkExecutions.map((row) => row.screenId))) {
    const summary = view.screenCheckSummaries?.[sid];
    const honesty = view.screenHonesty?.[sid];
    covs.set(sid, summary
      ? {
        verdict: honesty?.status ?? summary.verdict,
        entries: summary.classes.map((cell) => ({
          cls: cell.checkClass,
          status: cell.status,
          others: cell.outcomes.filter((o) => o.status !== cell.status),
          gaps: cell.gaps,
          unfulfilled: cell.unfulfilled,
        })),
        provenance: "ledger",
      }
      : { verdict: "unverified", entries: [], provenance: "ledger" }); // old server: do not trust note/guess a plan match
  }
  // A legacy note is useful as a plan breadcrumb, not an authoritative verdict.
  // Use the core projection or its fail-closed fallback when there are no ledger rows.
  const honesty = screenHonestyMap(view);
  const findingScreens = new Set(view.findings.map((f) => f.screenId));
  for (const [sid, cov] of covs) {
    if (cov.provenance !== "note") continue;
    const scan = honesty.get(sid);
    // Older servers lack the projection. A raw "finding" survives only with a
    // structured finding on this screen; the note itself cannot supply one.
    const verdict = !view.screenHonesty && scan?.raw === "finding" && findingScreens.has(sid)
      ? "finding" : scan?.status ?? "unknown-records";
    covs.set(sid, { ...cov, verdict });
  }
  return covs;
}

const ENTRY_CLS: Record<string, string> = {
  found: "border-destructive text-destructive",
  suspected: "border-warning text-warning",
  "tested-clean": "border-success text-success",
  unverified: "border-warning text-warning",
  blocked: "border-destructive/60 text-destructive",
};

export function Scenarios({ view, onJump }: { view: StateView; onJump: (screenId: string) => void }) {
  const t = useT();
  const plans = new Map<string, Plan>();
  const covs = scenarioCoverage(view);
  let focus = "";
  for (const e of view.events) {
    if (e.type !== "note") continue;
    const m = e.payload.message;
    let r: RegExpExecArray | null;
    if ((r = PLAN_RE.exec(m))) {
      plans.set(r[1]!, { screenId: r[1]!, classes: r[2]!.split(",").map((s) => s.trim()).filter(Boolean), plan: (r[3] ?? "").trim() });
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
      <h2 className="text-base font-semibold">{t("Scenarios")}</h2>
      {focus ? (
        <div className="rounded border border-success/40 bg-success/15 p-3 text-success" title={t("operator --focus, injected as the top priority of the scenario stage")}>
          {t("🎯 Operator focus:")} <b>{focus}</b>
        </div>
      ) : null}

      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t("Per-screen attack plans ({n})", { n: screenIds.length })}</h3>
      {screenIds.length === 0 ? (
        <p className="text-muted-foreground">{t("No plans yet — methodology runs after the survey maps the surface.")}</p>
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
                      title={c.provenance === "note" ? t("self-reported note — no structured check records; detail unknown") : t("derived from recorded check executions")}
                      className={c.provenance === "note" ? "text-muted-foreground" : c.verdict === "finding" ? "border-destructive text-destructive" : c.verdict === "clean" ? "border-success text-success" : c.verdict === "unverified" || c.verdict === "suspected" ? "border-warning text-warning" : "text-muted-foreground"}
                    >
                      {t(c.verdict)}{c.provenance === "note" ? t(" (note)") : ""}
                    </Badge>
                  ) : <Badge variant="outline">{t("planned")}</Badge>}
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
                          title={c.provenance === "note" ? t("self-reported note — no structured check records; detail unknown") : undefined}
                          className={c.provenance === "note" ? "text-muted-foreground" : (e.gaps > 0 || e.unfulfilled > 0) && e.status === "tested-clean" ? "border-warning text-warning" : (ENTRY_CLS[e.status] ?? "text-muted-foreground")}
                        >
                          {e.cls}{e.status ? `: ${t(e.status)}` : ""}{c.provenance === "note" ? t(" (note)") : ""}
                        </Badge>
                        {e.others.map((o) => {
                          const resolved = e.gaps === 0 && ["unverified", "blocked", "running"].includes(o.status);
                          return (
                            <Badge key={o.status} variant="outline"
                              title={resolved ? t("resolved historical attempt") : t("other recorded outcomes (including historical attempts)")}
                              className={resolved ? "text-muted-foreground" : (ENTRY_CLS[o.status] ?? "text-muted-foreground")}>
                              {resolved ? `${t("history")}: ` : ""}+{o.count} {t(o.status)}
                            </Badge>
                          );
                        })}
                        {e.gaps > 0 ? (
                          <Badge variant="outline" className="border-warning text-warning" title={t("unresolved check attempt(s)")}>
                            +{e.gaps} {t("gaps")}
                          </Badge>
                        ) : null}
                        {e.unfulfilled > 0 ? (
                          <Badge variant="outline" className="text-muted-foreground" title={t("plan slot(s) with no satisfying terminal execution")}>
                            +{e.unfulfilled} {t("plan")}
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

      <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t("A04 cross-screen scenarios ({n})", { n: scen.length })}</h3>
      {scen.length === 0 ? (
        <p className="text-muted-foreground">{t("No multi-step / cross-screen scenario findings (yet).")}</p>
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
