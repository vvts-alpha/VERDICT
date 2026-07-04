// DESIGN §7.6 — assessment report (report.md). Target info + scope + findings (by severity, with repro steps
// and full-request/response evidence). Renders markdown from the structured model (report-model.ts). Pure.

import type { AssessmentState, Severity } from "./types/index.js";
import type { BuildReportOptions, ReportEvidence, ReportModel } from "./report-model.js";
import { buildReportModel } from "./report-model.js";

function evidenceMd(e: ReportEvidence): string[] {
  const out: string[] = [`- Evidence \`${e.evidenceId}\` — \`${e.path}\``];
  if (e.request) out.push("", "Request:", "", "```http", e.request.trimEnd(), "```");
  if (e.response) out.push("", `Response${e.truncated ? " (truncated)" : ""}:`, "", "```http", e.response.trimEnd(), "```");
  return out;
}

/** ReportModel → Markdown (the body of report.md). */
export function renderMarkdown(m: ReportModel): string {
  const out: string[] = [];
  out.push(`# ${m.brand} Security Assessment Report`, "");

  // Separate confirmed (control+2replay) from suspected (single-anomaly leads). Only confirmed are headlined.
  const confirmed = m.findings.filter((f) => f.verdict === "confirmed");
  const suspected = m.findings.filter((f) => f.verdict === "suspected");
  const tocRow = (f: ReportModel["findings"][number]): string =>
    // A [] in a Markdown link text breaks the syntax, so omit the parens around severity and strip [] from the title.
    `    - [${f.index}. ${f.severity.toUpperCase()} — ${f.title.replace(/[[\]]/g, "")}](#finding-${f.index})`;

  // ── Contents (clicking in the renderer jumps to each section) ──
  //    Fixed sections use GFM auto-anchors (#assessment-information etc.); findings carry [SEV] + a sequence number
  //    in the heading so the slug is renderer-dependent — jump to an explicit anchor <a id="finding-N"> instead.
  out.push("## Contents", "");
  out.push("- [Assessment Information](#assessment-information)");
  out.push("- [Scope](#scope)");
  out.push("- [Summary](#summary)");
  if (confirmed.length > 0) {
    out.push("- [Findings](#findings)");
    for (const f of confirmed) out.push(tocRow(f));
  }
  if (suspected.length > 0) {
    out.push("- [Suspected (needs manual verification)](#suspected-needs-manual-verification)");
    for (const f of suspected) out.push(tocRow(f));
  }
  out.push("");

  // ── Target info ──
  out.push("## Assessment Information", "");
  out.push(`| | |`, `|---|---|`);
  out.push(`| Assessment ID | \`${m.id}\` |`);
  out.push(`| Target | ${m.target} |`);
  out.push(`| Started | ${m.startedAt} |`);
  out.push(`| Generated | ${m.generatedAt} |`);
  out.push(`| Phase | ${m.phase} |`);
  out.push(`| Screens | ${m.stats.screens.total} mapped · ${m.stats.screens.scanned} scanned · ${m.stats.screens.remaining} remaining |`);
  out.push(`| Hypotheses | ${m.stats.hypotheses.total} (${m.stats.hypotheses.confirmed} confirmed) |`);
  out.push(`| Findings | ${m.stats.findings.total} |`);
  out.push(`| Tooling | ${m.brand} |`, "");

  // ── Scope (formatted) ──
  const s = m.scope;
  out.push("## Scope", "");
  out.push(`- **In-scope hosts**: ${s.inScopeHosts.length ? s.inScopeHosts.map((h) => `\`${h}\``).join(", ") : "—"}`);
  out.push(`- **Out-of-scope hosts**: ${s.outOfScopeHosts.length ? s.outOfScopeHosts.map((h) => `\`${h}\``).join(", ") : "—"}`);
  out.push(`- **In-scope paths**: ${s.inScopePathPrefixes.length ? s.inScopePathPrefixes.map((p) => `\`${p}\``).join(", ") : "—"}`);
  out.push(`- **Out-of-scope paths**: ${s.outOfScopePathPrefixes.length ? s.outOfScopePathPrefixes.map((p) => `\`${p}\``).join(", ") : "—"}`);
  out.push(`- **Rate**: ${s.rate.requestsPerMinute} req/min, max ${s.rate.maxConcurrent} concurrent`, "");

  // ── Summary ──
  const summary = (Object.entries(m.stats.findings.bySeverity) as [Severity, number][])
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `${n} ${sev}`)
    .join(", ");
  out.push("## Summary", "", confirmed.length === 0 ? "_No confirmed findings._" : `${confirmed.length} finding(s): ${summary}`, "");
  if (suspected.length > 0)
    out.push(`_Plus ${suspected.length} suspected lead(s) needing manual verification — listed separately below, NOT counted above._`, "");

  // Render one finding (shared by confirmed / suspected; suspected adds [SUSPECTED] + anomaly to the heading).
  const renderFinding = (f: ReportModel["findings"][number]): void => {
    out.push(`<a id="finding-${f.index}"></a>`, ""); // explicit jump target from the contents (renderer-independent)
    const mark = f.verdict === "suspected" ? "[SUSPECTED] " : "";
    out.push(`### ${f.index}. ${mark}[${f.severity.toUpperCase()}] ${f.title}`, "");
    out.push(`- Screen: \`${f.screenId ?? "(cross-screen)"}\``);
    out.push(`- Source: ${f.sourceKind === "validator" ? `validator \`${f.sourceName}\`` : `hypothesis \`${f.sourceName}\``}`);
    out.push(`- Scope basis: ${f.scopeBasis}`, "");
    if (f.anomaly) out.push(`**Anomaly (why this is a lead):** ${f.anomaly}`, "");
    out.push(f.description, "");
    out.push("**Reproduction**", "", "```", f.reproSteps, "```", "");
    out.push("**Evidence**", "");
    if (f.evidence.length === 0) out.push("_(none recorded)_", "");
    else for (const e of f.evidence) out.push(...evidenceMd(e), "");
  };

  // ── confirmed findings (evidence is full req/resp) ──
  if (confirmed.length > 0) {
    out.push("## Findings", "");
    for (const f of confirmed) renderFinding(f);
  }

  // ── suspected (needs manual verification; not included in the confirmed total) ──
  if (suspected.length > 0) {
    out.push("## Suspected (needs manual verification)", "");
    out.push("_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._", "");
    for (const f of suspected) renderFinding(f);
  }

  return out.join("\n");
}

/** AssessmentState → report.md. opts.loadEvidence can pull in evidence bodies (req/resp). */
export function buildReport(state: AssessmentState, now: Date = new Date(), opts: BuildReportOptions = {}): string {
  return renderMarkdown(buildReportModel(state, now, opts));
}
