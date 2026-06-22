// DESIGN §7.6 — findings レポート(report.md)。重大度順 + 再現手順 + 証拠 + スコープ根拠。純粋。
// 構造化モデル(report-model.ts)を markdown に描画する。buildReport は後方互換のラッパ。

import type { AssessmentState, Severity } from "./types/index.js";
import type { ReportModel } from "./report-model.js";
import { buildReportModel } from "./report-model.js";

/** ReportModel → Markdown(report.md の本文)。 */
export function renderMarkdown(m: ReportModel): string {
  const out: string[] = [];
  out.push(`# ${m.brand} Assessment Report — \`${m.id}\``, "");
  out.push(`- **Target**: ${m.target}`);
  out.push(`- **Phase**: ${m.phase}`);
  out.push(`- **Screens**: ${m.stats.screens.total} (scanned ${m.stats.screens.scanned}, remaining ${m.stats.screens.remaining})`);
  out.push(`- **Hypotheses**: ${m.stats.hypotheses.total} (confirmed ${m.stats.hypotheses.confirmed})`);
  out.push(`- **Findings**: ${m.stats.findings.total}`);
  out.push(`- **Generated**: ${m.generatedAt}`, "");

  const summary = (Object.entries(m.stats.findings.bySeverity) as [Severity, number][])
    .filter(([, n]) => n > 0)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
  out.push("## Summary", "", m.findings.length === 0 ? "_No confirmed findings._" : `${m.findings.length} finding(s): ${summary}`, "");

  if (m.findings.length > 0) {
    out.push("## Findings", "");
    for (const f of m.findings) {
      out.push(`### ${f.index}. [${f.severity.toUpperCase()}] ${f.title}`, "");
      out.push(`- Screen: \`${f.screenId ?? "(cross-screen)"}\``);
      out.push(`- Source: ${f.sourceKind === "validator" ? `validator \`${f.sourceName}\`` : `hypothesis \`${f.sourceName}\``}`);
      out.push(`- Scope basis: ${f.scopeBasis}`, "");
      out.push(f.description, "");
      out.push("**Reproduction**", "", "```", f.reproSteps, "```", "");
      const evidence = f.evidencePaths.length ? f.evidencePaths.map((p) => `\`${p}\``).join(", ") : "—";
      out.push(`**Evidence**: ${evidence}`, "");
    }
  }

  out.push("## Scope", "", "```json", JSON.stringify(m.scope, null, 2), "```", "");
  return out.join("\n");
}

/** AssessmentState → report.md(後方互換)。 */
export function buildReport(state: AssessmentState, now: Date = new Date()): string {
  return renderMarkdown(buildReportModel(state, now));
}
