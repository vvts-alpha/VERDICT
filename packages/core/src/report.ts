// DESIGN §7.6 — findings レポート(report.md)。重大度順 + 再現手順 + 証拠 + スコープ根拠。純粋。

import type { AssessmentState, Severity } from "./types/index.js";
import { coverage } from "./coverage.js";

const SEVERITY_ORDER: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function buildReport(state: AssessmentState, now: Date = new Date()): string {
  const cov = coverage(state);
  const findings = [...state.findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  const target = state.target.kind === "single_url" ? state.target.url : `scope_manifest ${state.target.path}`;
  const confirmedHypotheses = state.hypotheses.filter((h) => h.status === "confirmed").length;

  const out: string[] = [];
  out.push(`# Umbra Hands Assessment Report — \`${state.id}\``, "");
  out.push(`- **Target**: ${target}`);
  out.push(`- **Phase**: ${state.phase}`);
  out.push(`- **Screens**: ${cov.total} (scanned ${cov.terminal}, remaining ${cov.remaining})`);
  out.push(`- **Hypotheses**: ${state.hypotheses.length} (confirmed ${confirmedHypotheses})`);
  out.push(`- **Findings**: ${state.findings.length}`);
  out.push(`- **Generated**: ${now.toISOString()}`, "");

  const bySeverity = findings.reduce<Record<string, number>>((m, f) => {
    m[f.severity] = (m[f.severity] ?? 0) + 1;
    return m;
  }, {});
  const summary = Object.entries(bySeverity)
    .map(([s, n]) => `${n} ${s}`)
    .join(", ");
  out.push("## Summary", "", findings.length === 0 ? "_No confirmed findings._" : `${findings.length} finding(s): ${summary}`, "");

  if (findings.length > 0) {
    out.push("## Findings", "");
    findings.forEach((f, idx) => {
      out.push(`### ${idx + 1}. [${f.severity.toUpperCase()}] ${f.title}`, "");
      out.push(`- Screen: \`${f.screenId ?? "(cross-screen)"}\``);
      out.push(
        `- Source: ${f.source.kind === "validator" ? `validator \`${f.source.validatorName}\`` : `hypothesis \`${f.source.hypothesisId}\``}`,
      );
      out.push(`- Scope basis: ${f.scopeBasis}`, "");
      out.push(f.description, "");
      out.push("**Reproduction**", "", "```", f.reproSteps, "```", "");
      const evidence = f.evidenceIds.length
        ? f.evidenceIds.map((e) => `\`artifacts/${f.screenId ?? "_"}/${e}/\``).join(", ")
        : "—";
      out.push(`**Evidence**: ${evidence}`, "");
    });
  }

  out.push("## Scope", "", "```json", JSON.stringify(state.scope, null, 2), "```", "");
  return out.join("\n");
}
