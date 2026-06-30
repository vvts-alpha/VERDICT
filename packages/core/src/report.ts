// DESIGN §7.6 — 診断レポート(report.md)。対象情報 + スコープ + findings(重大度順・再現手順・
// リクエスト/レスポンス全文の証拠)。構造化モデル(report-model.ts)から markdown を描画。純粋。

import type { AssessmentState, Severity } from "./types/index.js";
import type { BuildReportOptions, ReportEvidence, ReportModel } from "./report-model.js";
import { buildReportModel } from "./report-model.js";

function evidenceMd(e: ReportEvidence): string[] {
  const out: string[] = [`- Evidence \`${e.evidenceId}\` — \`${e.path}\``];
  if (e.request) out.push("", "Request:", "", "```http", e.request.trimEnd(), "```");
  if (e.response) out.push("", `Response${e.truncated ? " (truncated)" : ""}:`, "", "```http", e.response.trimEnd(), "```");
  return out;
}

/** ReportModel → Markdown(report.md の本文)。 */
export function renderMarkdown(m: ReportModel): string {
  const out: string[] = [];
  out.push(`# ${m.brand} Security Assessment Report`, "");

  // confirmed(control+2replay)と suspected(異常1件のリード)を分離。headline は confirmed のみ。
  const confirmed = m.findings.filter((f) => f.verdict === "confirmed");
  const suspected = m.findings.filter((f) => f.verdict === "suspected");
  const tocRow = (f: ReportModel["findings"][number]): string =>
    // Markdown のリンク文字列に [] があると構文が壊れるので、severity の括弧は付けず title の [] も除去。
    `    - [${f.index}. ${f.severity.toUpperCase()} — ${f.title.replace(/[[\]]/g, "")}](#finding-${f.index})`;

  // ── 目次(レンダラ上でクリックすると各節へジャンプ) ──
  //    固定節は GFM 自動アンカー(#assessment-information 等)、finding は見出しに [SEV]・連番が入り
  //    スラッグが renderer 依存になるため明示アンカー <a id="finding-N"> に飛ばす。
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

  // ── 対象情報 ──
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

  // ── スコープ(整形) ──
  const s = m.scope;
  out.push("## Scope", "");
  out.push(`- **In-scope hosts**: ${s.inScopeHosts.length ? s.inScopeHosts.map((h) => `\`${h}\``).join(", ") : "—"}`);
  out.push(`- **Out-of-scope hosts**: ${s.outOfScopeHosts.length ? s.outOfScopeHosts.map((h) => `\`${h}\``).join(", ") : "—"}`);
  out.push(`- **In-scope paths**: ${s.inScopePathPrefixes.length ? s.inScopePathPrefixes.map((p) => `\`${p}\``).join(", ") : "—"}`);
  out.push(`- **Out-of-scope paths**: ${s.outOfScopePathPrefixes.length ? s.outOfScopePathPrefixes.map((p) => `\`${p}\``).join(", ") : "—"}`);
  out.push(`- **Rate**: ${s.rate.requestsPerMinute} req/min, max ${s.rate.maxConcurrent} concurrent`, "");

  // ── サマリ ──
  const summary = (Object.entries(m.stats.findings.bySeverity) as [Severity, number][])
    .filter(([, n]) => n > 0)
    .map(([sev, n]) => `${n} ${sev}`)
    .join(", ");
  out.push("## Summary", "", confirmed.length === 0 ? "_No confirmed findings._" : `${confirmed.length} finding(s): ${summary}`, "");
  if (suspected.length > 0)
    out.push(`_Plus ${suspected.length} suspected lead(s) needing manual verification — listed separately below, NOT counted above._`, "");

  // 1 件分を描画(confirmed / suspected 共通。suspected は見出しに [SUSPECTED] + anomaly を添える)。
  const renderFinding = (f: ReportModel["findings"][number]): void => {
    out.push(`<a id="finding-${f.index}"></a>`, ""); // 目次からの明示ジャンプ先(renderer 非依存)
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

  // ── confirmed findings(証拠は req/resp 全文) ──
  if (confirmed.length > 0) {
    out.push("## Findings", "");
    for (const f of confirmed) renderFinding(f);
  }

  // ── suspected(要手動確認。confirmed 集計には含めない) ──
  if (suspected.length > 0) {
    out.push("## Suspected (needs manual verification)", "");
    out.push("_Leads with one concrete observed anomaly but without control+2-replay confirmation. NOT counted in the confirmed total above — verify before relying on them._", "");
    for (const f of suspected) renderFinding(f);
  }

  return out.join("\n");
}

/** AssessmentState → report.md。opts.loadEvidence で証拠本文(req/resp)を取り込める。 */
export function buildReport(state: AssessmentState, now: Date = new Date(), opts: BuildReportOptions = {}): string {
  return renderMarkdown(buildReportModel(state, now, opts));
}
