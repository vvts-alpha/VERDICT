// レポートの純粋レンダラ: HTML(自己完結) / CSV(findings・screens) / 画面一覧HTML。
// PDF は HTML を Chromium で印刷する(crawler 側 htmlToPdf)ので、ここでは HTML までを純粋に作る。

import type { Severity } from "./types/index.js";
import type { ReportModel, ReportScreenRow } from "./report-model.js";

const SEV_COLOR: Record<Severity, string> = {
  critical: "#b00020",
  high: "#d32f2f",
  medium: "#f57c00",
  low: "#c9a227",
  info: "#5f7d8c",
};

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** CSV セル(RFC4180: 区切り/引用符/改行を含むなら "..." で囲み、内側の " は "" に)。 */
function csvCell(v: string | number): string {
  const s = String(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function csvRows(rows: Array<Array<string | number>>): string {
  return rows.map((r) => r.map(csvCell).join(",")).join("\r\n") + "\r\n";
}

const BASE_CSS = `
*{box-sizing:border-box}
body{font:14px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1a1a;margin:0;padding:32px;background:#fff}
h1{font-size:22px;margin:0 0 4px} h2{font-size:17px;margin:28px 0 10px;border-bottom:2px solid #eee;padding-bottom:4px}
h3{font-size:15px;margin:18px 0 6px}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre{background:#f6f8fa;border:1px solid #e3e6ea;border-radius:6px;padding:10px;overflow:auto;font-size:12.5px;white-space:pre-wrap;word-break:break-word}
.meta{color:#555;font-size:13px;margin:0 0 2px}
.badge{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:700;letter-spacing:.3px}
.sumtags span{display:inline-block;margin:0 6px 6px 0;padding:2px 10px;border-radius:12px;background:#eef1f4;font-size:12px}
.f{border:1px solid #e3e6ea;border-radius:8px;padding:14px 16px;margin:0 0 14px}
.f .kv{color:#555;font-size:12.5px;margin:2px 0}
.f .desc{margin:8px 0}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #e3e6ea;padding:6px 8px;text-align:left;vertical-align:top}
th{background:#f6f8fa}
table.info td:first-child{width:170px;color:#555;font-weight:600;background:#fafbfc}
.muted{color:#888}
img.shot{max-width:220px;max-height:140px;border:1px solid #ddd;border-radius:4px}
.ev{margin:10px 0 0;border-left:3px solid #cdd5dd;padding-left:10px}
.ev .evh{font-size:12px;color:#555;margin:0 0 4px}
.ev .lbl{font-size:11px;font-weight:700;letter-spacing:.4px;color:#5f7d8c;margin:6px 0 2px}
.ev pre{margin:0;max-height:420px}
@media print{body{padding:0}.f{break-inside:avoid}.ev pre{max-height:none}}
`;

function docHtml(title: string, body: string): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)}</title><style>${BASE_CSS}</style></head>
<body>
${body}
</body></html>`;
}

function row(k: string, v: string): string {
  return `<tr><td>${esc(k)}</td><td>${v}</td></tr>`;
}

function evidenceHtml(e: ReportModel["findings"][number]["evidence"][number]): string {
  const parts: string[] = [`<div class="ev"><div class="evh">Evidence <code>${esc(e.evidenceId)}</code> — <code>${esc(e.path)}</code></div>`];
  if (e.request) parts.push(`<div class="lbl">REQUEST</div><pre>${esc(e.request.trimEnd())}</pre>`);
  if (e.response) parts.push(`<div class="lbl">RESPONSE${e.truncated ? " (truncated)" : ""}</div><pre>${esc(e.response.trimEnd())}</pre>`);
  parts.push(`</div>`);
  return parts.join("");
}

/** 診断レポート(対象情報 + scope + findings + req/resp 証拠)を自己完結 HTML で。PDF はこれを Chromium で印刷。 */
export function renderReportHtml(m: ReportModel): string {
  const out: string[] = [];
  out.push(`<h1>${esc(m.brand)} Security Assessment Report</h1>`);

  // 対象情報
  out.push(`<h2>Assessment Information</h2><table class="info">`);
  out.push(row("Assessment ID", `<code>${esc(m.id)}</code>`));
  out.push(row("Target", `<code>${esc(m.target)}</code>`));
  out.push(row("Started", esc(m.startedAt)));
  out.push(row("Generated", esc(m.generatedAt)));
  out.push(row("Phase", esc(m.phase)));
  out.push(row("Screens", `${m.stats.screens.total} mapped · ${m.stats.screens.scanned} scanned · ${m.stats.screens.remaining} remaining`));
  out.push(row("Hypotheses", `${m.stats.hypotheses.total} (${m.stats.hypotheses.confirmed} confirmed)`));
  out.push(row("Findings", String(m.stats.findings.total)));
  out.push(row("Tooling", esc(m.brand)));
  out.push(`</table>`);

  // スコープ
  const s = m.scope;
  const hostList = (xs: string[]): string => (xs.length ? xs.map((h) => `<code>${esc(h)}</code>`).join(", ") : "&mdash;");
  out.push(`<h2>Scope</h2><table class="info">`);
  out.push(row("In-scope hosts", hostList(s.inScopeHosts)));
  out.push(row("Out-of-scope hosts", hostList(s.outOfScopeHosts)));
  out.push(row("In-scope paths", hostList(s.inScopePathPrefixes)));
  out.push(row("Out-of-scope paths", hostList(s.outOfScopePathPrefixes)));
  out.push(row("Rate", `${s.rate.requestsPerMinute} req/min, max ${s.rate.maxConcurrent} concurrent`));
  out.push(`</table>`);

  // サマリ
  out.push(`<h2>Summary</h2>`);
  if (m.findings.length === 0) {
    out.push(`<p class="muted"><em>No confirmed findings.</em></p>`);
  } else {
    const tags = (Object.entries(m.stats.findings.bySeverity) as [Severity, number][])
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span><b style="color:${SEV_COLOR[sev]}">${n}</b> ${sev}</span>`)
      .join("");
    out.push(`<p>${m.findings.length} finding(s)</p><p class="sumtags">${tags}</p>`);
  }

  // findings(req/resp 全文)
  if (m.findings.length > 0) {
    out.push(`<h2>Findings</h2>`);
    for (const f of m.findings) {
      out.push(`<div class="f">`);
      out.push(`<h3><span class="badge" style="background:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span> ${f.index}. ${esc(f.title)}</h3>`);
      out.push(`<div class="kv">Screen: <code>${esc(f.screenId ?? "(cross-screen)")}</code></div>`);
      out.push(`<div class="kv">Source: ${f.sourceKind} <code>${esc(f.sourceName)}</code></div>`);
      out.push(`<div class="kv">Scope basis: ${esc(f.scopeBasis)}</div>`);
      out.push(`<div class="desc">${esc(f.description)}</div>`);
      out.push(`<div><b>Reproduction</b></div><pre>${esc(f.reproSteps)}</pre>`);
      out.push(`<div><b>Evidence</b></div>`);
      if (f.evidence.length === 0) out.push(`<p class="muted">(none recorded)</p>`);
      else for (const e of f.evidence) out.push(evidenceHtml(e));
      out.push(`</div>`);
    }
  }

  return docHtml(`${m.brand} Report ${m.id}`, out.join("\n"));
}

/** findings.csv — 1 finding 1 行。 */
export function renderFindingsCsv(m: ReportModel): string {
  const header = ["index", "severity", "title", "screen", "source", "scope_basis", "evidence", "repro"];
  const rows = m.findings.map((f) => [
    f.index,
    f.severity,
    f.title,
    f.screenId ?? "(cross-screen)",
    `${f.sourceKind}:${f.sourceName}`,
    f.scopeBasis,
    f.evidence.map((e) => e.path).join(" | "),
    f.reproSteps,
  ]);
  return csvRows([header, ...rows]);
}

/** screens.csv — 画面一覧(survey 結果)。 */
export function renderScreensCsv(m: ReportModel): string {
  const header = ["screen_id", "url", "type", "auth", "labels", "params", "apis", "scan_status", "screenshot"];
  const rows = m.screens.map((s) => [
    s.screenId,
    s.url,
    s.screenType,
    s.authState,
    s.labels.join(" | "),
    s.paramCount,
    s.apiCount,
    s.scanStatus,
    s.screenshot,
  ]);
  return csvRows([header, ...rows]);
}

function shotImg(s: ReportScreenRow): string {
  return s.screenshot ? `<img class="shot" src="artifacts/${esc(s.screenshot)}" alt="${esc(s.screenId)}">` : `<span class="muted">—</span>`;
}

/** inventory.html — 画面一覧(単体エクスポート)。screenshot サムネ + メタ。 */
export function renderInventoryHtml(m: ReportModel): string {
  const out: string[] = [];
  out.push(`<h1>${esc(m.brand)} Screen Inventory</h1>`);
  out.push(`<p class="meta"><code>${esc(m.id)}</code> · Target: <code>${esc(m.target)}</code> · ${m.screens.length} screen(s) · Generated: ${esc(m.generatedAt)}</p>`);
  out.push(`<table><thead><tr><th>Shot</th><th>Screen</th><th>URL</th><th>Type</th><th>Auth</th><th>Labels</th><th>Params</th><th>APIs</th><th>Scan</th></tr></thead><tbody>`);
  for (const s of m.screens) {
    out.push(
      `<tr><td>${shotImg(s)}</td><td><code>${esc(s.screenId)}</code></td><td><code>${esc(s.url)}</code></td>` +
        `<td>${esc(s.screenType)}</td><td>${esc(s.authState)}</td><td>${esc(s.labels.join(", "))}</td>` +
        `<td>${s.paramCount}</td><td>${s.apiCount}</td><td>${esc(s.scanStatus)}</td></tr>`,
    );
  }
  out.push(`</tbody></table>`);
  return docHtml(`${m.brand} Inventory ${m.id}`, out.join("\n"));
}
