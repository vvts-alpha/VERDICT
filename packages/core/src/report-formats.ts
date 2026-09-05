// Pure report renderers: HTML (self-contained) / CSV (findings, screens) / screen-inventory HTML.
// PDF prints the HTML with Chromium (crawler-side htmlToPdf), so here we purely produce up to the HTML.

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

/** CSV cell (RFC4180: quote as "..." if it contains a delimiter/quote/newline, and double inner "). */
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
html{scroll-behavior:smooth}
.toc{background:#fafbfc;border:1px solid #e3e6ea;border-radius:8px;padding:10px 16px;margin:14px 0 8px}
.toc .toctitle{font-weight:700;font-size:12px;color:#555;letter-spacing:.4px;text-transform:uppercase;margin:0 0 6px}
.toc ul{margin:0;padding-left:18px} .toc>ul{padding-left:16px;list-style:none}
.toc li{margin:2px 0;font-size:13px} .toc a{color:#0366d6;text-decoration:none} .toc a:hover{text-decoration:underline}
.toc .sev{font-weight:700;font-size:11px;letter-spacing:.3px}
@media print{body{padding:0}.f{break-inside:avoid}.ev pre{max-height:none}.toc{break-inside:avoid}}
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

/** The assessment report (target info + scope + findings + req/resp evidence) as self-contained HTML. PDF prints this with Chromium. */
export function renderReportHtml(m: ReportModel): string {
  const out: string[] = [];
  out.push(`<h1>${esc(m.brand)} Security Assessment Report</h1>`);

  // Separate confirmed from suspected. Only confirmed are headlined; suspected go in their own section.
  const confirmed = m.findings.filter((f) => f.verdict === "confirmed");
  const suspected = m.findings.filter((f) => f.verdict === "suspected");
  const tocLi = (f: ReportModel["findings"][number]): string =>
    `<li><a href="#finding-${f.index}">${f.index}. <span class="sev" style="color:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span> ${esc(f.title)}</a></li>`;

  // Contents (click to jump to each section / each finding's anchor)
  out.push(`<nav class="toc"><div class="toctitle">Contents</div><ul>`);
  out.push(`<li><a href="#assessment-information">Assessment Information</a></li>`);
  out.push(`<li><a href="#scope">Scope</a></li>`);
  out.push(`<li><a href="#summary">Summary</a></li>`);
  if (confirmed.length > 0) {
    out.push(`<li><a href="#findings">Findings</a><ul>`);
    for (const f of confirmed) out.push(tocLi(f));
    out.push(`</ul></li>`);
  }
  if (suspected.length > 0) {
    out.push(`<li><a href="#suspected">Suspected (needs manual verification)</a><ul>`);
    for (const f of suspected) out.push(tocLi(f));
    out.push(`</ul></li>`);
  }
  out.push(`</ul></nav>`);

  // Target info
  out.push(`<h2 id="assessment-information">Assessment Information</h2><table class="info">`);
  out.push(row("Assessment ID", `<code>${esc(m.id)}</code>`));
  out.push(row("Target", `<code>${esc(m.target)}</code>`));
  out.push(row("Started", esc(m.startedAt)));
  out.push(row("Generated", esc(m.generatedAt)));
  out.push(row("Phase", esc(m.phase)));
  out.push(row("Screens", `${m.stats.screens.total} mapped · ${m.stats.screens.scanned} tested · ${m.stats.screens.excluded} excluded · ${m.stats.screens.remaining} unfinished`));
  out.push(row("Hypotheses", `${m.stats.hypotheses.total} (${m.stats.hypotheses.confirmed} confirmed)`));
  out.push(row("Findings", String(m.stats.findings.total)));
  out.push(row("Tooling", esc(m.brand)));
  out.push(`</table>`);

  // Scope
  const s = m.scope;
  const hostList = (xs: string[]): string => (xs.length ? xs.map((h) => `<code>${esc(h)}</code>`).join(", ") : "&mdash;");
  out.push(`<h2 id="scope">Scope</h2><table class="info">`);
  out.push(row("In-scope hosts", hostList(s.inScopeHosts)));
  out.push(row("Out-of-scope hosts", hostList(s.outOfScopeHosts)));
  out.push(row("In-scope paths", hostList(s.inScopePathPrefixes)));
  out.push(row("Out-of-scope paths", hostList(s.outOfScopePathPrefixes)));
  out.push(row("Rate", `${s.rate.requestsPerMinute} req/min, max ${s.rate.maxConcurrent} concurrent`));
  out.push(`</table>`);

  // Summary
  out.push(`<h2 id="summary">Summary</h2>`);
  if (confirmed.length === 0) {
    out.push(`<p class="muted"><em>No confirmed findings.</em></p>`);
  } else {
    const tags = (Object.entries(m.stats.findings.bySeverity) as [Severity, number][])
      .filter(([, n]) => n > 0)
      .map(([sev, n]) => `<span><b style="color:${SEV_COLOR[sev]}">${n}</b> ${sev}</span>`)
      .join("");
    out.push(`<p>${confirmed.length} finding(s)</p><p class="sumtags">${tags}</p>`);
  }
  if (suspected.length > 0)
    out.push(`<p class="muted">Plus <b>${suspected.length}</b> suspected lead(s) needing manual verification (listed separately, not counted above).</p>`);

  // One finding (shared by confirmed / suspected; suspected gets a [SUSPECTED] badge + anomaly).
  const renderF = (f: ReportModel["findings"][number]): void => {
    out.push(`<div class="f" id="finding-${f.index}">`);
    const sus = f.verdict === "suspected" ? `<span class="badge" style="background:#8a6d00">SUSPECTED</span> ` : "";
    out.push(`<h3>${sus}<span class="badge" style="background:${SEV_COLOR[f.severity]}">${f.severity.toUpperCase()}</span> ${f.index}. ${esc(f.title)}</h3>`);
    out.push(`<div class="kv">Screen: <code>${esc(f.screenId ?? "(cross-screen)")}</code></div>`);
    out.push(`<div class="kv">Source: ${f.sourceKind} <code>${esc(f.sourceName)}</code></div>`);
    out.push(`<div class="kv">Scope basis: ${esc(f.scopeBasis)}</div>`);
    if (f.anomaly) out.push(`<div class="kv"><b>Anomaly (why this is a lead):</b> ${esc(f.anomaly)}</div>`);
    out.push(`<div class="desc">${esc(f.description)}</div>`);
    out.push(`<div><b>Reproduction</b></div><pre>${esc(f.reproSteps)}</pre>`);
    out.push(`<div><b>Evidence</b></div>`);
    if (f.evidence.length === 0) out.push(`<p class="muted">(none recorded)</p>`);
    else for (const e of f.evidence) out.push(evidenceHtml(e));
    out.push(`</div>`);
  };

  // confirmed findings (full req/resp)
  if (confirmed.length > 0) {
    out.push(`<h2 id="findings">Findings</h2>`);
    for (const f of confirmed) renderF(f);
  }
  // suspected (needs manual verification; not in the confirmed total)
  if (suspected.length > 0) {
    out.push(`<h2 id="suspected">Suspected (needs manual verification)</h2>`);
    out.push(`<p class="muted">Leads with one concrete anomaly but without control+2-replay confirmation — verify before relying on them.</p>`);
    for (const f of suspected) renderF(f);
  }

  return docHtml(`${m.brand} Report ${m.id}`, out.join("\n"));
}

/** findings.csv — one finding per row. */
export function renderFindingsCsv(m: ReportModel): string {
  const header = ["index", "severity", "verdict", "title", "screen", "source", "scope_basis", "evidence", "repro"];
  const rows = m.findings.map((f) => [
    f.index,
    f.severity,
    f.verdict, // so a suspected lead can't be mistaken for (or counted as) a confirmed finding by a CSV consumer
    f.title,
    f.screenId ?? "(cross-screen)",
    `${f.sourceKind}:${f.sourceName}`,
    f.scopeBasis,
    f.evidence.map((e) => e.path).join(" | "),
    f.reproSteps,
  ]);
  return csvRows([header, ...rows]);
}

/** screens.csv — the screen inventory (survey results). */
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

/** inventory.html — the screen inventory (standalone export). Screenshot thumbnails + metadata. */
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
