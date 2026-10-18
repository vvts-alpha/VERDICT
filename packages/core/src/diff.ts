// Run-vs-run diff — offline comparison of two assessment views for retest workflows. Pure and
// deterministic: no network, no heuristics. Keys are stable across runs (screens by urlTemplate,
// findings by dedupKey-or-title, checks by checkKey, roles by name) — ids differ per run so they're
// never compared directly.

import type { CheckExecution, Finding, ScreenScanStatus } from "./types/index.js";
import type { StateView } from "./view.js";

export interface StatusChange<K> {
  key: K;
  from: string;
  to: string;
}

export interface DiffReport {
  aId: string;
  bId: string;
  phase: { a: string; b: string };
  screens: {
    added: string[]; // urlTemplates only in b
    removed: string[]; // urlTemplates only in a
    statusChanges: StatusChange<string>[];
  };
  findings: {
    added: string[]; // finding titles only in b
    resolved: string[]; // only in a (fixed or no longer found)
    verdictChanges: StatusChange<string>[];
    severityChanges: StatusChange<string>[];
    totalA: number;
    totalB: number;
  };
  checks: {
    added: number;
    removed: number;
    transitions: StatusChange<string>[]; // checkKey → status change
  };
  roles: {
    added: string[];
    removed: string[];
    transitions: Array<{ key: string; from: string; to: string; reason?: string }>;
  };
  summary: string[];
}

const scanByScreen = (view: StateView): Map<string, ScreenScanStatus> => {
  const m = new Map<string, ScreenScanStatus>();
  const tpl = new Map<string, string>();
  for (const s of view.screens) tpl.set(s.screenId, s.urlTemplate);
  for (const s of view.screenScans) m.set(tpl.get(s.screenId) ?? s.screenId, s.status);
  return m;
};

const findingKey = (f: Finding): string => f.dedupKey ?? f.title;

const checkKeyOf = (c: CheckExecution): string => c.id;

export function diffStateViews(a: StateView, b: StateView): DiffReport {
  const scansA = scanByScreen(a);
  const scansB = scanByScreen(b);
  const addedScreens: string[] = [];
  const removedScreens: string[] = [];
  const statusChanges: StatusChange<string>[] = [];
  for (const [tpl, st] of scansB) {
    if (!scansA.has(tpl)) addedScreens.push(tpl);
    else if (scansA.get(tpl) !== st) statusChanges.push({ key: tpl, from: scansA.get(tpl)!, to: st });
  }
  for (const tpl of scansA.keys()) if (!scansB.has(tpl)) removedScreens.push(tpl);

  const findA = new Map(a.findings.map((f) => [findingKey(f), f]));
  const findB = new Map(b.findings.map((f) => [findingKey(f), f]));
  const addedFindings: string[] = [];
  const resolvedFindings: string[] = [];
  const verdictChanges: StatusChange<string>[] = [];
  const severityChanges: StatusChange<string>[] = [];
  for (const [k, f] of findB) {
    const prev = findA.get(k);
    if (!prev) { addedFindings.push(f.title); continue; }
    const va = prev.verdict ?? "confirmed";
    const vb = f.verdict ?? "confirmed";
    if (va !== vb) verdictChanges.push({ key: f.title, from: va, to: vb });
    if (prev.severity !== f.severity) severityChanges.push({ key: f.title, from: prev.severity, to: f.severity });
  }
  for (const [k, f] of findA) if (!findB.has(k)) resolvedFindings.push(f.title);

  const checksA = new Map(a.checkExecutions.map((c) => [checkKeyOf(c), c]));
  const checksB = new Map(b.checkExecutions.map((c) => [checkKeyOf(c), c]));
  let addedChecks = 0;
  const transitions: StatusChange<string>[] = [];
  for (const [k, c] of checksB) {
    const prev = checksA.get(k);
    if (!prev) { addedChecks++; continue; }
    if (prev.status !== c.status) transitions.push({ key: `${c.checkClass} ${c.target}${c.param ? ` ${c.param}` : ""}${c.subject ? ` as ${c.subject}` : ""}`, from: prev.status, to: c.status });
  }
  let removedChecks = 0;
  for (const k of checksA.keys()) if (!checksB.has(k)) removedChecks++;

  const rolesA = new Map(a.roleProgress.map((r) => [r.role, r]));
  const rolesB = new Map(b.roleProgress.map((r) => [r.role, r]));
  const addedRoles: string[] = [];
  const removedRoles: string[] = [];
  const roleTransitions: DiffReport["roles"]["transitions"] = [];
  for (const [name, r] of rolesB) {
    const prev = rolesA.get(name);
    if (!prev) { addedRoles.push(name); continue; }
    if (prev.state !== r.state || prev.visited !== r.visited || prev.pending !== r.pending) {
      roleTransitions.push({ key: name, from: `${prev.state} (visited ${prev.visited}, pending ${prev.pending})`, to: `${r.state} (visited ${r.visited}, pending ${r.pending})`, ...(r.reason ? { reason: r.reason } : {}) });
    }
  }
  for (const name of rolesA.keys()) if (!rolesB.has(name)) removedRoles.push(name);

  const summary: string[] = [];
  if (addedFindings.length) summary.push(`${addedFindings.length} NEW finding(s)`);
  if (resolvedFindings.length) summary.push(`${resolvedFindings.length} resolved finding(s)`);
  if (statusChanges.length) summary.push(`${statusChanges.length} screen status change(s)`);
  if (addedScreens.length) summary.push(`${addedScreens.length} new screen(s) discovered`);
  if (transitions.length) summary.push(`${transitions.length} check outcome change(s)`);
  if (!summary.length) summary.push("no differences");

  return {
    aId: a.id,
    bId: b.id,
    phase: { a: a.phase, b: b.phase },
    screens: { added: addedScreens, removed: removedScreens, statusChanges },
    findings: { added: addedFindings, resolved: resolvedFindings, verdictChanges, severityChanges, totalA: a.findings.length, totalB: b.findings.length },
    checks: { added: addedChecks, removed: removedChecks, transitions },
    roles: { added: addedRoles, removed: removedRoles, transitions: roleTransitions },
    summary,
  };
}

/** Markdown for the operator-facing diff report — honest deltas only, no severity inflation. */
export function renderDiffMarkdown(d: DiffReport): string {
  const lines: string[] = [
    `# Scan delta — ${d.aId} → ${d.bId}`,
    "",
    `**Summary:** ${d.summary.join(" · ")}`,
    "",
    `| | run A | run B |`,
    `|---|---|---|`,
    `| assessment | \`${d.aId}\` | \`${d.bId}\` |`,
    `| phase | ${d.phase.a} | ${d.phase.b} |`,
    `| findings | ${d.findings.totalA} | ${d.findings.totalB} |`,
    `| screens (scanned) | ${d.screens.added.length + d.screens.statusChanges.length + d.screens.removed.length === 0 ? "unchanged" : "see below"} | |`,
    "",
  ];
  if (d.findings.added.length || d.findings.resolved.length || d.findings.verdictChanges.length || d.findings.severityChanges.length) {
    lines.push("## Findings", "");
    for (const t of d.findings.added) lines.push(`- ➕ NEW: ${t}`);
    for (const t of d.findings.resolved) lines.push(`- ➖ resolved/absent: ${t}`);
    for (const c of d.findings.verdictChanges) lines.push(`- verdict: ${c.key} — ${c.from} → ${c.to}`);
    for (const c of d.findings.severityChanges) lines.push(`- severity: ${c.key} — ${c.from} → ${c.to}`);
    lines.push("");
  }
  if (d.screens.added.length || d.screens.removed.length || d.screens.statusChanges.length) {
    lines.push("## Screens", "");
    for (const s of d.screens.added) lines.push(`- ➕ discovered: ${s}`);
    for (const s of d.screens.removed) lines.push(`- ➖ gone: ${s}`);
    for (const c of d.screens.statusChanges) lines.push(`- ${c.key}: ${c.from} → ${c.to}`);
    lines.push("");
  }
  if (d.checks.transitions.length || d.checks.added || d.checks.removed) {
    lines.push("## Check outcomes", "");
    if (d.checks.added) lines.push(`- ${d.checks.added} new check execution(s)`);
    if (d.checks.removed) lines.push(`- ${d.checks.removed} check execution(s) absent in run B`);
    for (const c of d.checks.transitions) lines.push(`- ${c.key}: ${c.from} → ${c.to}`);
    lines.push("");
  }
  if (d.roles.added.length || d.roles.removed.length || d.roles.transitions.length) {
    lines.push("## Roles", "");
    for (const r of d.roles.added) lines.push(`- ➕ role: ${r}`);
    for (const r of d.roles.removed) lines.push(`- ➖ role: ${r}`);
    for (const c of d.roles.transitions) lines.push(`- ${c.key}: ${c.from} → ${c.to}${c.reason ? ` (${c.reason})` : ""}`);
    lines.push("");
  }
  return `${lines.join("\n")}\n`;
}
