// Burp's Information/Low/Medium issues, even on their own at low severity, are often **entry points to real vulns** (reflection point → XSS,
// external comms → SSRF, loose CORS → data theft…). verifyImportedBurp only re-verifies High+, so
// anything below that passes through untouched. This module triages that pass-through layer **by name** and surfaces "only the promising leads",
// a pure function (no network). The goal is not to verify everything, but to present the candidates the operator / downstream verify should focus on.

import type { BurpIssue } from "./burp.js";

export type LeadPriority = "high" | "medium" | "low";

export interface BurpLead {
  /** the real-vuln class this entry point points to (corresponds to the probe name) */
  lead: string;
  priority: LeadPriority;
  /** why it's promising (one line) */
  why: string;
  /** the next action to confirm (existing probe tool, etc.) */
  probe: string;
  /** the Burp issue names mapped to this lead (deduplicated) */
  names: string[];
  /** total count of matching issue instances (Burp's per-URL counting) */
  count: number;
  /** representative URLs (up to 5) */
  sampleUrls: string[];
}

const PRIORITY_RANK: Record<LeadPriority, number> = { high: 3, medium: 2, low: 1 };

/** issue name → lead rule (first match top-to-bottom wins). Hygiene items (cookie flag / TLS / charset etc.) are
 *  not "entry points", so they are **intentionally not picked up** (keeps the triage high-signal). */
const LEAD_RULES: Array<{ re: RegExp; lead: string; priority: LeadPriority; why: string; probe: string }> = [
  // ── XSS family (reflection points, stored reflection, DOM sink) = most promising ──
  {
    re: /cross-site scripting \(stored\)|input returned in response \(stored\)|stored.*\bxss\b/i,
    lead: "xss-stored",
    priority: "high",
    why: "stored reflection — may render unescaped at another screen/role",
    probe: "probe_stored_xss",
  },
  {
    re: /\bdom\b.*manipulation|dom[\s-]?based|dom data/i,
    lead: "xss-dom",
    priority: "high",
    why: "client-side sink with attacker-influenced source — DOM XSS candidate",
    probe: "probe_dom_xss",
  },
  {
    re: /cross-site scripting \(reflected\)|input returned in response \(reflected\)|reflected.*\bxss\b/i,
    lead: "xss-reflected",
    priority: "high",
    why: "reflection point — payload may break out of its HTML/JS context",
    probe: "probe_xss / probe_dom_xss",
  },
  // ── SSRF / OOB (external comms observed) = close to a hit ──
  {
    re: /external service interaction|out-of-band|\bssrf\b|server-side request/i,
    lead: "ssrf",
    priority: "high",
    why: "server reached an external host (DNS/HTTP) — strong SSRF/OOB signal",
    probe: "probe_oob (Collaborator)",
  },
  // ── injection hints ──
  {
    re: /suspicious input transformation|sql statement|serialized object|expression language|template/i,
    lead: "injection",
    priority: "medium",
    why: "input transformed/echoed in a dangerous sink — injection candidate",
    probe: "probe_params / probe_oob",
  },
  // ── CORS (loose origin trust) = data theft if credentialed ──
  {
    re: /cross-origin resource sharing|\bcors\b/i,
    lead: "cors",
    priority: "medium",
    why: "arbitrary/loose origin trusted — cross-site data theft if responses are credentialed",
    probe: "http_request with Origin: https://evil.example then check ACAO/ACAC",
  },
  // ── CSRF (state change without anti-CSRF) ──
  {
    re: /cross-site request forgery|\bcsrf\b/i,
    lead: "csrf",
    priority: "medium",
    why: "state-changing request without an anti-CSRF token",
    probe: "probe_csrf",
  },
  // ── open redirect / link manipulation ──
  {
    re: /open redirect|unvalidated redirect|link manipulation/i,
    lead: "open-redirect",
    priority: "medium",
    why: "redirect/link target is user-controlled",
    probe: "probe_redirect",
  },
  // ── weak CSP (can't stop injected XSS = amplifier) ──
  {
    re: /content security policy.*(untrusted script|form hijack|unsafe|allows)/i,
    lead: "csp-weak",
    priority: "medium",
    why: "weak CSP won't block injected script — amplifies any reflected/stored XSS lead",
    probe: "pair with an XSS lead on the same origin",
  },
  // ── upload feature (type/path/extension bypass surface) ──
  {
    re: /file upload/i,
    lead: "upload",
    priority: "medium",
    why: "upload surface — content-type / extension / path-traversal bypass to test",
    probe: "manual upload probe (type/path/overwrite)",
  },
  // ── API spec exposure (increases the test surface) ──
  {
    re: /openapi|swagger|graphql|wsdl|api definition/i,
    lead: "api-surface",
    priority: "medium",
    why: "API spec exposed — enumerate the endpoints it documents and test them",
    probe: "fetch the spec → probe_paths the listed endpoints",
  },
  // ── source/config disclosure ──
  {
    re: /source code disclosure|backup file|\.bak\b|configuration file|directory listing/i,
    lead: "info-disclosure",
    priority: "medium",
    why: "leaked source/config/listing aids targeting and may expose secrets",
    probe: "fetch & review for secrets / hidden endpoints",
  },
  // ── low-priority clues ──
  {
    re: /private ip address|internal ip/i,
    lead: "recon",
    priority: "low",
    why: "internal host/IP leaked — pair with an SSRF lead",
    probe: "—",
  },
  {
    re: /base64-encoded data in parameter|encoded.*parameter/i,
    lead: "tampering",
    priority: "low",
    why: "encoded param may hide an id/object-ref worth decoding and tampering",
    probe: "decode → probe_params",
  },
  {
    re: /robots\.txt|sitemap|hidden|spider/i,
    lead: "hidden-surface",
    priority: "low",
    why: "may reveal un-linked paths to map",
    probe: "probe_paths",
  },
];

export interface BurpLeadClass {
  lead: string;
  priority: LeadPriority;
  why: string;
  probe: string;
}

/** Burp issue name (or a finding title with "[burp] …" stripped) → lead classification. null for unclassified/hygiene.
 *  The single source of truth used both by the triage aggregation and by the selection-phase hint display / severity bump on confirmation. */
export function classifyBurpName(name: string): BurpLeadClass | null {
  for (const r of LEAD_RULES) if (r.re.test(name)) return { lead: r.lead, priority: r.priority, why: r.why, probe: r.probe };
  return null;
}

function matchRule(name: string): (typeof LEAD_RULES)[number] | null {
  for (const r of LEAD_RULES) if (r.re.test(name)) return r;
  return null;
}

/** Build the issue's URL (host+path) (for triage display; the scope check is assumed already done by the caller). */
function issueUrl(i: BurpIssue): string {
  try {
    return new URL(i.path || "/", i.host).toString();
  } catch {
    return `${i.host}${i.path || ""}`;
  }
}

/**
 * Triage a set of Burp issues (usually the below-High layer that verify doesn't touch) and return the promising leads
 * aggregated per lead class, sorted priority-desc then count-desc. Hygiene items are excluded.
 */
export function triageBurpInfo(issues: ReadonlyArray<BurpIssue>): BurpLead[] {
  const byLead = new Map<string, BurpLead & { _names: Set<string>; _urls: string[] }>();
  for (const issue of issues) {
    const rule = matchRule(issue.name);
    if (!rule) continue; // ignore hygiene / unclassified
    let agg = byLead.get(rule.lead);
    if (!agg) {
      agg = {
        lead: rule.lead,
        priority: rule.priority,
        why: rule.why,
        probe: rule.probe,
        names: [],
        count: 0,
        sampleUrls: [],
        _names: new Set<string>(),
        _urls: [],
      };
      byLead.set(rule.lead, agg);
    }
    agg.count += 1;
    agg._names.add(issue.name);
    if (agg._urls.length < 5) {
      const u = issueUrl(issue);
      if (!agg._urls.includes(u)) agg._urls.push(u);
    }
  }
  const leads: BurpLead[] = [...byLead.values()].map((a) => ({
    lead: a.lead,
    priority: a.priority,
    why: a.why,
    probe: a.probe,
    names: [...a._names],
    count: a.count,
    sampleUrls: a._urls,
  }));
  leads.sort((x, y) => PRIORITY_RANK[y.priority] - PRIORITY_RANK[x.priority] || y.count - x.count);
  return leads;
}

/** Format the triage result into human-readable lines (for CLI logs / event notes). */
export function formatBurpLeads(leads: ReadonlyArray<BurpLead>): string[] {
  return leads.map(
    (l) =>
      `[${l.priority}] ${l.lead} — ${l.count} issue(s): ${l.why} → ${l.probe}` +
      (l.sampleUrls.length ? `  (e.g. ${l.sampleUrls.slice(0, 3).join(", ")})` : ""),
  );
}
