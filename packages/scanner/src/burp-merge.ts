// Shared logic for merging Burp issues (from XML or REST) into an existing run.
// Deduplicated against existing findings by (coarse category × normalized endpoint); out-of-scope is dropped.
// Both the CLI (burp-import / burp-scan) and the server (upload-import API) use this.
// To keep the layering intact, endpoint normalization (crawler's normalizePath) is injected (pathTemplate).

import type { AssessmentStore, Finding, ScopePolicy, Severity } from "@veritas/core";
import { isInScope } from "@veritas/core";
import { EvidenceStore } from "./evidence.js";
import { coarseCategory, burpSeverity } from "./burp.js";
import type { BurpIssue } from "./burp.js";

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const maxSeverity = (a: Severity, b: Severity): Severity => (SEV_RANK[b] > SEV_RANK[a] ? b : a);

export interface MergeBurpOptions {
  /** Prefix for the finding id (default "b"). burp-import="b" / burp-scan is also "b". */
  prefix?: string;
  /** Templatize the endpoint for use as the dedup key (default: identity). CLI/server pass normalizePath. */
  pathTemplate?: (path: string) => string;
}

export interface MergeBurpResult {
  added: number;
  skipped: number;
  oos: number;
}

/** From state we only read findings (existing-dup check) and scope (in-scope check). */
export function mergeBurpIssues(
  store: Pick<AssessmentStore, "upsertFinding">,
  id: string,
  state: { findings: ReadonlyArray<Finding>; scope: ScopePolicy },
  artifactsDir: string,
  issues: ReadonlyArray<BurpIssue>,
  opts: MergeBurpOptions = {},
): MergeBurpResult {
  const prefix = opts.prefix ?? "b";
  const tmpl = opts.pathTemplate ?? ((p) => p);
  const evidence = new EvidenceStore(artifactsDir);
  const keyOf = (cat: string, path: string): string => {
    try {
      return `${cat}::${tmpl(path)}`;
    } catch {
      return `${cat}::${path}`;
    }
  };
  const existing = new Set<string>();
  for (const f of state.findings) {
    const ep = /(\/[A-Za-z0-9_{}/.-]+)/.exec(f.title)?.[1] ?? "/";
    existing.add(keyOf(coarseCategory(f.title), ep));
  }
  let added = 0;
  let skipped = 0;
  let oos = 0;

  // 1) Keep only in-scope (resolve URL/path). Drop out-of-scope.
  const inScope: Array<{ issue: BurpIssue; url: string; path: string }> = [];
  for (const issue of issues) {
    let url: string;
    try {
      url = new URL(issue.path || "/", issue.host).toString();
    } catch {
      url = issue.host;
    }
    if (!isInScope(url, state.scope)) {
      oos += 1;
      continue;
    }
    let path: string;
    try {
      path = new URL(url).pathname;
    } catch {
      path = issue.path || "/";
    }
    inScope.push({ issue, url, path });
  }

  // 2) Group by issue name. Burp emits the same issue (e.g. "CORS: arbitrary origin trusted") once per URL, so
  //    collapse the per-URL duplicates into **one finding (with a list of affected URLs)**. Removes report inflation (53 → effectively ~20).
  const groups = new Map<string, Array<{ issue: BurpIssue; url: string; path: string }>>();
  for (const it of inScope) {
    const g = groups.get(it.issue.name) ?? [];
    g.push(it);
    groups.set(it.issue.name, g);
  }

  // 3) One finding per group (deduplicated against existing claude-pilot findings by (coarse category × path)).
  for (const members of groups.values()) {
    const first = members[0]!;
    const key = keyOf(coarseCategory(first.issue.name), first.path);
    if (existing.has(key)) {
      skipped += members.length;
      continue;
    }
    existing.add(key);
    added += 1;
    const severity = members.map((m) => burpSeverity(m.issue.severity)).reduce(maxSeverity);
    const urls = [...new Set(members.map((m) => m.url))];
    // Put the representative URL at the end as "@ <url>" (don't break verifyBurpFindings' endpointOf extraction). List the rest in a preceding note.
    const more = urls.length > 1 ? ` [+${urls.length - 1} more URL(s): ${urls.slice(1, 6).join(", ")}${urls.length > 6 ? ", …" : ""}]` : "";
    const ev = evidence.record({
      screenId: "burp",
      validator: "burp",
      kind: "positive_replay",
      request: { method: "GET", url: first.url, headers: {}, body: first.issue.request || null },
      response: { status: 0, finalUrl: first.url, durationMs: 0, headers: {}, body: first.issue.response },
      note: first.issue.name,
    });
    store.upsertFinding(id, {
      id: `${prefix}-${String(added).padStart(3, "0")}`,
      screenId: null,
      title: `[burp] ${first.issue.name}${urls.length > 1 ? ` (${urls.length} URLs)` : ""}`,
      severity,
      source: { kind: "validator", validatorName: "burp" },
      description: `${(first.issue.detail || first.issue.background).slice(0, 600)}${more} @ ${first.url}`,
      reproSteps: "Detected by Burp. Evidence contains the request/response (Cookie/Authorization redacted).",
      evidenceIds: [ev.id],
      scopeBasis: "burp scan (in-scope)",
    });
  }
  return { added, skipped, oos };
}
