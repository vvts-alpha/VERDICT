import type { Finding } from "@veritas/core";
import { findingVerdict } from "@veritas/core";
import { normalizePath } from "@veritas/crawler";
import type { EvidenceRecord, EvidenceStore } from "@veritas/scanner";

function category(f: Finding): string {
  return /^\[([a-z-]+)\]/.exec(f.title)?.[1] ?? "";
}

/** Prefer the actual tested sink over model-written endpoint/parameter spellings. Unknown cases stay separate. */
export function evidenceFindingKey(f: Finding, evidence: EvidenceStore): string | undefined {
  const records = f.evidenceIds.map(id => evidence.records.find(r => r.id === id)).filter((r): r is EvidenceRecord => !!r);
  const positives = records.filter(r => r.kind === "positive_replay" && r.response.status < 400);
  if (!positives.length) return undefined;
  const origins = new Set(positives.map(r => { try { return new URL(r.request.url).origin; } catch { return ""; } }));
  if (origins.size !== 1 || origins.has("")) return undefined;
  const origin = [...origins][0]!;
  const cat = category(f);
  // The credential claim is the same disclosure even when observed through different endpoints.
  // Do not combine it with a forgery or a claim of recovered plaintext / account takeover.
  if (cat === "session" && /(?:JWT|token)/i.test(f.title) && /password (?:hash|digest)|password.*embedded|digest embedded/i.test(f.title)
      && !/forg|crack|takeover|recovered/i.test(f.title)) {
    const hasDigest = positives.some(r => /"password"\s*:\s*"[a-f0-9]{32,128}"/i.test(r.response.body));
    // Session-analysis leads may cite the HTTP snapshot rather than the decoded token.
    // Consolidating that same claim does not validate it or promote a suspected finding.
    const analysisLead = findingVerdict(f) === "suspected" && positives.some(r => r.validator === "claude-pilot-session");
    if (hasDigest || analysisLead) return `${origin}::session::password-digest-disclosure`;
  }
  if (cat === "session" && /alg\s*[:=]\s*none/i.test(f.title)
      && positives.some(r => r.validator === "claude-pilot-jwt" && /alg.?none/i.test(r.note))) {
    return `${origin}::session::alg-none`;
  }
  const dom = positives.filter(r => r.validator === "claude-pilot-dom-xss");
  if (cat === "xss-reflected" && dom.length) {
    const keys = new Set(dom.map(r => {
      const u = new URL(r.request.url);
      const route = u.hash.startsWith("#/") ? new URL(u.hash.slice(1), u.origin) : u;
      return `${u.origin}::dom-xss::${u.pathname}::${route.pathname}::${[...route.searchParams.keys()].sort().join(",")}`;
    }));
    return keys.size === 1 ? [...keys][0] : undefined;
  }
  if (cat !== "sqli" && cat !== "idor-write") return undefined;
  const signatures = new Set<string>();
  for (const r of positives) {
    const u = new URL(r.request.url);
    if (cat === "idor-write" && !["PUT", "PATCH", "DELETE"].includes(r.request.method.toUpperCase())) continue;
    const params = new Set<string>();
    if (cat === "sqli") {
      // Require a SQL-bearing input; this avoids merging unrelated query/body injection points.
      const sql = /(?:['"].*(?:or|union|and)\b|\b(?:sleep|pg_sleep|waitfor)\b)/i;
      for (const [key, value] of u.searchParams) if (sql.test(value)) params.add(`query:${key}`);
      try { for (const [key, value] of Object.entries(JSON.parse(r.request.body ?? "{}"))) if (sql.test(String(value))) params.add(`body:${key}`); } catch { /* unknown body encoding */ }
      if (!params.size) return undefined;
    }
    signatures.add(`${origin}::${cat}::${r.request.method.toUpperCase()}::${normalizePath(u.pathname).template}::${[...params].sort().join(",")}`);
  }
  return signatures.size === 1 ? [...signatures][0] : undefined;
}

/** Conservative consolidation: retain the original rows, merge evidence, prefer confirmed over suspected. */
export function consolidateFindings(findings: Finding[], evidence: EvidenceStore): number {
  const groups = new Map<string, Finding[]>();
  for (const f of findings) {
    if (f.duplicateOf || f.source.kind !== "validator" || f.source.validatorName !== "claude-pilot") continue;
    const key = evidenceFindingKey(f, evidence);
    if (!key) continue;
    const group = groups.get(key) ?? [];
    group.push(f);
    groups.set(key, group);
  }
  let merged = 0;
  for (const group of groups.values()) {
    const canonical = group.find(f => findingVerdict(f) === "confirmed") ?? group[0]!;
    for (const f of group) {
      if (f === canonical) continue;
      canonical.evidenceIds = [...new Set([...canonical.evidenceIds, ...f.evidenceIds])];
      // Keep the canonical, evidence-qualified writeup and severity; never inherit a speculative impact claim.
      f.duplicateOf = canonical.id;
      merged++;
    }
  }
  return merged;
}

/** Restrict claims to what the cited evidence actually establishes. Never promote confidence or severity. */
export function qualifyFinding(f: Finding, evidence: EvidenceStore): string | undefined {
  if (f.source.kind !== "validator" || f.source.validatorName !== "claude-pilot" || findingVerdict(f) !== "confirmed") return undefined;
  const records = evidence.records.filter(r => f.evidenceIds.includes(r.id));
  const positives = records.filter(r => r.kind === "positive_replay");
  if (!positives.length) return undefined;
  const cat = category(f);
  if (cat === "xss-stored" && /upload|mime|content.type/i.test(f.title)) {
    const execution = positives.filter(r => r.validator === "claude-pilot-stored-xss" && /^XSS EXECUTED\b/.test(r.response.body));
    if (execution.length >= 2 && records.some(r => r.kind === "negative_control" && r.validator === "claude-pilot-stored-xss" && !/^XSS EXECUTED\b/.test(r.response.body))) return undefined;
    const reason = "Uploaded content was accepted; the cited evidence does not establish browser script execution with a clean control and two execution replays.";
    f.verdict = "suspected";
    f.anomaly = reason;
    if (f.severity === "high" || f.severity === "critical") f.severity = "medium";
    f.title = "[xss-stored] Uploaded active content — browser execution unverified";
    f.description = `${reason} Treat this as an upload-validation observation and an XSS lead, not confirmed Stored XSS. Serving script-bearing bytes as an image does not itself demonstrate execution.`;
    return reason;
  }
  if (cat === "price-tampering" && /wallet|top.up|deposit/i.test(f.title) && /negative/i.test(f.title)) {
    const negativeDeposits = positives.filter(r => {
      try {
        const body = JSON.parse(r.request.body ?? "{}");
        const result = JSON.parse(r.response.body);
        return r.response.status < 400 && Number(body.balance) < 0 && typeof result.data === "number" && result.data < 0;
      } catch { return false; }
    });
    if (negativeDeposits.length < 2 || negativeDeposits.length !== positives.length) return undefined;
    const reason = "Negative deposit amounts were accepted. External payout, theft, or payment bypass was not established by these deposit responses.";
    if (f.description.startsWith(reason)) return undefined;
    f.title = "[price-tampering] Wallet top-up accepts negative deposit amounts";
    f.description = reason + " This establishes an amount-validation flaw; independently verify the resulting ledger state and any wider financial impact.";
    if (f.severity === "high" || f.severity === "critical") f.severity = "medium";
    return reason;
  }
  return undefined;
}
