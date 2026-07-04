// Parse a Burp Suite Pro XML report (Save report → XML) with no dependencies.
// Extracts issues for finding import, and also provides a coarse category for dedup (add net-new only).

import type { Severity } from "@veritas/core";

export interface BurpIssue {
  name: string;
  /** e.g. https://example.com */
  host: string;
  /** e.g. /app.js */
  path: string;
  /** High | Medium | Low | Information */
  severity: string;
  /** issueDetail (HTML stripped) */
  detail: string;
  background: string;
  /** raw request captured by the proxy (decoded, Cookie/Authorization redacted) */
  request: string;
  /** raw response (decoded) */
  response: string;
}

function cdata(s: string): string {
  const m = /^\s*<!\[CDATA\[([\s\S]*?)\]\]>\s*$/.exec(s);
  return (m ? (m[1] ?? "") : s).trim();
}

function tag(block: string, name: string): string {
  const m = new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i").exec(block);
  return m ? cdata(m[1] ?? "") : "";
}

function isBase64(chunk: string, name: string): boolean {
  return new RegExp(`<${name}[^>]*\\bbase64="true"`, "i").test(chunk);
}

function stripHtml(s: string): string {
  return s
    .replace(/<[^>]+>/g, " ")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/\s+/g, " ")
    .trim();
}

function redactCreds(raw: string): string {
  return raw.replace(/^(Cookie|Authorization|Set-Cookie):.*$/gim, "$1: <redacted>");
}

/** Burp XML report string → array of issues. */
export function parseBurpReport(xml: string): BurpIssue[] {
  const issues: BurpIssue[] = [];
  for (const raw of xml.split(/<issue>/i).slice(1)) {
    const block = raw.split(/<\/issue>/i)[0] ?? "";
    const rr = /<requestresponse>([\s\S]*?)<\/requestresponse>/i.exec(block)?.[1] ?? "";
    const dec = (val: string, name: string): string => {
      if (!val) return "";
      try {
        return isBase64(rr, name) ? Buffer.from(val, "base64").toString("utf8") : val;
      } catch {
        return val;
      }
    };
    issues.push({
      name: tag(block, "name"),
      host: tag(block, "host"),
      path: tag(block, "path") || tag(block, "location"),
      severity: tag(block, "severity"),
      detail: stripHtml(tag(block, "issueDetail")),
      background: stripHtml(tag(block, "issueBackground")),
      request: redactCreds(dec(tag(rr, "request"), "request")).slice(0, 8000),
      response: dec(tag(rr, "response"), "response").slice(0, 16000),
    });
  }
  return issues.filter((i) => i.name);
}

/** Burp severity → internal Severity. */
export function burpSeverity(s: string): Severity {
  switch (s.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "info";
  }
}

/** label (Burp issue name or internal finding title) → coarse category. Drops both families into the same bucket for dedup. */
export function coarseCategory(label: string): string {
  const s = label.toLowerCase();
  if (/xss|cross[\s-]?site script/.test(s)) return "xss";
  if (/sql inj|sqli/.test(s)) return "sqli";
  if (/idor|bola|object[\s-]?level|broken access|broken object/.test(s)) return "idor";
  if (/open redirect|unvalidated redirect/.test(s)) return "open-redirect";
  if (/path travers|arbitrary file|file read|lfi|directory travers/.test(s)) return "path-traversal";
  if (/\bssrf\b/.test(s)) return "ssrf";
  if (/header|content security|strict transport|clickjack|x-frame|csp/.test(s)) return "headers";
  if (/vulnerable javascript|outdated|out of date|dependency/.test(s)) return "vuln-js";
  if (/version|software|banner|disclos|information leak/.test(s)) return "info-disclosure";
  if (/csrf|cross[\s-]?site request/.test(s)) return "csrf";
  if (/session|cookie/.test(s)) return "session";
  return s.replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 24) || "other";
}
