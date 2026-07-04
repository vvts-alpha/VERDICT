// Info-level security-header audit (deterministic, no LLM).
// The default list is editable. The CLI `header-audit` applies this list against the response headers to decide.

import type { Severity } from "@veritas/core";

export interface HeaderRule {
  /** short id selected via --headers */
  key: string;
  /** response header name (lowercase) */
  header: string;
  severity: Severity;
  title: string;
  /** why it matters (shown in the finding description) */
  note: string;
}

/** Default security-header checklist (edit here to make a custom list). */
export const SECURITY_HEADERS: HeaderRule[] = [
  { key: "csp", header: "content-security-policy", severity: "low", title: "Missing Content-Security-Policy", note: "No CSP — weak defense-in-depth against XSS / data injection / clickjacking." },
  { key: "hsts", header: "strict-transport-security", severity: "low", title: "Missing HSTS", note: "No Strict-Transport-Security (when served over TLS) — downgrade / man-in-the-middle risk." },
  { key: "xfo", header: "x-frame-options", severity: "info", title: "Missing X-Frame-Options", note: "Neither X-Frame-Options nor CSP frame-ancestors — clickjacking." },
  { key: "xcto", header: "x-content-type-options", severity: "info", title: "Missing X-Content-Type-Options (nosniff)", note: "No nosniff — MIME sniffing can assist XSS." },
  { key: "refpol", header: "referrer-policy", severity: "info", title: "Missing Referrer-Policy", note: "No Referrer-Policy — information leakage via the Referer header." },
  { key: "permpol", header: "permissions-policy", severity: "info", title: "Missing Permissions-Policy", note: "No Permissions-Policy — powerful browser features are unrestricted." },
];

/** Audit response headers + URL against rules; return the missing/insufficient rules. */
export function auditHeaders(
  headers: Record<string, string>,
  url: string,
  rules: HeaderRule[] = SECURITY_HEADERS,
): HeaderRule[] {
  const missing: HeaderRule[] = [];
  for (const r of rules) {
    const value = headers[r.header];
    if (r.key === "xfo") {
      // OK if either X-Frame-Options or CSP frame-ancestors is present.
      const csp = headers["content-security-policy"] ?? "";
      if (value || /frame-ancestors/i.test(csp)) continue;
      missing.push(r);
      continue;
    }
    if (r.key === "hsts" && !url.toLowerCase().startsWith("https:")) {
      continue; // don't require HSTS for non-TLS
    }
    if (r.key === "xcto") {
      if ((value ?? "").toLowerCase().includes("nosniff")) continue;
      missing.push(r);
      continue;
    }
    if (!value) missing.push(r);
  }
  return missing;
}
