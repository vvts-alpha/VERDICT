// In-band disclosure oracle for probe_secrets: concrete secrets (impact oracle) OR classic info-disclosure
// signatures (phpinfo / directory listing / stack trace). Ambient copies in the control body are ignored.

import { impactOracle } from "@veritas/scanner";

export interface DisclosureHit {
  category: "secret-exposure" | "info-disclosure";
  marker: string;
  detail: string;
}

const INFO_SIGS: ReadonlyArray<{ re: RegExp; marker: string; detail: string }> = [
  { re: /<title>\s*Index of\s/i, marker: "Index of", detail: "directory listing (Index of)" },
  { re: /Directory listing for /i, marker: "Directory listing for", detail: "directory listing" },
  { re: /<h1[^>]*>phpinfo\(\)/i, marker: "phpinfo()", detail: "phpinfo() output" },
  { re: /PHP Version\s+\d+\.\d+/i, marker: "PHP Version", detail: "phpinfo / PHP version dump" },
  { re: /Traceback \(most recent call last\)/, marker: "Traceback (most recent call last)", detail: "Python traceback" },
  { re: /java\.lang\.(Exception|Throwable|RuntimeException)/, marker: "java.lang.", detail: "Java stack trace" },
  { re: /Django (?:Debug|Version)/i, marker: "Django", detail: "Django debug page" },
];

export function disclosureHit(body: string, baselineBody?: string): DisclosureHit | null {
  const impact = impactOracle(body, baselineBody !== undefined ? { baselineBody } : {});
  const first = impact[0];
  if (first) return { category: "secret-exposure", marker: first.marker, detail: first.detail };
  for (const sig of INFO_SIGS) {
    if (!sig.re.test(body)) continue;
    if (baselineBody && sig.re.test(baselineBody)) continue;
    return { category: "info-disclosure", marker: sig.marker, detail: sig.detail };
  }
  return null;
}

/** robots.txt is a public file. A Sitemap: line (even to production from staging) is not info-disclosure. */
export function looksLikeRobotsTxt(body: string): boolean {
  const t = body.replace(/^\uFEFF/, "").trimStart().slice(0, 4000);
  return /user-agent\s*:/i.test(t) && /(?:sitemap|disallow|allow)\s*:/i.test(t);
}

/** sitemap.xml / sitemapindex — also a public file, not info-disclosure. */
export function looksLikeSitemapXml(body: string): boolean {
  const t = body.replace(/^\uFEFF/, "").trimStart().slice(0, 8000);
  return /<(?:urlset|sitemapindex)\b/i.test(t);
}

export function looksLikePublicWebFile(body: string): boolean {
  return looksLikeRobotsTxt(body) || looksLikeSitemapXml(body);
}
