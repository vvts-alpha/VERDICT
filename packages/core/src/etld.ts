// Approximate the registrable domain (eTLD+1). Used by the "etld" scope mode to build `*.<registrable domain>`.
//
// To stay zero-dependency we don't ship the full Public Suffix List; instead we approximate with an
// exception table of common compound ccTLDs (co.uk / com.au / co.jp ...) plus a "last two labels" fallback.
// Limitation: not a complete PSL (newer compound TLDs or private suffixes may be missed). When an exact
// match is required, override explicitly via the manifest's scope.inScopeHosts.

/** Compound ccTLDs whose last two labels act as an "effective TLD"; treat up to the third label as the registrable domain. */
const MULTI_PART_SUFFIXES = new Set([
  // UK
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
  // JP
  "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
  // AU
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  // NZ
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
  // BR
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  // CN
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  // KR
  "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr",
  // IN
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in",
  // ZA
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  // Other commonly seen com.* families
  "com.mx", "com.tr", "com.ar", "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn",
  "com.ua", "com.pl", "com.ru", "com.co", "com.pe", "com.eg", "com.sa", "com.br",
]);

/**
 * Approximate the registrable domain (eTLD+1) from a hostname (a hostname without a port).
 * IPv4 / IPv6 / single-label hosts (e.g. localhost) are returned as-is.
 */
export function registrableDomain(hostname: string): string {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  // IPv4 (digits and dots only) / IPv6 (contains a colon) / single label: return as-is
  if (h.length === 0 || h.includes(":") || /^[0-9.]+$/.test(h)) return h;
  const labels = h.split(".");
  if (labels.length <= 2) return h;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}
