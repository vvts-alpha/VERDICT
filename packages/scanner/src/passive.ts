// Passive-inspection framework (deterministic, no LLM). Holds the Burp-passive-scan equivalent as a
// "custom list of checks". Each check is a pure function PassiveContext (response) → PassiveIssue[].
// Default checks: security-headers / version-disclosure / vulnerable-js. Add here to grow the list.

import type { Severity } from "@veritas/core";
import { SECURITY_HEADERS, auditHeaders, type HeaderRule } from "./headers.js";

export interface PassiveContext {
  url: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

export interface PassiveIssue {
  /** stable key for dedup (source of the finding id) */
  key: string;
  severity: Severity;
  title: string;
  detail: string;
}

export interface PassiveCheck {
  id: string;
  label: string;
  run(ctx: PassiveContext): PassiveIssue[];
}

// ───────────────────────── security headers ─────────────────────────
export function headersCheck(rules: HeaderRule[] = SECURITY_HEADERS): PassiveCheck {
  return {
    id: "headers",
    label: "security headers",
    run: (ctx) =>
      auditHeaders(ctx.headers, ctx.url, rules).map((r) => ({
        key: `header-${r.key}`,
        severity: r.severity,
        title: r.title,
        detail: r.note,
      })),
  };
}

// ───────────────────────── version / banner disclosure ─────────────────────────
const VERSION_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "x-runtime"];

export const versionCheck: PassiveCheck = {
  id: "version",
  label: "version disclosure",
  run: (ctx) => {
    const out: PassiveIssue[] = [];
    for (const h of VERSION_HEADERS) {
      const v = ctx.headers[h];
      if (v && /\d/.test(v)) {
        out.push({ key: `version-${h}`, severity: "info", title: `Version disclosure via '${h}' header`, detail: `${h}: ${v}` });
      }
    }
    const meta = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(ctx.body);
    if (meta?.[1]) {
      out.push({ key: "version-generator", severity: "info", title: "Version disclosure via <meta generator>", detail: meta[1] });
    }
    return out;
  },
};

// ───────────────────────── vulnerable JavaScript libraries (Retire.js-lite) ─────────────────────────
interface JsLib {
  name: string;
  /** pick up name and version from the filename/reference. group 1 = version */
  re: RegExp;
  /** treat this version and below as vulnerable (last known-vulnerable version) */
  maxVuln: string;
  note: string;
}

/** Table of known-vulnerable libraries (edit to make a custom list). */
export const VULN_JS_LIBS: JsLib[] = [
  { name: "jQuery", re: /jquery[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "3.4.1", note: "jQuery <3.5.0: XSS via htmlPrefilter (CVE-2020-11022/11023)." },
  { name: "jQuery UI", re: /jquery-ui[-.]?(\d+\.\d+(?:\.\d+)?)/i, maxVuln: "1.12.1", note: "jQuery UI <1.13.0: XSS (CVE-2021-41182/41183/41184)." },
  { name: "AngularJS", re: /angular[-.]?(1\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "1.8.3", note: "AngularJS 1.x is EOL — multiple XSS / sandbox-bypass issues, no fixes." },
  { name: "Bootstrap", re: /bootstrap[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "3.4.0", note: "Bootstrap <3.4.1/<4.3.1: XSS in data-* attributes (CVE-2019-8331)." },
  { name: "Lodash", re: /lodash[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "4.17.11", note: "lodash <4.17.12: prototype pollution (CVE-2019-10744)." },
  { name: "Moment.js", re: /moment[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "2.29.1", note: "moment <2.29.2: ReDoS (CVE-2022-31129)." },
  { name: "Handlebars", re: /handlebars[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "4.0.13", note: "Handlebars <4.3.0: prototype pollution / RCE (CVE-2019-19919)." },
  { name: "DOMPurify", re: /(?:purify|dompurify)[-.]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js/i, maxVuln: "2.0.16", note: "DOMPurify <2.0.17: mXSS bypass." },
];

/** a <= b ? (numeric-tuple comparison) */
export function versionLeq(a: string, b: string): boolean {
  const pa = a.split(".").map((x) => Number.parseInt(x, 10));
  const pb = b.split(".").map((x) => Number.parseInt(x, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x < y) return true;
    if (x > y) return false;
  }
  return true;
}

function scriptRefs(body: string): string[] {
  const out: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

export const vulnJsCheck: PassiveCheck = {
  id: "vuln-js",
  label: "vulnerable JavaScript",
  run: (ctx) => {
    const out: PassiveIssue[] = [];
    const seen = new Set<string>();
    for (const ref of scriptRefs(ctx.body)) {
      for (const lib of VULN_JS_LIBS) {
        const m = lib.re.exec(ref);
        const ver = m?.[1];
        if (ver && versionLeq(ver, lib.maxVuln)) {
          const key = `vuln-js-${lib.name.toLowerCase().replace(/\s+/g, "")}-${ver}`;
          if (seen.has(key)) continue;
          seen.add(key);
          out.push({ key, severity: "low", title: `Vulnerable JS: ${lib.name} ${ver}`, detail: `${lib.note} (ref: ${ref}) — presence-only; sink reachability not verified` });
        }
      }
    }
    return out;
  },
};

/** id → check. Selected via --checks (custom list). */
export function passiveChecks(): PassiveCheck[] {
  return [headersCheck(), versionCheck, vulnJsCheck];
}
