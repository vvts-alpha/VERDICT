// Technology-stack fingerprinting (deterministic, no LLM). From the response's headers/Cookie/meta/script-src
// it structurally extracts the "name + version" of server, middleware, language, framework, CMS, and frontend libraries.
// Of the known-vuln matching, **JS libraries are annotated deterministically via the VULN_JS_LIBS catalog**, while server/middleware/language
// just collect versions, evaluated by pilot's A06 stage (the LLM's CVE knowledge). Collection is reliable; evaluation is knowledge-dependent.

import { VULN_JS_LIBS, versionLeq } from "./passive.js";

export type TechKind = "server" | "language" | "framework" | "cms" | "frontend-lib";

export interface TechComponent {
  kind: TechKind;
  name: string;
  /** the version obtained (e.g. "2.4.41"). null if there's only a banner with no version. */
  version: string | null;
  /** detection source (header name / "cookie" / "meta generator" / "script src"). */
  source: string;
  /** the raw clue (basis for the report/evidence). */
  evidence: string;
  /** note when it matches a known-vulnerable version (JS library catalog only; empty means unmatched = evaluated at the LLM stage). */
  knownVuln?: string;
}

export interface TechSample {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** "Apache/2.4.41 (Ubuntu)" / "nginx/1.18.0" / "PHP/7.4.3" → { name, version } */
function splitBanner(v: string): { name: string; version: string | null } {
  const m = /^([A-Za-z][\w.+-]*?)[/ ]v?(\d+(?:\.\d+){0,3})/.exec(v.trim());
  if (m) return { name: m[1]!, version: m[2]! };
  const first = v.trim().split(/[\s(;,]/)[0] ?? v.trim();
  return { name: first, version: null };
}

// header → kind (splitBanner splits the banner into name+version)
const BANNER_HEADERS: { header: string; kind: TechKind }[] = [
  { header: "server", kind: "server" },
  { header: "x-powered-by", kind: "framework" },
  { header: "via", kind: "server" },
];

// headers that carry the version directly (the value itself is the version)
const VERSION_VALUE_HEADERS: { header: string; kind: TechKind; name: string }[] = [
  { header: "x-aspnet-version", kind: "framework", name: "ASP.NET" },
  { header: "x-aspnetmvc-version", kind: "framework", name: "ASP.NET MVC" },
  { header: "x-generator", kind: "cms", name: "(generator)" },
  { header: "microsoftsharepointteamservices", kind: "cms", name: "Microsoft SharePoint" },
];

// Set-Cookie name → framework/language (no version, but reveals "what it's built with")
const COOKIE_TECH: { re: RegExp; kind: TechKind; name: string }[] = [
  { re: /\bPHPSESSID\b/i, kind: "language", name: "PHP" },
  { re: /\bJSESSIONID\b/i, kind: "language", name: "Java (servlet container)" },
  { re: /\bconnect\.sid\b/i, kind: "framework", name: "Express / Node.js" },
  { re: /\blaravel_session\b/i, kind: "framework", name: "Laravel (PHP)" },
  { re: /\bci_session\b/i, kind: "framework", name: "CodeIgniter (PHP)" },
  { re: /\b_session_id\b/i, kind: "framework", name: "Ruby on Rails" },
  { re: /\bASP\.NET_SessionId\b/i, kind: "framework", name: "ASP.NET" },
  { re: /\bcsrftoken\b/i, kind: "framework", name: "Django" },
];

function scriptRefs(body: string): string[] {
  const out: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

/**
 * Extract and deduplicate technology components from one or more response samples.
 * JS libraries are matched against VULN_JS_LIBS; a known-vulnerable version gets a knownVuln annotation (deterministic).
 */
export function fingerprintTech(samples: ReadonlyArray<TechSample>): TechComponent[] {
  const byKey = new Map<string, TechComponent>();
  const add = (c: TechComponent): void => {
    const key = `${c.kind}|${c.name.toLowerCase()}|${c.version ?? ""}`;
    if (!byKey.has(key)) byKey.set(key, c);
  };

  for (const s of samples) {
    const h = s.headers;
    // banner headers (Server / X-Powered-By / Via)
    for (const { header, kind } of BANNER_HEADERS) {
      const v = h[header];
      if (!v) continue;
      // X-Powered-By may have multiple values like "PHP/7.4.3" or "Express"
      for (const part of v.split(",")) {
        const { name, version } = splitBanner(part);
        if (!name) continue;
        add({ kind, name, version, source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // headers whose value is the version itself
    for (const { header, kind, name } of VERSION_VALUE_HEADERS) {
      const v = h[header];
      if (v && /\d/.test(v)) {
        const nm = name === "(generator)" ? splitBanner(v).name || "generator" : name;
        add({ kind, name: nm, version: splitBanner(v).version ?? v.trim().slice(0, 40), source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // Set-Cookie name → framework lineage
    const setCookie = h["set-cookie"] ?? "";
    if (setCookie) {
      for (const c of COOKIE_TECH) {
        if (c.re.test(setCookie)) add({ kind: c.kind, name: c.name, version: null, source: "cookie", evidence: `Set-Cookie name matched ${c.re.source}` });
      }
    }
    // <meta name="generator" content="WordPress 6.4">
    const meta = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(s.body);
    if (meta?.[1]) {
      const { name, version } = splitBanner(meta[1]);
      add({ kind: "cms", name: name || meta[1], version, source: "meta generator", evidence: `<meta generator>: ${meta[1]}`.slice(0, 200) });
    }
    // frontend libraries (name+version from the script src filename; knownVuln if a known-vulnerable version)
    for (const ref of scriptRefs(s.body)) {
      for (const lib of VULN_JS_LIBS) {
        const m = lib.re.exec(ref);
        const ver = m?.[1];
        if (!ver) continue;
        add({
          kind: "frontend-lib",
          name: lib.name,
          version: ver,
          source: "script src",
          evidence: ref.slice(0, 200),
          ...(versionLeq(ver, lib.maxVuln) ? { knownVuln: lib.note } : {}),
        });
      }
    }
    // SharePoint hive paths (/_layouts/15/, corev15.css) identify the PRODUCT, not a patch version.
    // 2016 / 2019 / Subscription / Online still serve the 15 hive for compatibility — not "SharePoint 2013".
    if (
      /\/_layouts\/\d+\//.test(s.body) ||
      /corev\d+\.css/i.test(s.body) ||
      /\/_catalogs\/masterpage\//i.test(s.body)
    ) {
      add({
        kind: "cms",
        name: "Microsoft SharePoint",
        version: null,
        source: "path",
        evidence: "/_layouts/ or corevN.css (hive path is not a patch version)",
      });
    }
  }
  return [...byKey.values()];
}

function lowerHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function compsOf(headers: Record<string, string>, body: string): TechComponent[] {
  return fingerprintTech([{ url: "https://local/", headers: lowerHeaders(headers), body: body ?? "" }]);
}

/** True when fingerprinting the response yields at least one component WITH a version (Apache/2.4.41, jquery-1.12.4).
 *  `Server: BigIP` / a cookie name / a product family with no version is false. */
export function hasVersionedComponent(headers: Record<string, string>, body: string): boolean {
  return compsOf(headers, body).some((c) => Boolean(c.version));
}

/** Does the writeup cite this fingerprinted version (full string, or major.minor)? */
function writeupCitesVersion(writeup: string, version: string): boolean {
  if (!version) return false;
  if (writeup.includes(version)) return true;
  const mm = /^(\d+\.\d+)/.exec(version);
  if (!mm) return false;
  const esc = mm[1]!.replace(/\./g, "\\.");
  return new RegExp(`(?<!\\d)${esc}(?!\\d)`).test(writeup);
}

/** Product-family CVE history with no version (F5 BIG-IP + CVE-2020-5902 "may apply") is not A06.
 *  A hive path (/_layouts/15/) is not a version — the writeup must cite a version that fingerprinting actually extracted. */
const VERSIONLESS_WRITEUP =
  /undisclosed version|version\s+(?:is\s+|was\s+)?(?:not\s+|un)disclosed|no version (?:is |was )?(?:leaked|disclosed)|version remains unknown|\bunknown version\b|version unknown|product family has|patch level (?:could not|cannot|unverified)/i;

export function isVersionlessComponentLead(writeup: string, headers: Record<string, string>, body: string): boolean {
  if (VERSIONLESS_WRITEUP.test(writeup)) return true;
  const versioned = compsOf(headers, body).filter((c) => c.version);
  if (versioned.length === 0) return true;
  return !versioned.some((c) => writeupCitesVersion(writeup, c.version!));
}

/** Format TechComponent[] into a human-readable table (for the LLM prompt / report). */
export function formatTechInventory(components: ReadonlyArray<TechComponent>): string[] {
  return components.map(
    (c) =>
      `- [${c.kind}] ${c.name}${c.version ? ` ${c.version}` : " (version unknown)"} — via ${c.source}` +
      (c.knownVuln ? `  ⚠ KNOWN: ${c.knownVuln}` : ""),
  );
}

/** Detected stack → hints for the attack classes to target (deterministic, pentest knowledge). Used to inject the early
 *  fingerprint result into the plan so the methodology is tech-aware. Empty array = no specific hints (keep the structure-based plan). */
export function stackAttackHints(components: ReadonlyArray<TechComponent>): string[] {
  const hay = components.map((c) => `${c.name} ${c.kind}`).join(" | ").toLowerCase();
  const hints: string[] = [];
  const add = (re: RegExp, hint: string): void => {
    if (re.test(hay)) hints.push(hint);
  };
  add(
    /jinja|flask|django|twig|freemarker|velocity|thymeleaf|handlebars|nunjucks|mako|smarty|\berb\b/,
    "TEMPLATE ENGINE present → run probe_ssti on EVERY reflected/rendered param (even when HTML-escaped); SSTI is RCE-class here, so plan ssti on any screen with reflected input.",
  );
  add(
    /\bphp\b|laravel|codeigniter|symfony/,
    "PHP → plan path-traversal/LFI (incl. php://filter source read), type-juggling on loose compares (==, auth checks), and unserialize() deserialization on any serialized/base64 input.",
  );
  add(/rails|ruby/, "Rails/Ruby → plan mass-assignment (inject extra model attrs e.g. role/admin), ERB SSTI, and Marshal deserialization.");
  add(
    /express|node\.js|next\.js|nest/,
    "Node/Express → plan prototype pollution (__proto__/constructor in JSON & query), NoSQL injection ($gt/$ne/$where operators), and SSTI if pug/handlebars render user input.",
  );
  add(/spring|\bjava\b|tomcat|jsp|servlet/, "Java/Spring → plan SpEL SSTI (${...} / #{...} / T(...)), Java deserialization, and probe exposed /actuator (env/heapdump) endpoints.");
  add(/wordpress|drupal|joomla/, "CMS → probe known-CVE endpoints (xmlrpc.php, wp-json/, admin-ajax.php) and enumerate plugin/theme versions for CVEs.");
  add(/asp\.net|\biis\b|kestrel/, "ASP.NET/IIS → plan ViewState (__VIEWSTATE) deserialization, path-traversal, and Razor SSTI.");
  return hints;
}
