// Session glance (pure): dump live Cookie / Bearer / Set-Cookie so the diagnose model can judge
// whether session material LOOKS weak. Not a confirmation oracle — forge / probe_jwt still confirm.

import { parseJwt } from "./jwt.js";

export interface SessionCookie {
  name: string;
  value: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
}

export interface JwtGlance {
  alg: string;
  unsigned: boolean;
  claims: Record<string, unknown>;
}

export interface CookieGlance {
  name: string;
  /** Full enough to judge (JWT header.payload stays readable). */
  value: string;
  httpOnly: boolean | null;
  secure: boolean | null;
  sameSite: string | null;
  structure: "jwt" | "hex" | "base64ish" | "numeric" | "plain";
  jwt?: JwtGlance;
  hints: string[];
}

const IDENTITY_CLAIM_KEYS = new Set([
  "sub",
  "user",
  "username",
  "preferred_username",
  "email",
  "role",
  "roles",
  "admin",
  "isadmin",
  "uid",
  "userid",
  "id",
  "name",
]);

export function parseCookieHeader(header: string): SessionCookie[] {
  const out: SessionCookie[] = [];
  for (const part of header.split(";")) {
    const t = part.trim();
    if (!t) continue;
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    out.push({ name: t.slice(0, eq).trim(), value: t.slice(eq + 1).trim() });
  }
  return out;
}

export function cookieStructure(value: string): CookieGlance["structure"] {
  if (value.split(".").length === 3 && value.length > 20) return "jwt";
  if (/^\d{1,12}$/.test(value)) return "numeric";
  if (/^[0-9a-f]{16,}$/i.test(value)) return "hex";
  if (/^[A-Za-z0-9+/=_-]{16,}$/.test(value)) return "base64ish";
  return "plain";
}

export function peekJwt(token: string): JwtGlance | null {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const alg = typeof parsed.header.alg === "string" ? parsed.header.alg : "";
  const unsigned = !parsed.signature || /^(none|None|NONE)$/.test(alg);
  const claims: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(parsed.payload)) {
    if (IDENTITY_CLAIM_KEYS.has(k.toLowerCase())) claims[k] = v;
  }
  if (typeof parsed.payload.exp === "number") claims.exp = parsed.payload.exp;
  return { alg: alg || "?", unsigned, claims };
}

export function clipValue(value: string, max = 240): string {
  if (value.length <= max) return value;
  return `${value.slice(0, max)}…`;
}

/** Hints for the model — not a verdict. Role name + known usernames (configured creds). */
export function cookieHints(name: string, value: string, identities: readonly string[]): string[] {
  const hints: string[] = [];
  const v = value.toLowerCase();
  const n = name.toLowerCase();
  const sessionish = /sess|sid|auth|token|jwt|user/.test(n);
  for (const id of identities) {
    const idl = id.toLowerCase().trim();
    if (!idl || idl.length < 2) continue;
    if (v === idl || v.includes(idl)) hints.push(`value equals/contains identity ${JSON.stringify(id)}`);
  }
  const st = cookieStructure(value);
  if (st === "plain" && value.length < 12) hints.push("short plaintext value (easy to guess/swap)");
  if (st === "numeric" && sessionish) hints.push("numeric value on a session-ish cookie (user id as session?)");
  if (st === "jwt") {
    const j = peekJwt(value);
    if (j?.unsigned) hints.push(`JWT alg=${j.alg} with empty/none signature`);
    else if (j) hints.push(`JWT alg=${j.alg} — judge claims; probe_jwt if this is also the Bearer`);
  }
  return hints;
}

export function glanceCookie(c: SessionCookie, identities: readonly string[]): CookieGlance {
  const structure = cookieStructure(c.value);
  const jwt = structure === "jwt" ? peekJwt(c.value) ?? undefined : undefined;
  const httpOnly = c.httpOnly;
  const hints = [...cookieHints(c.name, c.value, identities)];
  if (httpOnly === false && /sess|sid|auth|token|jwt/.test(c.name.toLowerCase())) hints.push("session-ish cookie lacks HttpOnly");
  return {
    name: c.name,
    value: clipValue(c.value),
    httpOnly: httpOnly === undefined ? null : httpOnly,
    secure: c.secure === undefined ? null : c.secure,
    sameSite: c.sameSite ?? null,
    structure,
    ...(jwt ? { jwt } : {}),
    hints,
  };
}

export function formatRequestDump(method: string, url: string, cookie: string, authorization: string): string {
  let host = "";
  let target = url;
  try {
    const u = new URL(url);
    host = u.host;
    target = `${u.pathname}${u.search}` || "/";
  } catch {
    /* leave as-is */
  }
  const lines = [`${method.toUpperCase()} ${target} HTTP/1.1`];
  if (host) lines.push(`Host: ${host}`);
  if (cookie) lines.push(`Cookie: ${cookie}`);
  if (authorization) lines.push(`Authorization: ${authorization}`);
  return lines.join("\n");
}

// ── Deterministic session-cookie attribute audit (absence class, probe_headers-style) ──
// A missing Set-Cookie attribute needs no control differential — two stable GETs of the same URL
// are the evidence (exactly like missing security headers). Pure: analyze_session and record_finding's
// gate both call these so the recorded finding is re-verified against the cited responses.

/** Session-ish cookie names (analyze_session's deterministic checks apply to these only). */
const SESSION_COOKIE_NAME_RE = /sess|sid|auth|token|jwt|remember/i;
/** Noise names — NEVER session-cookie findings even when the name matches (a missing HttpOnly on a
 *  locale/csrf/analytics cookie is not a session finding). CSRF double-submit cookies must never be checked. */
const COOKIE_NOISE_NAME_RE = /locale|lang|theme|currency|tz|timezone|csrf|xsrf|_ga|_gid|consent|style|ui/i;

export function isSessionCookieName(name: string): boolean {
  return SESSION_COOKIE_NAME_RE.test(name) && !COOKIE_NOISE_NAME_RE.test(name);
}

/** rule keys of the deterministic session-cookie checks (record_finding param values). */
export type SessionAttrKey = "secure" | "httponly" | "samesite" | "domain-scope";
export const SESSION_COOKIE_ATTR_KEYS: ReadonlySet<string> = new Set<SessionAttrKey>(["secure", "httponly", "samesite", "domain-scope"]);

/** One parsed Set-Cookie line: name=value plus its attributes (lowercased names; "" for valueless flags). */
export interface SetCookieLine {
  name: string;
  value: string;
  /** lowercase attribute name ("secure", "httponly", "samesite", "domain", "path", "expires", ...) → trimmed value */
  attrs: Record<string, string>;
}

/** Parse a (possibly newline-joined) Set-Cookie header value into lines. Split each line on ";" only —
 *  NEVER on commas: an Expires date ("Expires=Wed, 21 Oct 2015 07:28:00 GMT") contains one. */
export function parseSetCookieLines(setCookie: string): SetCookieLine[] {
  const out: SetCookieLine[] = [];
  for (const line of setCookie.split(/\r?\n/)) {
    if (!line.trim()) continue;
    const parts = line.split(";");
    const nv = parts[0] ?? "";
    const eq = nv.indexOf("=");
    if (eq <= 0) continue; // no name=value → not a Set-Cookie pair
    const attrs: Record<string, string> = {};
    for (const part of parts.slice(1)) {
      const t = part.trim();
      if (!t) continue;
      const aeq = t.indexOf("=");
      if (aeq < 0) attrs[t.toLowerCase()] = "";
      else attrs[t.slice(0, aeq).trim().toLowerCase()] = t.slice(aeq + 1).trim();
    }
    out.push({ name: nv.slice(0, eq).trim(), value: nv.slice(eq + 1).trim(), attrs });
  }
  return out;
}

/** Domain attribute is a PARENT of the request host (cookie flows to sibling subdomains)? */
function isParentDomain(domainAttr: string, host: string): boolean {
  if (!host) return false;
  const d = domainAttr.replace(/^\./, "").toLowerCase();
  if (!d || d === host) return false; // same host = not a widening
  return host.endsWith(`.${d}`);
}

export interface SessionAttrFinding {
  key: SessionAttrKey;
  cookieName: string;
  severity: "low" | "medium";
}

export interface SessionCookieFlagAudit {
  findings: SessionAttrFinding[];
  /** attributes that could NOT be determined — reported "unknown", never inferred. */
  unknown: string[];
  /** identified session-cookie names (checked; everything else is noise by construction). */
  sessionCookies: string[];
}

/** Audit the session cookie's attributes (absence class, session cookie ONLY):
 *  secure (missing Secure on an https target — skipped on non-TLS, like HSTS) / httponly / samesite
 *  (absent or SameSite=None; None without Secure also trips secure) / domain-scope (Domain = a parent
 *  of the request host). Path and Expires/Max-Age are FP noise and never checked. When the response
 *  issues no Set-Cookie for a session cookie, fall back to the driver jar's httpOnly/secure/sameSite
 *  fields when known; anything still undetermined is reported "unknown" — never inferred. */
export function auditSessionCookieFlags(opts: {
  /** raw (possibly newline-joined) Set-Cookie response header value */
  setCookie: string;
  /** cookie names sent in the request Cookie header (also eligible for session identification) */
  requestCookieNames: readonly string[];
  /** the request URL (TLS check for `secure`, host for `domain-scope`) */
  url: string;
  /** driver cookie jar — fallback when the response issues no Set-Cookie */
  jar?: readonly SessionCookie[];
}): SessionCookieFlagAudit {
  const findings: SessionAttrFinding[] = [];
  const unknown: string[] = [];
  const tls = /^https:/i.test(opts.url.trim());
  let host = "";
  try {
    host = new URL(opts.url).hostname.toLowerCase();
  } catch {
    /* leave "" — domain-scope simply cannot be judged */
  }
  const lines = parseSetCookieLines(opts.setCookie);
  const byLower = new Map<string, SetCookieLine>();
  for (const l of lines) {
    if (isSessionCookieName(l.name)) byLower.set(l.name.toLowerCase(), l);
  }
  // Candidates: session cookies issued by the response first, then session names seen in the request
  // Cookie header (the cookie exists even when this response doesn't re-issue it).
  const order: string[] = [];
  const display = new Map<string, string>();
  const addCandidate = (name: string): void => {
    const lower = name.toLowerCase();
    if (!lower || display.has(lower)) return;
    order.push(lower);
    display.set(lower, name);
  };
  for (const l of byLower.values()) addCandidate(l.name);
  for (const n of opts.requestCookieNames) if (isSessionCookieName(n)) addCandidate(n);
  for (const lower of order) {
    const name = display.get(lower)!;
    const line = byLower.get(lower);
    if (line) {
      // Attributes straight from the issuing Set-Cookie — deterministic.
      if (tls && !("secure" in line.attrs)) findings.push({ key: "secure", cookieName: name, severity: "medium" });
      if (!("httponly" in line.attrs)) findings.push({ key: "httponly", cookieName: name, severity: "medium" });
      const ss = line.attrs["samesite"];
      if (ss === undefined || ss === "" || ss.toLowerCase() === "none") findings.push({ key: "samesite", cookieName: name, severity: "low" });
      const dom = line.attrs["domain"];
      if (dom && isParentDomain(dom, host)) findings.push({ key: "domain-scope", cookieName: name, severity: "low" });
      continue;
    }
    // No Set-Cookie for this cookie in the response → driver jar fallback (known fields only).
    const jarCookie = opts.jar?.find((c) => c.name.toLowerCase() === lower);
    if (!jarCookie) {
      unknown.push(`${name}: flags unknown (no Set-Cookie in the response; browser jar has no entry)`);
      continue;
    }
    if (tls && jarCookie.secure === false) findings.push({ key: "secure", cookieName: name, severity: "medium" });
    else if (tls && jarCookie.secure === undefined) unknown.push(`${name}: secure unknown (no Set-Cookie; jar lacks the flag)`);
    if (jarCookie.httpOnly === false) findings.push({ key: "httponly", cookieName: name, severity: "medium" });
    else if (jarCookie.httpOnly === undefined) unknown.push(`${name}: httponly unknown (no Set-Cookie; jar lacks the flag)`);
    const jss = jarCookie.sameSite;
    if (jss == null || jss === "") unknown.push(`${name}: samesite unknown (no Set-Cookie; jar lacks the flag)`);
    else if (jss.toLowerCase() === "none") findings.push({ key: "samesite", cookieName: name, severity: "low" });
    unknown.push(`${name}: domain-scope unknown (no Set-Cookie in the response)`);
  }
  return { findings, unknown, sessionCookies: order.map((lower) => display.get(lower)!) };
}
