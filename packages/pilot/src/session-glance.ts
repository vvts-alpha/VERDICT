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
