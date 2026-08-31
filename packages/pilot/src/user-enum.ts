// User-enumeration oracle (pure): a known-valid username vs a non-existent one must produce a
// DISTINGUISHING marker that appears only for the valid account — not a length delta, and not the
// username echoing back. Used by probe_user_enum; record_finding(user-enumeration) is marker-based.

export interface UserEnumSample {
  status: number;
  body: string;
}

export interface UserEnumHit {
  marker: string;
  reason: string;
}

/** Phrases that mean "this account exists" (wrong password / MFA / lockout) — must NOT appear for an unknown user. */
const VALID_ACCOUNT_RE: ReadonlyArray<RegExp> = [
  /invalid password/i,
  /wrong password/i,
  /incorrect password/i,
  /password is incorrect/i,
  /password does not match/i,
  /account (is )?locked/i,
  /too many (failed )?attempts/i,
  /auth_method/i,
  /"exists"\s*:\s*true/i,
  /"userExists"\s*:\s*true/i,
  /"registered"\s*:\s*true/i,
  /"accountExists"\s*:\s*true/i,
];

function stripUsers(body: string, users: string[]): string {
  let s = body;
  for (const u of users) {
    if (!u) continue;
    s = s.split(u).join("");
    try {
      s = s.split(encodeURIComponent(u)).join("");
    } catch {
      /* ignore */
    }
  }
  return s;
}

function looksVolatile(s: string): boolean {
  if (s.length > 40 && /^[A-Za-z0-9+/=_-]+$/.test(s)) return true;
  return /csrf|nonce|viewstate|requestverificationtoken|authenticity_token/i.test(s);
}

function jsonExclusive(valid: string, invalid: string): string | null {
  const parse = (raw: string): unknown => {
    try {
      return JSON.parse(raw.trim());
    } catch {
      return null;
    }
  };
  const a = parse(valid);
  const b = parse(invalid);
  if (!a || typeof a !== "object" || !b || typeof b !== "object") return null;
  const flat = (obj: unknown, prefix: string, out: Map<string, string>): void => {
    if (obj === null || obj === undefined) return;
    if (typeof obj === "string" || typeof obj === "number" || typeof obj === "boolean") {
      out.set(prefix, String(obj));
      return;
    }
    if (typeof obj !== "object" || Array.isArray(obj)) return;
    for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
      if (k === "__proto__" || k === "constructor" || k === "prototype") continue;
      flat(v, prefix ? `${prefix}.${k}` : k, out);
    }
  };
  const va = new Map<string, string>();
  const ia = new Map<string, string>();
  flat(a, "", va);
  flat(b, "", ia);
  for (const [k, v] of va) {
    if (ia.get(k) === v) continue;
    if (looksVolatile(v) || looksVolatile(k)) continue;
    if (v.length < 1 || v.length > 80) continue;
    const snippet = `"${k.split(".").pop()}":${JSON.stringify(JSON.parse(JSON.stringify(v)))}`;
    // Prefer a snippet that is literally in the valid body (so record_finding's includes() hits).
    if (valid.includes(v) && !invalid.includes(v)) return v.length >= 4 ? v : snippet;
  }
  return null;
}

function exclusiveSnippet(valid: string, invalid: string): string | null {
  const quoted = [...valid.matchAll(/"([^"]{4,80})"/g)].map((m) => m[1]!).filter((s) => !looksVolatile(s) && !invalid.includes(s));
  if (quoted[0]) return quoted[0];
  return null;
}

/** Put `user` into url/body. Needs {{USER}} in url or body, or a query `param` name. */
export function placeUserIdentity(
  url: string,
  body: string | null | undefined,
  param: string | undefined,
  user: string,
): { url: string; body: string | null } | null {
  if (body != null && body.includes("{{USER}}")) return { url, body: body.replaceAll("{{USER}}", user) };
  if (url.includes("{{USER}}")) return { url: url.replaceAll("{{USER}}", encodeURIComponent(user)), body: body ?? null };
  if (param) {
    try {
      const u = new URL(url);
      u.searchParams.set(param, user);
      return { url: u.toString(), body: body ?? null };
    } catch {
      return null;
    }
  }
  return null;
}

/** Find a marker in BOTH valid replays and absent from the invalid-user control. */
export function userEnumMarker(
  invalid: UserEnumSample,
  validA: UserEnumSample,
  validB: UserEnumSample,
  validUser: string,
  invalidUser: string,
): UserEnumHit | null {
  const users = [validUser, invalidUser];
  const iBody = stripUsers(invalid.body, users);
  const aBody = stripUsers(validA.body, users);
  const bBody = stripUsers(validB.body, users);

  if (validA.status === validB.status && validA.status !== invalid.status) {
    const marker = `status:${validA.status}`;
    return { marker, reason: `HTTP ${validA.status} for a valid user vs ${invalid.status} for a non-existent user` };
  }

  for (const re of VALID_ACCOUNT_RE) {
    const ma = aBody.match(re);
    const mb = bBody.match(re);
    if (ma && mb && !re.test(iBody)) return { marker: ma[0], reason: "valid-account phrase absent for the unknown user" };
  }

  const jsonA = jsonExclusive(aBody, iBody);
  if (jsonA && bBody.includes(jsonA) && !iBody.includes(jsonA)) {
    return { marker: jsonA, reason: "JSON field present only for the valid username" };
  }

  const snip = exclusiveSnippet(aBody, iBody);
  if (snip && bBody.includes(snip)) return { marker: snip, reason: "response content exclusive to the valid username (stable across 2 replays)" };

  return null;
}
