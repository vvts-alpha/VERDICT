// General-purpose impact oracle (deterministic, no LLM). Decides whether an exploit's response shows a "concrete impact".
// Not specific to CTF FLAG{}, but generalized to what carries value directly in real engagements: secrets / file leaks / command output /
// other users' data. The content-side counterpart of effectMarker that promotes a probe's suspected to confirmed (routed through checkLogicEvidence).
// FP suppression is two-stage: (1) exclude documentation placeholders, (2) anti-ambient = exclude anything already present in the baseline (control).
// Same as checkLogicEvidence's "a marker must not appear in the control" principle. The CTF-flag regex applies only when ctx.flagRegex is set (default OFF).

import type { Severity } from "@veritas/core";

export type ImpactKind = "file-leak" | "source-leak" | "secret" | "command-output" | "cross-user" | "ctf-flag";

export interface ImpactContext {
  /** control/baseline response. A marker already present here is treated as ambient and does not fire (FP suppression). */
  baselineBody?: string;
  /** the requested victim ID. If present in the response and the attacker's own ID is not, it's cross-user. */
  requestedIdentity?: string;
  /** the attacker's own ID (so their own data isn't mis-flagged as cross-user). */
  sessionIdentity?: string;
  /** a flag regex passed only for CTF/benchmarks. Default undefined = ctf-flag disabled (don't bring CTF coupling into real engagements). */
  flagRegex?: RegExp;
}

export interface ImpactSignal {
  kind: ImpactKind;
  severity: Severity;
  /** the actual marker in the response that showed the impact (reusable as effectMarker). */
  marker: string;
  detail: string;
}

interface Detector {
  kind: ImpactKind;
  severity: Severity;
  re: RegExp;
  detail: string;
}

// Documentation examples / placeholders (not real secrets).
const PLACEHOLDERS: RegExp[] = [
  /AKIAIOSFODNN7EXAMPLE/i,
  /your[-_]?(api[-_]?)?(key|secret|token)/i,
  /\bexample\b/i,
  /x{8,}/i,
  /\b0{8,}\b/,
  /changeme|placeholder|<your|dummy|sample[-_]?key|test[-_]?key|s3cr3t-example/i,
];

const DETECTORS: Detector[] = [
  // ── file leak ──
  { kind: "file-leak", severity: "high", re: /\broot:.*?:0:0:/, detail: "/etc/passwd contents (root:…:0:0:)" },
  { kind: "file-leak", severity: "high", re: /\[fonts\]|\[extensions\]|for 16-bit app support/i, detail: "win.ini contents" },
  // ── source/config leak ──
  { kind: "source-leak", severity: "high", re: /<\?php[\s\S]{0,30}/, detail: "PHP source disclosure" },
  { kind: "source-leak", severity: "high", re: /\b(DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*[=:]\s*\S{6,}/i, detail: "config/.env secret" },
  // ── secrets ──
  { kind: "secret", severity: "high", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, detail: "private key" },
  { kind: "secret", severity: "high", re: /\bAKIA[0-9A-Z]{16}\b/, detail: "AWS access key id" },
  { kind: "secret", severity: "high", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, detail: "Slack token" },
  { kind: "secret", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/, detail: "Google API key" },
  { kind: "secret", severity: "high", re: /\bsk_live_[0-9A-Za-z]{20,}\b/, detail: "Stripe live secret key" },
  { kind: "secret", severity: "high", re: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/, detail: "GitHub token" }, // ghp_/gho_/ghu_/ghs_/ghr_
  { kind: "secret", severity: "high", re: /\bglpat-[0-9A-Za-z_-]{20,}\b/, detail: "GitLab personal access token" },
  { kind: "secret", severity: "high", re: /\bnpm_[0-9A-Za-z]{36}\b/, detail: "npm access token" },
  { kind: "secret", severity: "high", re: /\bSG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}\b/, detail: "SendGrid API key" },
  { kind: "secret", severity: "high", re: /\bGOCSPX-[0-9A-Za-z_-]{20,}\b/, detail: "Google OAuth client secret" },
  { kind: "secret", severity: "high", re: /\bsk-proj-[0-9A-Za-z_-]{20,}\b/, detail: "OpenAI API key" }, // sk-proj- (specific prefix; avoids bare sk- FP)
  { kind: "secret", severity: "medium", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/, detail: "JWT" },
  { kind: "secret", severity: "high", re: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@/i, detail: "credentials embedded in URL (user:pass@host)" },
  { kind: "secret", severity: "medium", re: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, detail: "bcrypt password hash" },
  // ── command output (RCE/CMDi evidence) ──
  { kind: "command-output", severity: "high", re: /\buid=\d+\([^)]*\)\s+gid=\d+\(/, detail: "id command output (uid=…gid=…)" },
  { kind: "command-output", severity: "medium", re: /Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i, detail: "Windows dir/command output" },
];

/** Does `id` appear as a DISTINCT token in `body` (not an incidental substring of a longer run)? Guards the cross-user
 *  oracle: a bare id like "1002" must not match inside "3100241" — it needs a non-alphanumeric boundary on both sides.
 *  This kills the false-cross-user bug where a victim id matched incidentally inside an unrelated number, letting a
 *  self-owned / public object confirm as IDOR. (No length floor — single-digit object ids are legitimate.) */
export function identityAppears(body: string, id: string): boolean {
  if (!id) return false;
  const esc = id.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_])${esc}([^A-Za-z0-9_]|$)`).test(body);
}

/** How much of another user's object is actually private. A tenant people-picker card (displayName + work
 *  email + photo + tenant) is usually intended; phone / home address / SSN / DOB / extra internal id /
 *  order-basket contents are the IDOR that pays. */
export type CrossUserBodyClass = "sensitive-pii" | "private-object" | "public-directory" | "identity-only";

export interface CrossUserBodyClassification {
  class: CrossUserBodyClass;
  detail: string;
}

const normKey = (k: string): string => k.toLowerCase().replace(/[-_]/g, "");

const PUBLIC_PROFILE_KEYS = new Set([
  "id", "uuid", "guid",
  "name", "displayname", "fullname", "firstname", "lastname",
  "username", "nickname", "nick", "handle", "slug", "alias",
  "avatar", "avatarurl", "picture", "photo", "photourl", "image", "imageurl", "profileimage", "thumbnail",
  "bio", "about", "title", "headline", "pronouns", "tagline",
  "followers", "following", "posts", "likes", "verified", "badge", "premium",
  "website", "url", "href", "link", "profileurl",
  "createdat", "updatedat", "joinedat", "created", "updated",
  "location", "city", "country", "region", "locale", "language", "timezone",
  "role", "status", "type", "kind", "active", "enabled", "isdeleted", "isactive", "isadmin",
  "cover", "banner", "color", "theme",
  // Tenant people-picker: work email + tenant + photo are the directory card, not a High IDOR.
  "email", "emailaddress", "mail", "emailaddr",
  "tenant", "tenantid", "tenantname", "org", "orgid", "organization",
]);
const PERSON_MARKERS = new Set([
  "name", "displayname", "fullname", "firstname", "lastname",
  "username", "nickname", "handle", "slug", "alias", "avatar", "avatarurl", "bio", "about", "email",
]);
const SENSITIVE_PII_KEYS = new Set([
  "phone", "phonenumber", "tel", "telephone", "mobile", "cell", "cellphone", "fax",
  "address", "street", "street1", "street2", "postal", "postalcode", "zip", "zipcode", "postcode", "prefecture", "building",
  "ssn", "sin", "nin", "nationalid", "passport", "taxid", "mynumber",
  "dob", "dateofbirth", "birthdate", "birthday", "birth",
  "password", "passwordhash", "secret",
  "iban", "accountnumber", "cardnumber", "creditcard", "cvv",
]);
// Substrings that mark a sensitive field even inside a compound camelCase key (shippingAddress / billingAddress /
// phoneNo / homeStreet / dateOfBirth / cardNumber). Checked only AFTER PUBLIC_PROFILE_KEYS `continue`, so whitelisted
// compounds (emailAddress) are unaffected. Kept specific to avoid over-marking benign keys.
const SENSITIVE_PII_SUBSTRINGS = [
  "phone", "address", "street", "postal", "postcode", "zipcode",
  "ssn", "passport", "taxid", "nationalid", "dateofbirth", "birthdate", "creditcard", "cardnumber", "iban",
];
const INTERNAL_ID_KEYS = new Set([
  "userid", "uid", "accountid", "customerid", "memberid", "employeeid", "staffid", "internalid", "customerno", "employeeno",
]);
const PRIVATE_OBJECT_KEYS = new Set([
  "order", "orders", "orderid", "basket", "basketid", "cart", "invoice", "receipt", "payment",
  "product", "products", "item", "items", "lineitems",
  "message", "messages", "filename", "file", "document", "attachment",
  "amount", "total", "price", "quantity", "qty", "balance", "wallet", "coupon", "paymentmethod",
  "owner", "ownerid",
]);

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/;
const MAILTO_RE = /mailto:/i;
const TEL_HREF_RE = /\btel:/i;

function tryParseJson(body: string): unknown {
  const t = body.trim();
  const i = t.search(/[\[{]/);
  if (i < 0) return undefined;
  try {
    return JSON.parse(t.slice(i));
  } catch {
    return undefined;
  }
}

function jsonRecords(v: unknown, depth = 0): Array<Record<string, unknown>> {
  if (depth > 4 || v == null) return [];
  if (Array.isArray(v)) return v.flatMap((x) => jsonRecords(x, depth + 1)).slice(0, 3);
  if (typeof v !== "object") return [];
  const o = v as Record<string, unknown>;
  const nest = o.data ?? o.user ?? o.profile ?? o.result ?? o.payload;
  if (nest && typeof nest === "object") return jsonRecords(nest, depth + 1);
  return [o];
}

function classifyJsonRecord(rec: Record<string, unknown>, victimId: string | undefined): CrossUserBodyClassification | null {
  let person = false;
  let pii: string | undefined;
  let internal: string | undefined;
  let priv: string | undefined;
  for (const [k, val] of Object.entries(rec)) {
    const n = normKey(k);
    if (PERSON_MARKERS.has(n)) person = true;
    if (PUBLIC_PROFILE_KEYS.has(n)) continue;
    const sval = val == null || typeof val === "object" ? "" : String(val);
    if (INTERNAL_ID_KEYS.has(n)) {
      if (victimId && sval === String(victimId)) continue; // echoed lookup key, not an extra internal id
      internal = k;
      continue;
    }
    if (SENSITIVE_PII_KEYS.has(n) || SENSITIVE_PII_SUBSTRINGS.some((s) => n.includes(s))) {
      // Compound key names (shippingAddress, billingAddress, phoneNo, homeStreet, dateOfBirth) don't hit the exact set —
      // normKey doesn't split camelCase — so also match sensitive SUBSTRINGS. PUBLIC_PROFILE_KEYS already `continue`d
      // above, so whitelisted compounds like emailAddress never reach here.
      pii = k;
      continue;
    }
    if (PRIVATE_OBJECT_KEYS.has(n)) {
      priv = k;
      continue;
    }
    if (typeof val === "string" && EMAIL_RE.test(val) && !person) pii = k;
  }
  if (pii) return { class: "sensitive-pii", detail: `private field '${pii}'` };
  if (internal) return { class: "sensitive-pii", detail: `extra internal id '${internal}'` };
  if (priv) return { class: "private-object", detail: `private object field '${priv}'` };
  if (person) return { class: "public-directory", detail: "tenant people-picker card (display name / work email / photo / tenant)" };
  return null;
}

/**
 * Public store / branch / dealer locator HTML (Valero LocationDetails, "Find a Station", og:type=place).
 * Sequential store ids + unauthenticated 200 is how a store finder works — not IDOR. Must run BEFORE the
 * HTML phone/address heuristics: a gas-station page advertises its address and tel: on purpose.
 */
export function looksLikePublicCatalogPage(body: string): boolean {
  const head = body.slice(0, 12_000);
  if (/property=["']og:type["'][^>]*content=["']place["']/i.test(head) || /content=["']place["'][^>]*property=["']og:type["']/i.test(head))
    return true;
  if (/property=["']place:location:(?:latitude|longitude)["']/i.test(head)) return true;
  if (/itemtype=["']https?:\/\/schema\.org\/(?:LocalBusiness|Store|GasStation|Restaurant|Place)\b/i.test(head)) return true;
  const locChrome = /find a station|find a store|store locator|dealer locator|branch locator|gas station near you|locationdetails/i.test(head);
  const coords = /place:location:latitude|property=["']place:location/i.test(head);
  return locChrome && coords;
}

/**
 * Classify another user's response body. A tenant people-picker card (displayName + work email + photo +
 * tenant) is usually intended, not IDOR. A public store/location catalog (og:type place, Find a Station)
 * is the same: intended directory, not broken access control. Phone / home address / SSN / DOB / extra
 * internal id, or order/basket/message contents, is the IDOR worth reporting. Non-JSON / unclassified
 * bodies stay `identity-only` (existing cross-user-id behaviour).
 */
export function classifyCrossUserBody(body: string, victimId?: string): CrossUserBodyClassification {
  if (looksLikePublicCatalogPage(body))
    return { class: "public-directory", detail: "public store/location catalog (og:type place / store locator)" };
  const parsed = tryParseJson(body);
  if (parsed !== undefined) {
    let directory: CrossUserBodyClassification | undefined;
    for (const rec of jsonRecords(parsed)) {
      const hit = classifyJsonRecord(rec, victimId);
      if (!hit) continue;
      if (hit.class !== "public-directory") return hit;
      directory = hit;
    }
    if (directory) return directory;
  }
  if (EMAIL_RE.test(body) || MAILTO_RE.test(body)) return { class: "sensitive-pii", detail: "email address in body" };
  if (TEL_HREF_RE.test(body) || /"(phone|tel|mobile)"\s*:/i.test(body)) return { class: "sensitive-pii", detail: "phone in body" };
  if (/\b(street address|postal code|zip code)\b/i.test(body)) return { class: "sensitive-pii", detail: "address in body" };
  if (/\b(order|receipt|invoice|basket|cart|payment|balance)\b/i.test(body)) return { class: "private-object", detail: "private object wording" };
  return { class: "identity-only", detail: "victim id present, no profile/PII shape" };
}

function aizaKeysIn(body: string, marker?: string): string[] {
  const keyRe = /\bAIza[0-9A-Za-z_-]{35}\b/g;
  if (marker && /^AIza[0-9A-Za-z_-]{35}$/.test(marker)) return [marker];
  return [...body.matchAll(keyRe)].map((m) => m[0]);
}

function windowAround(body: string, token: string, before: number, after: number): string | null {
  const i = body.indexOf(token);
  if (i < 0) return null;
  return body.slice(Math.max(0, i - before), i + token.length + after);
}

/** Maps JavaScript API keys in `maps.googleapis.com/maps/api/js?key=` are public by design (HTTP-referrer
 *  restrictions in Google Cloud). They are not secret-exposure. Server-side AIza keys (.env, JSON config)
 *  still fire. */
export function isBrowserGoogleMapsApiKey(body: string, marker?: string): boolean {
  const keys = aizaKeysIn(body, marker);
  if (keys.length === 0) return false;
  return keys.every((k) => {
    const win = windowAround(body, k, 320, 24);
    return !!win && /maps\.googleapis\.com\/maps\/api\/js/i.test(win);
  });
}

/** Firebase *web* apiKey in firebaseConfig / initializeApp is public by design (security is Security Rules, not hiding the key). */
export function isFirebaseWebApiKey(body: string, marker?: string): boolean {
  const keys = aizaKeysIn(body, marker);
  if (keys.length === 0) return false;
  return keys.every((k) => {
    const win = windowAround(body, k, 400, 400);
    return !!win && /firebase(?:app)?\.com|firebase\.initializeApp|["']authDomain["']|measurementId|messagingSenderId/i.test(win);
  });
}

/** reCAPTCHA *site* keys (6L…) next to grecaptcha are public by design. Secret keys are 6L… but live in server env, not this widget. */
export function isRecaptchaSiteKey(body: string, marker?: string): boolean {
  const re = /\b6L[0-9A-Za-z_-]{30,40}\b/g;
  const keys = marker && /^6L[0-9A-Za-z_-]{30,40}$/.test(marker) ? [marker] : [...body.matchAll(re)].map((m) => m[0]);
  if (keys.length === 0) return false;
  return keys.every((k) => {
    const win = windowAround(body, k, 280, 80);
    return !!win && /recaptcha|grecaptcha|g-recaptcha/i.test(win);
  });
}

/** Client credentials that are *supposed* to be in HTML/JS. .env / `const KEY=` without this context still fires. */
export function isPublicByDesignClientCredential(body: string, marker?: string): boolean {
  // A supplied marker IS the cited secret. If it is not itself a known public-by-design key format (AIza… Google/
  // Firebase, 6L… reCAPTCHA site key), it cannot be vouched for by OTHER public keys that happen to sit in the same
  // body — e.g. a real Stripe sk_live_ co-located with a legit Maps key must NOT be swallowed as "public by design".
  if (marker && !/^AIza[0-9A-Za-z_-]{35}$/.test(marker) && !/^6L[0-9A-Za-z_-]{30,40}$/.test(marker)) return false;
  return isBrowserGoogleMapsApiKey(body, marker) || isFirebaseWebApiKey(body, marker) || isRecaptchaSiteKey(body, marker);
}

/**
 * Scan the response text and return concrete-impact signals (empty if none). Suppresses FP via placeholder / anti-ambient.
 */
export function impactOracle(responseText: string, ctx: ImpactContext = {}): ImpactSignal[] {
  const body = responseText || "";
  const base = ctx.baselineBody ?? "";
  const out: ImpactSignal[] = [];
  const seen = new Set<string>();
  const emit = (kind: ImpactKind, severity: Severity, rawMarker: string, detail: string): void => {
    const marker = rawMarker.slice(0, 100);
    if (!marker) return;
    if (PLACEHOLDERS.some((p) => p.test(marker))) return; // documentation placeholder
    if (base && base.includes(marker)) return; // anti-ambient: already present in the baseline
    if (detail === "Google API key" && isPublicByDesignClientCredential(body, marker)) return;
    const key = `${kind}:${marker}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, severity, marker, detail });
  };
  for (const d of DETECTORS) {
    // Iterate ALL matches, not just the first: emit() suppresses placeholders / ambient (baseline) / public-by-design
    // keys, so a suppressed FIRST match must not mask a REAL secret of the same detector later in the body (e.g. a public
    // Maps AIza key before a leaked server-side AIza key). Clone with the global flag (detectors are non-global) so
    // matchAll walks every occurrence; emit() dedups by marker, so repeats collapse.
    const re = d.re.global ? d.re : new RegExp(d.re.source, `${d.re.flags}g`);
    for (const m of body.matchAll(re)) emit(d.kind, d.severity, m[0], d.detail);
  }
  // cross-user: the requested victim ID appears as a DISTINCT token in the response, the attacker's own ID does not, and it
  // is not in the baseline either. identityAppears (word-boundary + min length) stops a bare short id like "42" from
  // matching incidentally inside unrelated numbers — the false-cross-user bug that let a self-owned/public object confirm.
  // A tenant people-picker card (displayName + work email + photo + tenant) is intended, not IDOR — require
  // phone/home-address/SSN/DOB, an extra internal id, or private-object contents (order/basket/message) before firing.
  if (
    ctx.requestedIdentity &&
    ctx.requestedIdentity !== ctx.sessionIdentity && // you cannot IDOR your OWN id
    identityAppears(body, ctx.requestedIdentity) &&
    // The self-object suppressor must be a DISTINCTIVE id (>=3 chars): a short self id like "1"/"42" collides
    // incidentally ("unread":1, page:2) and was silently suppressing real cross-user reads of a different victim.
    (!ctx.sessionIdentity || ctx.sessionIdentity.length < 3 || !identityAppears(body, ctx.sessionIdentity)) &&
    !identityAppears(base, ctx.requestedIdentity)
  ) {
    const shape = classifyCrossUserBody(body, ctx.requestedIdentity);
    if (shape.class !== "public-directory") {
      out.push({
        kind: "cross-user",
        severity: "high",
        marker: ctx.requestedIdentity.slice(0, 100),
        detail:
          shape.class === "sensitive-pii"
            ? `cross-user object carries ${shape.detail} (victim '${ctx.requestedIdentity}')`
            : `response contains the requested victim identity '${ctx.requestedIdentity}' (not the attacker's own) — ${shape.detail}`,
      });
    }
  }
  // ctf-flag: only when a flagRegex is explicitly passed (default OFF).
  if (ctx.flagRegex) {
    const fm = ctx.flagRegex.exec(body);
    if (fm && !base.includes(fm[0])) out.push({ kind: "ctf-flag", severity: "medium", marker: fm[0].slice(0, 100), detail: "engagement flag pattern matched" });
  }
  return out;
}

/** impact signals on one line (for logs / returning to the LLM). */
export function formatImpact(signals: ReadonlyArray<ImpactSignal>): string {
  return signals.map((s) => `${s.kind}[${s.severity}]: ${s.detail} (${s.marker.slice(0, 40)})`).join("; ");
}
