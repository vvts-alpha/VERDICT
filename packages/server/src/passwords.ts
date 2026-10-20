// Password hashing for local accounts — node:crypto scrypt only (no deps).
// Stored format (PHC-ish): scrypt$N$r$p$<b64 salt>$<b64 hash>
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";

const N = 16384;
const R = 8;
const P = 1;
const KEY_LEN = 64;
const SALT_LEN = 16;
const MIN_PASSWORD_LENGTH = 12;

export function hashPassword(password: string): string {
  const salt = randomBytes(SALT_LEN);
  const hash = scryptSync(password, salt, KEY_LEN, { N, r: R, p: P });
  return `scrypt$${N}$${R}$${P}$${salt.toString("base64")}$${hash.toString("base64")}`;
}

/** Constant-time verify; returns false on malformed stored hashes too. */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [n, r, p] = [Number(parts[1]), Number(parts[2]), Number(parts[3])];
  if (![n, r, p].every(Number.isSafeInteger) || n <= 0 || r <= 0 || p <= 0 || n > 1_048_576) return false;
  const salt = Buffer.from(parts[4]!, "base64");
  const expected = Buffer.from(parts[5]!, "base64");
  if (!salt.length || expected.length !== KEY_LEN) return false;
  const actual = scryptSync(password, salt, KEY_LEN, { N: n, r, p, maxmem: 128 * n * r * 2 });
  return timingSafeEqual(actual, expected);
}

/** Enforced on set/reset; keep requirements simple and documented. */
export function passwordPolicyError(password: string): string | null {
  if (password.length < MIN_PASSWORD_LENGTH) return `Password must be at least ${MIN_PASSWORD_LENGTH} characters`;
  if (password.length > 1024) return "Password is too long";
  return null;
}
