// Multi-user request authentication for serve mode — the session cookie only (no API tokens:
// there is no programmatic client today, and cookie login works for any automation that appears).
// Legacy shared-password cookies still resolve through auth.ts when authPasswords is set (compat gate).
import type { IncomingMessage } from "node:http";
import type { UsersDb, UserRow, UserRole } from "./users-db.js";

export const SESSION_COOKIE = "verdict_session";
export const SESSION_IDLE_MS = 12 * 3600 * 1000;
export const SESSION_ABSOLUTE_MS = 7 * 24 * 3600 * 1000;
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCK_MS = 15 * 60 * 1000;

export interface Principal {
  userId: string;
  username: string;
  role: UserRole;
  sessionId: string;
}

function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

export function sessionCookieValue(id: string, expiresAt: number): string {
  return `${SESSION_COOKIE}=${id}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${Math.max(0, Math.floor((expiresAt - Date.now()) / 1000))}`;
}

export function clearedSessionCookie(): string {
  return `${SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0`;
}

/** Resolve the caller's identity from the session cookie. */
export function principalForReq(req: IncomingMessage, db: UsersDb, now: number): Principal | null {
  const sessionId = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!sessionId) return null;
  const session = db.getSession(sessionId, now);
  if (!session) return null;
  // Sliding idle window bounded by an absolute lifetime.
  if (session.expiresAt - now < SESSION_IDLE_MS / 2) {
    db.refreshSessionExpiry(sessionId, Math.min(now + SESSION_IDLE_MS, session.createdAt + SESSION_ABSOLUTE_MS));
  }
  const user = db.getUserById(session.userId) as UserRow;
  return { userId: user.id, username: user.username, role: user.role, sessionId };
}

interface LoginFail {
  fails: number;
  lockedUntil: number;
}

/** In-memory login throttle keyed by ip+username. Resets on success; enough for a single-process server. */
export class LoginRateLimiter {
  private readonly fails = new Map<string, LoginFail>();

  locked(key: string, now: number): boolean {
    const f = this.fails.get(key);
    return !!f && f.lockedUntil > now;
  }

  fail(key: string, now: number): { fails: number; lockedUntil: number } {
    const f = this.fails.get(key) ?? { fails: 0, lockedUntil: 0 };
    f.fails += 1;
    if (f.fails >= LOGIN_MAX_FAILS) f.lockedUntil = now + LOGIN_LOCK_MS;
    this.fails.set(key, f);
    return f;
  }

  reset(key: string): void {
    this.fails.delete(key);
  }

  lockRemainingMs(key: string, now: number): number {
    const f = this.fails.get(key);
    return f ? Math.max(0, f.lockedUntil - now) : 0;
  }
}

/** Verify against a fixed dummy hash when the username is unknown, so timing doesn't reveal valid usernames. */
export const DUMMY_PASSWORD_HASH =
  "scrypt$16384$8$1$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
