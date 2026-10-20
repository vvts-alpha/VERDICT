// Multi-user identity store for serve mode — server-global auth DB (verdict-server.db next to runs/).
// Keeps accounts, server-side sessions, CLI API tokens, run ownership, and the append-only audit log.
// Uses builtin node:sqlite like the per-run AssessmentStore; separate file so run stores stay untouched.
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { randomBytes } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

/** Conventional location of the server-global auth DB — a sibling of the runs directory. */
export function usersDbPath(runsDir: string): string {
  return resolve(runsDir, "..", "verdict-server.db");
}

export type UserRole = "admin" | "user";
export type UserStatus = "active" | "disabled";

export interface UserRow {
  id: string;
  username: string;
  displayName: string;
  role: UserRole;
  status: UserStatus;
  passwordHash: string;
  passwordChangedAt: number;
  createdAt: number;
}

export interface SessionRow {
  id: string;
  userId: string;
  createdAt: number;
  expiresAt: number;
  lastSeenAt: number;
  ip: string;
  userAgent: string;
  revokedAt: number | null;
}

export interface ApiTokenRow {
  id: string;
  userId: string;
  name: string;
  createdAt: number;
  lastUsedAt: number | null;
  revokedAt: number | null;
}

export interface AuditRow {
  seq: number;
  ts: number;
  actorId: string | null;
  actorName: string | null;
  action: string;
  target: string | null;
  ip: string | null;
  detail: string | null;
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL COLLATE NOCASE UNIQUE,
  display_name TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL CHECK (role IN ('admin','user')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  password_hash TEXT NOT NULL,
  password_changed_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  user_agent TEXT NOT NULL DEFAULT '',
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
CREATE TABLE IF NOT EXISTS api_tokens (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  name TEXT NOT NULL DEFAULT '',
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  last_used_at INTEGER,
  revoked_at INTEGER
);
CREATE INDEX IF NOT EXISTS api_tokens_user ON api_tokens(user_id);
CREATE TABLE IF NOT EXISTS run_owners (
  run_id TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS run_owners_user ON run_owners(owner_id);
CREATE TABLE IF NOT EXISTS audit_events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  actor_id TEXT,
  actor_name TEXT,
  action TEXT NOT NULL,
  target TEXT,
  ip TEXT,
  detail TEXT
);`;

function userId(): string {
  return `u-${randomBytes(8).toString("hex")}`;
}
function randomId(prefix: string): string {
  return `${prefix}-${randomBytes(16).toString("hex")}`;
}

export class UsersDb {
  private constructor(private readonly db: DatabaseSync) {}

  static open(dbPath: string): UsersDb {
    mkdirSync(dirname(dbPath), { recursive: true });
    const db = new DatabaseSync(dbPath);
    db.exec(SCHEMA);
    return new UsersDb(db);
  }

  close(): void {
    this.db.close();
  }

  // --- users ---
  createUser(input: { username: string; displayName?: string; passwordHash: string; role: UserRole }): UserRow {
    const now = Date.now();
    const row: UserRow = {
      id: userId(),
      username: input.username.trim(),
      displayName: input.displayName?.trim() ?? "",
      role: input.role,
      status: "active",
      passwordHash: input.passwordHash,
      passwordChangedAt: now,
      createdAt: now,
    };
    this.db
      .prepare("INSERT INTO users (id, username, display_name, role, status, password_hash, password_changed_at, created_at) VALUES (?,?,?,?,?,?,?,?)")
      .run(row.id, row.username, row.displayName, row.role, row.status, row.passwordHash, row.passwordChangedAt, row.createdAt);
    return row;
  }

  private static mapUser(r: Record<string, unknown>): UserRow {
    return {
      id: r.id as string,
      username: r.username as string,
      displayName: r.display_name as string,
      role: r.role as UserRole,
      status: r.status as UserStatus,
      passwordHash: r.password_hash as string,
      passwordChangedAt: r.password_changed_at as number,
      createdAt: r.created_at as number,
    };
  }

  getUserByUsername(username: string): UserRow | null {
    const r = this.db.prepare("SELECT * FROM users WHERE username = ?").get(username.trim()) as Record<string, unknown> | undefined;
    return r ? UsersDb.mapUser(r) : null;
  }

  getUserById(id: string): UserRow | null {
    const r = this.db.prepare("SELECT * FROM users WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    return r ? UsersDb.mapUser(r) : null;
  }

  listUsers(): UserRow[] {
    return (this.db.prepare("SELECT * FROM users ORDER BY created_at, username").all() as Record<string, unknown>[]).map(UsersDb.mapUser);
  }

  countUsers(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM users").get() as { n: number }).n;
  }

  countActiveAdmins(): number {
    return (this.db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND status = 'active'").get() as { n: number }).n;
  }

  updateUser(id: string, patch: { displayName?: string; role?: UserRole; status?: UserStatus; passwordHash?: string }): void {
    const sets: string[] = [];
    const args: unknown[] = [];
    if (patch.displayName !== undefined) { sets.push("display_name = ?"); args.push(patch.displayName); }
    if (patch.role !== undefined) { sets.push("role = ?"); args.push(patch.role); }
    if (patch.status !== undefined) { sets.push("status = ?"); args.push(patch.status); }
    if (patch.passwordHash !== undefined) {
      sets.push("password_hash = ?", "password_changed_at = ?");
      args.push(patch.passwordHash, Date.now());
    }
    if (!sets.length) return;
    this.db.prepare(`UPDATE users SET ${sets.join(", ")} WHERE id = ?`).run(...(args as never[]), id);
  }

  // --- sessions ---
  createSession(userIdValue: string, ttlMs: number, ip: string, userAgent: string): SessionRow {
    const now = Date.now();
    const row: SessionRow = { id: randomId("s"), userId: userIdValue, createdAt: now, expiresAt: now + ttlMs, lastSeenAt: now, ip, userAgent, revokedAt: null };
    this.db.prepare("INSERT INTO sessions (id, user_id, created_at, expires_at, last_seen_at, ip, user_agent) VALUES (?,?,?,?,?,?,?)").run(row.id, row.userId, row.createdAt, row.expiresAt, row.lastSeenAt, row.ip, row.userAgent);
    return row;
  }

  /** Valid session → its row (revoked/expired/disabled user → null). Refreshes last_seen. */
  getSession(id: string, now: number): SessionRow | null {
    const r = this.db.prepare("SELECT * FROM sessions WHERE id = ?").get(id) as Record<string, unknown> | undefined;
    if (!r || r.revoked_at !== null || (r.expires_at as number) <= now) return null;
    const user = this.getUserById(r.user_id as string);
    if (!user || user.status !== "active") return null;
    this.db.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").run(now, id);
    return { id: r.id as string, userId: r.user_id as string, createdAt: r.created_at as number, expiresAt: r.expires_at as number, lastSeenAt: now, ip: r.ip as string, userAgent: r.user_agent as string, revokedAt: null };
  }

  /** Sliding idle refresh bounded by an absolute cap. */
  refreshSessionExpiry(id: string, expiresAt: number): void {
    this.db.prepare("UPDATE sessions SET expires_at = ? WHERE id = ? AND revoked_at IS NULL").run(expiresAt, id);
  }

  revokeSession(id: string): void {
    this.db.prepare("UPDATE sessions SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL").run(Date.now(), id);
  }

  revokeUserSessions(userIdValue: string): void {
    this.db.prepare("UPDATE sessions SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL").run(Date.now(), userIdValue);
  }

  // --- api tokens (CLI bearer; sha256 of the presented secret is stored, never the secret) ---
  createApiToken(userIdValue: string, name: string, tokenHash: string): ApiTokenRow {
    const row: ApiTokenRow = { id: randomId("t"), userId: userIdValue, name: name.trim(), createdAt: Date.now(), lastUsedAt: null, revokedAt: null };
    this.db.prepare("INSERT INTO api_tokens (id, user_id, name, token_hash, created_at) VALUES (?,?,?,?,?)").run(row.id, row.userId, row.name, tokenHash, row.createdAt);
    return row;
  }

  getApiTokenUser(tokenHash: string): UserRow | null {
    const r = this.db.prepare("SELECT id, user_id, revoked_at FROM api_tokens WHERE token_hash = ?").get(tokenHash) as Record<string, unknown> | undefined;
    if (!r || r.revoked_at !== null) return null;
    const user = this.getUserById(r.user_id as string);
    if (!user || user.status !== "active") return null;
    this.db.prepare("UPDATE api_tokens SET last_used_at = ? WHERE id = ?").run(Date.now(), r.id as string);
    return user;
  }

  listApiTokens(userIdValue: string): ApiTokenRow[] {
    return (this.db.prepare("SELECT * FROM api_tokens WHERE user_id = ? ORDER BY created_at").all(userIdValue) as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, userId: r.user_id as string, name: r.name as string, createdAt: r.created_at as number,
      lastUsedAt: (r.last_used_at as number | null) ?? null, revokedAt: (r.revoked_at as number | null) ?? null,
    }));
  }

  revokeApiToken(id: string, userIdValue: string): boolean {
    const res = this.db.prepare("UPDATE api_tokens SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL").run(Date.now(), id, userIdValue);
    return res.changes > 0;
  }

  // --- run ownership ---
  setRunOwner(runId: string, ownerId: string): void {
    this.db.prepare("INSERT OR REPLACE INTO run_owners (run_id, owner_id, created_at) VALUES (?,?,?)").run(runId, ownerId, Date.now());
  }

  getRunOwner(runId: string): string | null {
    const r = this.db.prepare("SELECT owner_id FROM run_owners WHERE run_id = ?").get(runId) as { owner_id: string } | undefined;
    return r?.owner_id ?? null;
  }

  ownedRunIds(ownerId: string): Set<string> {
    return new Set((this.db.prepare("SELECT run_id FROM run_owners WHERE owner_id = ?").all(ownerId) as { run_id: string }[]).map((r) => r.run_id));
  }

  // --- audit (append-only; never write secrets to detail) ---
  audit(entry: { actorId?: string | null; actorName?: string | null; action: string; target?: string | null; ip?: string | null; detail?: string | null }): void {
    this.db.prepare("INSERT INTO audit_events (ts, actor_id, actor_name, action, target, ip, detail) VALUES (?,?,?,?,?,?,?)").run(
      Date.now(), entry.actorId ?? null, entry.actorName ?? null, entry.action, entry.target ?? null, entry.ip ?? null, entry.detail ?? null);
  }

  listAudit(limit = 200): AuditRow[] {
    return (this.db.prepare("SELECT * FROM audit_events ORDER BY seq DESC LIMIT ?").all(limit) as Record<string, unknown>[]).map((r) => ({
      seq: r.seq as number, ts: r.ts as number, actorId: (r.actor_id as string | null) ?? null, actorName: (r.actor_name as string | null) ?? null,
      action: r.action as string, target: (r.target as string | null) ?? null, ip: (r.ip as string | null) ?? null, detail: (r.detail as string | null) ?? null,
    }));
  }
}
