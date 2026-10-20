// Multi-user authN/authZ integration: real HTTP fixture (no mocks) exercising login,
// session lifecycle, run ownership isolation, admin CRUD, and rate limiting.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { WebSocket } from "ws";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { Screen } from "@veritas/core";
import { startServer } from "./index.js";
import { UsersDb } from "./users-db.js";
import { hashPassword, passwordPolicyError, verifyPassword } from "./passwords.js";

function screen(id: string, urlTemplate: string): Screen {
  return {
    screenId: id, urlTemplate, observedUrls: [], authState: "unauth", screenType: "other",
    description: "", params: [], apis: [], screenshot: "", domSkeletonHash: id, labels: [],
  };
}

function seed(runsDir: string, id: string): void {
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(join(runsDir, id, "state.sqlite"));
  store.createAssessment({
    id,
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
  });
  store.upsertScreen(id, screen("s-0001", "/products/{id}"));
  store.close();
}

interface Rig {
  url: string;
  runsDir: string;
  db: UsersDb;
  close(): Promise<void>;
}

const PW = { admin: "admin-password-1", alice: "pw-alice-longenough", bob: "pw-bob-longenough" };

async function rig(): Promise<Rig> {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-mu-runs-"));
  const dbDir = mkdtempSync(join(tmpdir(), "veritas-mu-db-"));
  const db = UsersDb.open(join(dbDir, "server.db"));
  db.createUser({ username: "admin", passwordHash: hashPassword(PW.admin), role: "admin" });
  db.createUser({ username: "alice", passwordHash: hashPassword(PW.alice), role: "user" });
  db.createUser({ username: "bob", passwordHash: hashPassword(PW.bob), role: "user" });
  const srv = await startServer({ runsDir, usersDb: db, pollMs: 50 });
  return {
    url: srv.url,
    runsDir,
    db,
    close: async () => {
      await srv.close();
      db.close();
      rmSync(runsDir, { recursive: true, force: true });
      rmSync(dbDir, { recursive: true, force: true });
    },
  };
}

function cookieOf(res: Response): string {
  const set = res.headers.get("set-cookie") ?? "";
  return set.split(";")[0] ?? "";
}

async function login(url: string, username: string, password: string): Promise<{ status: number; cookie: string }> {
  const res = await fetch(`${url}/api/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  return { status: res.status, cookie: cookieOf(res) };
}

function authed(url: string, cookie: string, path: string, init?: RequestInit): Promise<Response> {
  return fetch(`${url}${path}`, { ...init, headers: { cookie, ...(init?.headers as Record<string, string> ?? {}) } });
}

// ---------- passwords ----------

test("scrypt hash/verify roundtrip; wrong password and malformed hashes rejected", () => {
  const hash = hashPassword("correct horse battery staple");
  assert.equal(verifyPassword("correct horse battery staple", hash), true);
  assert.equal(verifyPassword("wrong", hash), false);
  assert.equal(verifyPassword("x", "not-a-hash"), false);
  assert.equal(verifyPassword("x", "scrypt$0$0$0$$$"), false);
  assert.ok(passwordPolicyError("short") !== null);
  assert.equal(passwordPolicyError("long-enough-password"), null);
});

// ---------- users-db ----------

test("users-db: users, sessions, run owners, audit", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-udb-"));
  const db = UsersDb.open(join(dir, "s.db"));
  try {
    const admin = db.createUser({ username: "Admin", passwordHash: hashPassword(PW.admin), role: "admin" });
    assert.equal(db.getUserByUsername("ADMIN")?.id, admin.id); // NOCASE
    assert.throws(() => db.createUser({ username: "admin", passwordHash: hashPassword("x-password-1"), role: "user" }), /UNIQUE/);

    const s = db.createSession(admin.id, 60_000, "10.0.0.1", "ua");
    assert.equal(db.getSession(s.id, Date.now())?.userId, admin.id);
    assert.equal(db.getSession(s.id, Date.now() + 61_000), null); // expired
    const s2 = db.createSession(admin.id, 60_000, "10.0.0.1", "ua");
    db.revokeSession(s2.id);
    assert.equal(db.getSession(s2.id, Date.now()), null);

    // disabled user's sessions die
    const u = db.createUser({ username: "dave", passwordHash: hashPassword("dave-password-1"), role: "user" });
    const s3 = db.createSession(u.id, 60_000, "", "");
    db.updateUser(u.id, { status: "disabled" });
    assert.equal(db.getSession(s3.id, Date.now()), null);

    // the last-admin guard lives in updateUser so the CLI path cannot bypass it either
    assert.equal(db.countActiveAdmins(), 1);
    assert.throws(() => db.updateUser(admin.id, { role: "user" }), /last_admin/);
    assert.throws(() => db.updateUser(admin.id, { status: "disabled" }), /last_admin/);
    const admin2 = db.createUser({ username: "ops2", passwordHash: hashPassword("ops2-password-1"), role: "admin" });
    db.updateUser(admin.id, { role: "user" }); // allowed now — ops2 keeps admin rights
    assert.equal(db.getUserById(admin.id)!.role, "user");
    assert.throws(() => db.updateUser(admin2.id, { role: "user" }), /last_admin/); // ops2 is last again

    db.setRunOwner("run-1", admin.id);
    assert.equal(db.getRunOwner("run-1"), admin.id);
    assert.ok(db.ownedRunIds(admin.id).has("run-1"));

    db.audit({ actorId: admin.id, action: "login", ip: "1.2.3.4" });
    db.audit({ actorName: "cli", action: "user_created" });
    const events = db.listAudit();
    assert.equal(events.length, 2);
    assert.equal(events[0]!.action, "user_created"); // DESC order
    assert.ok(events[0]!.seq > events[1]!.seq);
  } finally {
    db.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------- HTTP integration ----------

test("unauthenticated: API 401, pages redirect to /login", async () => {
  const r = await rig();
  try {
    const api = await fetch(`${r.url}/api/assessments`);
    assert.equal(api.status, 401);
    const page = await fetch(`${r.url}/`, { redirect: "manual" });
    assert.equal(page.status, 302);
    assert.match(page.headers.get("location") ?? "", /login/);
    const loginPage = await fetch(`${r.url}/login`);
    assert.equal(loginPage.status, 200);
  } finally {
    await r.close();
  }
});

test("login issues a session; /api/me reports the account; logout revokes", async () => {
  const r = await rig();
  try {
    const bad = await login(r.url, "alice", "nope");
    assert.equal(bad.status, 401);
    const good = await login(r.url, "alice", PW.alice);
    assert.equal(good.status, 200);
    const me = await fetch(`${r.url}/api/me`, { headers: { cookie: good.cookie } });
    const meJson = (await me.json()) as { role: string; user: { username: string }; multiUser: boolean };
    assert.equal(meJson.multiUser, true);
    assert.equal(meJson.user.username, "alice");
    assert.equal(meJson.role, "user");

    await authed(r.url, good.cookie, "/api/auth/logout", { method: "POST" });
    const after = await fetch(`${r.url}/api/me`, { headers: { cookie: good.cookie } });
    assert.equal(after.status, 401);
  } finally {
    await r.close();
  }
});

test("login rate-limit locks after repeated failures", async () => {
  const r = await rig();
  try {
    for (let i = 0; i < 5; i++) {
      const res = await login(r.url, "alice", "bad-password");
      assert.equal(res.status, 401, `attempt ${i}`);
    }
    const locked = await login(r.url, "alice", PW.alice);
    assert.equal(locked.status, 429); // even the right password is locked out
  } finally {
    await r.close();
  }
});

test("run ownership: users see only their own; admin sees all; ownerless is admin-only", async () => {
  const r = await rig();
  try {
    const alice = (await login(r.url, "alice", PW.alice)).cookie;
    const bob = (await login(r.url, "bob", PW.bob)).cookie;
    const admin = (await login(r.url, "admin", PW.admin)).cookie;
    const aliceId = r.db.getUserByUsername("alice")!.id;
    const bobId = r.db.getUserByUsername("bob")!.id;

    for (const id of ["run-a", "run-b", "run-old"]) seed(r.runsDir, id);
    r.db.setRunOwner("run-a", aliceId);
    r.db.setRunOwner("run-b", bobId);
    // run-old deliberately has no owner (pre-multi-user artifact)

    const listOf = async (cookie: string) => ((await (await authed(r.url, cookie, "/api/assessments")).json()) as Array<{ id: string }>).map((x) => x.id).sort();
    assert.deepEqual(await listOf(alice), ["run-a"]);
    assert.deepEqual(await listOf(bob), ["run-b"]);
    assert.deepEqual(await listOf(admin), ["run-a", "run-b", "run-old"]);

    // direct access: other user's run and ownerless runs are indistinguishable from missing (404)
    assert.equal((await authed(r.url, alice, "/api/assessments/run-b")).status, 404);
    assert.equal((await authed(r.url, alice, "/api/assessments/run-old")).status, 404);
    assert.equal((await authed(r.url, alice, "/api/assessments/run-a")).status, 200);
    assert.equal((await authed(r.url, admin, "/api/assessments/run-b")).status, 200);
    assert.equal((await authed(r.url, admin, "/api/assessments/run-old")).status, 200);

    // control routes are owner-gated too — POST on another user's run → 404. Every denied access is
    // audited regardless of method: the earlier GET probes (lines above) and this POST both recorded.
    const denied = await authed(r.url, alice, "/api/assessments/run-b/pause", { method: "POST" });
    assert.equal(denied.status, 404);
    const audit = r.db.listAudit();
    const deniedGet = audit.filter((e) => e.action === "access_denied" && e.target === "run:run-b" && e.detail === "GET");
    const deniedPost = audit.filter((e) => e.action === "access_denied" && e.target === "run:run-b" && e.detail === "POST");
    assert.equal(deniedGet.length, 1); // exactly the GET probe from above
    assert.equal(deniedPost.length, 1); // exactly this POST
  } finally {
    await r.close();
  }
});

test("run creation records the owner (spawned via a fake CLI)", async () => {
  const runsDir = mkdtempSync(join(tmpdir(), "veritas-mu-runs-"));
  const dbDir = mkdtempSync(join(tmpdir(), "veritas-mu-db-"));
  const cliDir = mkdtempSync(join(tmpdir(), "veritas-fake-cli-"));
  const db = UsersDb.open(join(dbDir, "server.db"));
  db.createUser({ username: "alice", passwordHash: hashPassword(PW.alice), role: "user" });
  db.createUser({ username: "bob", passwordHash: hashPassword(PW.bob), role: "user" });
  const fakeCli = join(cliDir, "fake-cli.js");
  writeFileSync(fakeCli, "console.log('ok');\n");
  const srv = await startServer({
    runsDir,
    usersDb: db,
    pollMs: 50,
    runLauncher: { runsDir, cliPath: fakeCli, nodePath: process.execPath },
  });
  try {
    const alice = (await login(srv.url, "alice", PW.alice)).cookie;
    const res = await authed(srv.url, alice, "/api/run", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ command: "assess", manifest: { target: "https://shop.test/" } }),
    });
    assert.equal(res.status, 200);
    const { id } = (await res.json()) as { id: string };
    assert.equal(db.getRunOwner(id), db.getUserByUsername("alice")!.id);
    assert.ok(db.listAudit().some((e) => e.action === "run_created" && e.target === `run:${id}`));
    // a different user cannot see the fresh run
    const bob = (await login(srv.url, "bob", PW.bob)).cookie;
    assert.equal((await authed(srv.url, bob, `/api/assessments/${id}`)).status, 404);
  } finally {
    await srv.close();
    db.close();
    rmSync(runsDir, { recursive: true, force: true });
    rmSync(dbDir, { recursive: true, force: true });
    rmSync(cliDir, { recursive: true, force: true });
  }
});

test("admin API: list + create only; management mutations stay host-local (CLI)", async () => {
  const r = await rig();
  try {
    const admin = (await login(r.url, "admin", PW.admin)).cookie;
    const alice = (await login(r.url, "alice", PW.alice)).cookie;

    assert.equal((await authed(r.url, alice, "/api/admin/users")).status, 403);
    const list = (await (await authed(r.url, admin, "/api/admin/users")).json()) as Array<{ username: string; passwordHash?: string }>;
    assert.equal(list.length, 3);
    assert.ok(list.every((u) => u.passwordHash === undefined)); // never serialized

    const created = await authed(r.url, admin, "/api/admin/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "carol", role: "user", password: "carol-password-1" }),
    });
    assert.equal(created.status, 201);
    const dup = await authed(r.url, admin, "/api/admin/users", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username: "CAROL", role: "user", password: "carol-password-1" }),
    });
    assert.equal(dup.status, 409);
    assert.equal((await login(r.url, "carol", "carol-password-1")).status, 200);

    // The mutation routes do not exist over HTTP — role/status/resets are `veritas user …` on the host.
    const adminId = r.db.getUserByUsername("admin")!.id;
    assert.equal(
      (await authed(r.url, admin, `/api/admin/users/${adminId}`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ role: "user" }) })).status,
      404,
    );
    assert.equal((await authed(r.url, admin, `/api/admin/users/${adminId}/reset-password`, { method: "POST" })).status, 404);
    assert.equal((await authed(r.url, admin, "/api/admin/audit")).status, 404);
  } finally {
    await r.close();
  }
});

test("change-password verifies the current one and kills all sessions", async () => {
  const r = await rig();
  try {
    const alice = (await login(r.url, "alice", PW.alice)).cookie;
    const wrong = await authed(r.url, alice, "/api/auth/change-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ currentPassword: "nope", newPassword: "new-alice-password-1" }),
    });
    assert.equal(wrong.status, 403);
    const ok = await authed(r.url, alice, "/api/auth/change-password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ currentPassword: PW.alice, newPassword: "new-alice-password-1" }),
    });
    assert.equal(ok.status, 200);
    assert.equal((await fetch(`${r.url}/api/me`, { headers: { cookie: alice } })).status, 401); // old session dead
    assert.equal((await login(r.url, "alice", PW.alice)).status, 401); // old password dead
    assert.equal((await login(r.url, "alice", "new-alice-password-1")).status, 200);
  } finally {
    await r.close();
  }
});

test("WS: another user's run stream is refused; owner connects", async () => {
  const r = await rig();
  try {
    seed(r.runsDir, "run-ws");
    r.db.setRunOwner("run-ws", r.db.getUserByUsername("alice")!.id);
    const bob = (await login(r.url, "bob", PW.bob)).cookie;
    const alice = (await login(r.url, "alice", PW.alice)).cookie;
    const wsUrl = r.url.replace("http://", "ws://") + "/ws?id=run-ws";

    const bobResult = await new Promise<string>((resolvePromise) => {
      const ws = new WebSocket(wsUrl, { headers: { cookie: bob } });
      ws.on("open", () => { ws.close(); resolvePromise("opened"); });
      ws.on("error", () => resolvePromise("refused"));
      ws.on("unexpected-response", (_req, res) => resolvePromise(`http-${res.statusCode}`));
    });
    assert.notEqual(bobResult, "opened");

    const aliceResult = await new Promise<string>((resolvePromise) => {
      const ws = new WebSocket(wsUrl, { headers: { cookie: alice } });
      ws.on("open", () => { ws.close(); resolvePromise("opened"); });
      ws.on("error", () => resolvePromise("refused"));
      ws.on("unexpected-response", (_req, res) => resolvePromise(`http-${res.statusCode}`));
    });
    assert.equal(aliceResult, "opened");
  } finally {
    await r.close();
  }
});
