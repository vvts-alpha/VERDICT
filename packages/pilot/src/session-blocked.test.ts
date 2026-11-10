import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after } from "node:test";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

// There is NO role "blocked" state. An observation never marks anything — a 403 may be a scope gap, a
// 401 a per-resource decision, a redirect a routing quirk, and login-ish content appears on register/
// i18n/settings pages of a live session. A failed login() is just a failed login(): it returns the
// reason, counts ONE attempt (an observation, not a verdict), and the role stays retrievable forever.
// survey_done distinguishes "never even tried" (refused) from "tried and couldn't" (warned, passes).

const base = "http://app.test/";
const dir = mkdtempSync(join(tmpdir(), "veritas-sblk-"));
let dbN = 0;
after(() => rmSync(dir, { recursive: true, force: true }));

function session(site: Record<string, Parameters<FakeDriver["visit"]>[0] extends string ? object : never> | Record<string, Partial<import("@veritas/crawler").Observation>>): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  const scope = deriveScopeFromSingleUrl(base);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: base, followLinks: true, maxDepth: 2 }, scope });
  const driver = Object.assign(new FakeDriver(site), { saveScreenshot: async () => false });
  return {
    driver,
    http: new FetchHttpClient({ allow: () => true }),
    store,
    assessmentId: "a-1",
    evidence: new EvidenceStore(join(dir, `art-${dbN}`)),
    inv: new InventoryBuilder(),
    scope,
    targetUrl: base,
    artifactsDir: dir,
    currentScreenId: "s-1",
    currentCookie: "sess=alice",
    currentBearer: "",
    currentRole: "alice",
    roleCreds: new Map(),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map(),
    roleNames: new Set(["alice"]), // 'alice' is a configured role (attended launch set) — mirrors run.ts population
    visited: new Set<string>(),
    frontier: new Set<string>(),
    refererGated: new Set<string>(),
    visitedByRole: new Map<string, Set<string>>(),
    roleSurveyCounts: new Map<string, number>(),
    roleLoginAttempts: new Map<string, number>(),
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

async function navigate(s: PilotSession, url: string): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === "browser_navigate") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return (await t.handler({ url }, {})).content[0]!.text;
}
async function login(s: PilotSession, args: Record<string, unknown>): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return (await t.handler(args, {})).content[0]!.text;
}
const close = (s: PilotSession): void => (s as unknown as { store: { close(): void } }).store.close();
const attempts = (s: PilotSession, role: string): number => s.roleLoginAttempts?.get(role) ?? 0;

test("deliberate visit to /#/register (password fields, live session) records no login attempt", async () => {
  const s = session({
    [`${base}#/register`]: { visibleText: "Register — Email, Password, Repeat Password, Security Question" },
  });
  try {
    const out = await navigate(s, `${base}#/register`);
    assert.doesNotMatch(out, /ERROR/);
    assert.equal(attempts(s, "alice"), 0, "a page visit is not a login attempt");
  } finally {
    close(s);
  }
});

test("a redirect bounce to a login page just doesn't count as mapped", async () => {
  const s = session({
    [`${base}account`]: { finalUrl: `${base}#/login`, visibleText: "Please log in" },
  });
  try {
    await navigate(s, `${base}account`);
    assert.equal(s.visitedByRole.get("alice")?.size ?? 0, 0, "a bounced visit doesn't count as mapped");
    assert.equal(attempts(s, "alice"), 0, "nor is it a login attempt");
  } finally {
    close(s);
  }
});

test("an inline login wall on a NON-auth route is just an observation", async () => {
  const s = session({
    [`${base}products`]: {
      visibleText: "Please sign in to continue — enter your password",
      forms: [{ action: `${base}login`, method: "POST", fields: [{ name: "email", type: "email" }, { name: "password", type: "password" }] }],
    },
  });
  try {
    await navigate(s, `${base}products`);
    assert.equal(attempts(s, "alice"), 0, "even a real login form counts no attempt and marks nothing");
  } finally {
    close(s);
  }
});

test("a static asset whose body mentions login words (i18n JSON) counts nothing", async () => {
  const s = session({
    [`${base}assets/i18n/en.json`]: { visibleText: '{"SIGN_IN":"Sign in","PASSWORD":"Password","LOGIN":"Login","FORGOT_PASSWORD":"Forgot password"}' },
  });
  try {
    const out = await navigate(s, `${base}assets/i18n/en.json`);
    assert.doesNotMatch(out, /ERROR/);
    assert.equal(attempts(s, "alice"), 0);
  } finally {
    close(s);
  }
});

test("a failed login() counts exactly ONE attempt — retriable, no verdict state", async () => {
  const s = session({});
  try {
    const out = await login(s, { role: "alice" });
    assert.match(out, /no credentials\/cookie/);
    assert.equal(attempts(s, "alice"), 1, "the attempt is recorded as an observation");
    // Retryable: a second call counts a second attempt — nothing locks the role out.
    const out2 = await login(s, { role: "alice" });
    assert.match(out2, /no credentials\/cookie/);
    assert.equal(attempts(s, "alice"), 2);
  } finally {
    close(s);
  }
});

test("a dropped attended session RESPAWNS on login() instead of dying on 'no credentials' (the a-mvk7tmnr regression)", async () => {
  const s = session({});
  // Attended: roleSessions map exists but 'alice' is absent (context was dropped); a respawn hook
  // re-establishes it — the alternative was the live Sessions-tab browser staying up while login()
  // answered "no credentials".
  s.roleSessions = new Map();
  let respawned = 0;
  s.respawnAttended = async (role) => {
    respawned++;
    assert.equal(role, "alice");
    const d = Object.assign(new FakeDriver({}), {
      saveScreenshot: async () => false,
      sessionCookieHeader: async () => "sess=respawned",
      bearerToken: async () => null,
    });
    return { driver: d as unknown as import("@veritas/crawler").PlaywrightDriver, cookie: "sess=respawned" };
  };
  try {
    const out = await login(s, { role: "alice" });
    assert.equal(respawned, 1, "login() must try the attended respawn before declaring no material");
    assert.match(out, /switched to live attended session/);
    assert.ok(s.roleSessions.get("alice"), "the respawned session re-enters roleSessions for the warm set");
  } finally {
    close(s);
  }
});

test("a FAILED attended respawn still falls through to an honest failure", async () => {
  const s = session({});
  s.roleSessions = new Map();
  s.respawnAttended = async () => {
    throw new Error("launch failed");
  };
  try {
    const out = await login(s, { role: "alice" });
    assert.match(out, /no credentials\/cookie/);
    assert.equal(attempts(s, "alice"), 1);
  } finally {
    close(s);
  }
});

test("a DROPPED role stays a configured requirement — availableRoles doesn't read live sessions", async () => {
  const s = session({});
  // Attended: 'alice' configured (roleNames) but her live session was dropped — the map is empty.
  // If availableRoles read roleSessions.keys() the role's auth requirement would silently vanish
  // (survey_done stops asking, and her screens stay queued forever).
  s.roleSessions = new Map();
  try {
    const { availableRoles } = await import("./tools.js");
    assert.ok(availableRoles(s).some((r) => r.name === "alice"), "a dropped session must not drop the role");
  } finally {
    close(s);
  }
});

test("login() refuses an UNCONFIGURED role — no respawn, no attempt counted", async () => {
  const s = session({});
  s.roleSessions = new Map();
  let spawned = 0;
  s.respawnAttended = async () => (spawned++, null);
  try {
    const out = await login(s, { role: "ghost" });
    assert.match(out, /unknown role/);
    assert.equal(spawned, 0, "a typo'd role must never spawn a real browser");
    assert.equal(attempts(s, "ghost"), 0, "nor count an attempt for a role that doesn't exist");
  } finally {
    close(s);
  }
});

test("a material-less live session falls through to configured creds instead of a dead end", async () => {
  const s = session({});
  const d = Object.assign(new FakeDriver({}), { saveScreenshot: async () => false, sessionCookieHeader: async () => "", bearerToken: async () => null });
  s.roleSessions = new Map([["alice", { driver: d as unknown as import("@veritas/crawler").PlaywrightDriver, cookie: "" }]]);
  s.roleCreds = new Map([["alice", { username: "a", password: "p" }]]);
  try {
    const out = await login(s, { role: "alice" });
    // The empty operator session must NOT win — creds-configured roles still get the
    // machine login attempt (which honestly fails here: FakeDriver can't complete a real login).
    assert.doesNotMatch(out, /carries no session material/, "empty live session must not pre-empt the creds path");
    assert.match(out, /did not complete|login error/i);
    assert.equal(attempts(s, "alice"), 1);
  } finally {
    close(s);
  }
});

/** A cred-sensitive login driver: the fake site accepts exactly one password. Enough of the
 *  Driver + LoginDriver surface for the login() credential path (smartLogin + session capture). */
class CredsDriver {
  readonly filled: Record<string, string> = {};
  submitted = false;
  private url = "";
  constructor(private readonly rightPassword: string) {}
  async visit(u: string) {
    this.url = u;
    return { requestedUrl: u, finalUrl: u, status: 200, title: "", domSkeleton: "", visibleText: "", forms: [], links: [], virtualRoutes: [], apiCalls: [] };
  }
  async close(): Promise<void> {}
  currentUrl(): string { return this.url; }
  async clearSession(): Promise<void> {
    this.submitted = false;
    for (const k of Object.keys(this.filled)) delete this.filled[k];
  }
  async sessionCookieHeader(): Promise<string> { return "sess=fake"; }
  async bearerToken(): Promise<string | null> { return null; }
  async gotoUrl(u: string): Promise<void> { this.url = u; }
  async snapshot() {
    const ok = this.submitted && this.filled['[name="password"]'] === this.rightPassword;
    return {
      url: this.url,
      title: "",
      domSkeleton: "",
      visibleText: ok ? "Welcome to your dashboard" : "Please log in",
      links: [`${base}#/login`],
      forms: ok ? [] : [{ action: "/rest/user/login", method: "post", fields: [{ name: "email", type: "text" }, { name: "password", type: "password" }] }],
      virtualRoutes: [],
    };
  }
  async fill(sel: string, v: string): Promise<boolean> { this.filled[sel] = v; return true; }
  async clickFirst(): Promise<boolean> { this.submitted = true; return true; }
  async pressEnter(): Promise<void> { this.submitted = true; }
}

test("a failed override never poisons the configured credentials", async () => {
  const s = session({});
  s.roleCreds.set("alice", { username: "alice@x.test", password: "right-pw" });
  try {
    // The model guesses wrong: FakeDriver's smartLogin always fails — but the guess must NOT
    // overwrite the configured creds, and the configured creds get their own attempt in the same call.
    const out = await login(s, { role: "alice", username: "alice@x.test", password: "wrong-guess" });
    assert.match(out, /both the supplied and the configured credentials failed/);
    assert.deepEqual(s.roleCreds.get("alice"), { username: "alice@x.test", password: "right-pw" }, "configured creds survive the bad guess");
    assert.equal(attempts(s, "alice"), 1);
  } finally {
    close(s);
  }
});

test("a failed override binds nothing — unproven guesses are not stored as credentials", async () => {
  const s = session({});
  try {
    await login(s, { role: "alice", username: "alice@x.test", password: "pw123" });
    assert.equal(s.roleCreds.get("alice"), undefined, "a failed guess is not bound");
    const out = await login(s, { role: "alice" });
    assert.match(out, /no credentials\/cookie/, "with no proven creds bound, a bare login honestly reports none");
    assert.equal(attempts(s, "alice"), 2);
  } finally {
    close(s);
  }
});

test("a wrong override falls back to the configured credentials in the same call", async () => {
  const s = session({});
  s.driver = new CredsDriver("right-pw") as unknown as PilotSession["driver"];
  s.roleCreds.set("alice", { username: "alice@x.test", password: "right-pw" });
  try {
    const out = await login(s, { role: "alice", username: "alice@x.test", password: "wrong-guess" });
    assert.match(out, /logged in as 'alice'/, `fallback should authenticate, got: ${out}`);
    assert.match(out, /configured credentials worked/);
    assert.deepEqual(s.roleCreds.get("alice"), { username: "alice@x.test", password: "right-pw" });
    assert.equal(attempts(s, "alice"), 1);
  } finally {
    close(s);
  }
});

test("a successful override binds the proven credentials for later logins", async () => {
  const s = session({});
  s.driver = new CredsDriver("minted-9") as unknown as PilotSession["driver"];
  try {
    const out = await login(s, { role: "alice", username: "mint@x.test", password: "minted-9" });
    assert.match(out, /logged in as 'alice'.*bound to this role/, `got: ${out}`);
    assert.deepEqual(s.roleCreds.get("alice"), { username: "mint@x.test", password: "minted-9" });
    // A later bare login() reuses the bound creds.
    const out2 = await login(s, { role: "alice" });
    assert.match(out2, /logged in as 'alice'/);
    assert.doesNotMatch(out2, /no credentials\/cookie/);
    assert.equal(attempts(s, "alice"), 2);
  } finally {
    close(s);
  }
});

test("sign-out chrome on a password-bearing page = live session (the visit counts as mapped)", async () => {
  const s = session({
    [`${base}#/account/settings`]: {
      visibleText: "Account settings — current password, new password",
      links: [`${base}logout`], // sign-out chrome: only rendered when the server believes we're authenticated
    },
  });
  try {
    await navigate(s, `${base}#/account/settings`);
    assert.ok(s.visitedByRole.get("alice")?.size === 1, "live-session evidence makes the visit count as mapped");
  } finally {
    close(s);
  }
});
