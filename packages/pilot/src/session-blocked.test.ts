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

// Regression: an observation NEVER marks a role's session blocked — a 403 may be a scope gap, a 401 a
// per-resource decision, a redirect a routing quirk, and login-ish content appears on register/i18n/
// settings pages of a live session. The ONLY authoritative blocked source is a failed login() itself.
// A dead session simply stops accumulating session-bound visits (the role stays unfinished; survey_done
// names it and the model resolves it through login). (The a-mvie79rl symptom: alice/bob were marked
// blocked by visiting /#/register while fully logged in.)

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
    roleSurveyBlocked: new Map<string, string>(),
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
const close = (s: PilotSession): void => (s as unknown as { store: { close(): void } }).store.close();

test("deliberate visit to /#/register (password fields, live session) does NOT mark the role blocked", async () => {
  const s = session({
    [`${base}#/register`]: { visibleText: "Register — Email, Password, Repeat Password, Security Question" },
  });
  try {
    const out = await navigate(s, `${base}#/register`);
    assert.doesNotMatch(out, /ERROR/);
    assert.equal(s.roleSurveyBlocked.has("alice"), false, "register page visit is not a session bounce");
  } finally {
    close(s);
  }
});

test("a redirect bounce to a login page does NOT mark the role blocked (it just doesn't count)", async () => {
  const s = session({
    [`${base}account`]: { finalUrl: `${base}#/login`, visibleText: "Please log in" },
  });
  try {
    await navigate(s, `${base}account`);
    assert.equal(s.roleSurveyBlocked.has("alice"), false, "a bounce is ambiguous — never a blocked verdict");
    assert.equal(s.visitedByRole.get("alice")?.size ?? 0, 0, "nor does a bounced visit count as mapped");
  } finally {
    close(s);
  }
});

test("an inline login wall on a NON-auth route does NOT mark blocked", async () => {
  const s = session({
    [`${base}products`]: {
      visibleText: "Please sign in to continue — enter your password",
      forms: [{ action: `${base}login`, method: "POST", fields: [{ name: "email", type: "email" }, { name: "password", type: "password" }] }],
    },
  });
  try {
    await navigate(s, `${base}products`);
    assert.equal(s.roleSurveyBlocked.has("alice"), false, "even a real login form can't prove the session died");
  } finally {
    close(s);
  }
});

test("a static asset whose body mentions login words (i18n JSON) does NOT mark the role blocked", async () => {
  const s = session({
    [`${base}assets/i18n/en.json`]: { visibleText: '{"SIGN_IN":"Sign in","PASSWORD":"Password","LOGIN":"Login","FORGOT_PASSWORD":"Forgot password"}' },
  });
  try {
    const out = await navigate(s, `${base}assets/i18n/en.json`);
    assert.doesNotMatch(out, /ERROR/);
    assert.equal(s.roleSurveyBlocked.has("alice"), false, "a JSON resource's content is not a login wall");
  } finally {
    close(s);
  }
});

test("the ONLY authoritative blocked source: a login() with no usable material records the role blocked", async () => {
  const s = session({});
  try {
    const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
    const out = (await t.handler({ role: "alice" }, {})).content[0]!.text;
    assert.match(out, /no credentials\/cookie/);
    assert.equal(s.roleSurveyBlocked.has("alice"), true, "a failed login() is the one reliable blocked verdict");
  } finally {
    close(s);
  }
});

test("a dropped attended session RESPAWNS on login() instead of blocking (the a-mvk7tmnr regression)", async () => {
  const s = session({});
  // Attended: roleSessions map exists but 'alice' is absent (context was dropped); a respawn hook
  // re-establishes it — the alternative was the live Sessions-tab browser staying up while login()
  // answered "no credentials" and marked the role blocked.
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
    const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
    const out = (await t.handler({ role: "alice" }, {})).content[0]!.text;
    assert.equal(respawned, 1, "login() must try the attended respawn before declaring no material");
    assert.match(out, /switched to live attended session/);
    assert.equal(s.roleSurveyBlocked.has("alice"), false, "a respawned session is not blocked");
    assert.ok(s.roleSessions.get("alice"), "the respawned session re-enters roleSessions for the warm set");
  } finally {
    close(s);
  }
});

test("a FAILED attended respawn still falls through to an honest blocked", async () => {
  const s = session({});
  s.roleSessions = new Map();
  s.respawnAttended = async () => {
    throw new Error("launch failed");
  };
  try {
    const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
    const out = (await t.handler({ role: "alice" }, {})).content[0]!.text;
    assert.match(out, /no credentials\/cookie/);
    assert.equal(s.roleSurveyBlocked.has("alice"), true);
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

test("login() refuses an UNCONFIGURED role — no respawn, no phantom blocked mark", async () => {
  const s = session({});
  s.roleSessions = new Map();
  let spawned = 0;
  s.respawnAttended = async () => (spawned++, null);
  try {
    const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
    const out = (await t.handler({ role: "ghost" }, {})).content[0]!.text;
    assert.match(out, /unknown role/);
    assert.equal(spawned, 0, "a typo'd role must never spawn a real browser");
    assert.equal(s.roleSurveyBlocked.has("ghost"), false, "nor pollute the blocked ledger");
  } finally {
    close(s);
  }
});

test("a material-less live session falls through to configured creds instead of blocking", async () => {
  const s = session({});
  const d = Object.assign(new FakeDriver({}), { saveScreenshot: async () => false, sessionCookieHeader: async () => "", bearerToken: async () => null });
  s.roleSessions = new Map([["alice", { driver: d as unknown as import("@veritas/crawler").PlaywrightDriver, cookie: "" }]]);
  s.roleCreds = new Map([["alice", { username: "a", password: "p" }]]);
  try {
    const t = buildTools(s).find((x) => (x as { name: string }).name === "login") as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
    const out = (await t.handler({ role: "alice" }, {})).content[0]!.text;
    // The empty operator session must NOT win the verdict — creds-configured roles still get the
    // machine login attempt (which honestly fails here: FakeDriver can't complete a real login).
    assert.doesNotMatch(out, /carries no session material/, "empty live session must not pre-empt the creds path");
    assert.match(out, /did not complete|login error|blocked/i);
    assert.ok(s.roleSurveyBlocked.has("alice"), "the honest outcome is still recorded");
  } finally {
    close(s);
  }
});

test("sign-out chrome on a password-bearing page = live session (counted, not blocked)", async () => {
  const s = session({
    [`${base}#/account/settings`]: {
      visibleText: "Account settings — current password, new password",
      links: [`${base}logout`], // sign-out chrome: only rendered when the server believes we're authenticated
    },
  });
  try {
    await navigate(s, `${base}#/account/settings`);
    assert.equal(s.roleSurveyBlocked.has("alice"), false);
    assert.ok(s.visitedByRole.get("alice")?.size === 1, "live-session evidence makes the visit count as mapped");
  } finally {
    close(s);
  }
});
