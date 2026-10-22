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
