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

// Regression: a deliberate visit to an auth-shaped page (register/login/account — whose forms legitimately
// contain "password" markers) must NOT mark the role's session blocked. Only a genuine bounce (requested
// != final landing on a login page) or an inline login wall on a non-auth route proves session death.
// (The a-mvie79rl symptom: alice/bob were marked blocked by visiting /#/register while fully logged in.)

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

test("a genuine bounce (requested /account → final /#/login) still marks the role blocked", async () => {
  const s = session({
    [`${base}account`]: { finalUrl: `${base}#/login`, visibleText: "Please log in — password" },
  });
  try {
    await navigate(s, `${base}account`);
    assert.equal(s.roleSurveyBlocked.has("alice"), true, "a real redirect to login proves session death");
    assert.match(s.roleSurveyBlocked.get("alice") ?? "", /login|expired/i);
  } finally {
    close(s);
  }
});

test("an inline login wall on a NON-auth route (no redirect) still marks blocked", async () => {
  const s = session({
    [`${base}products`]: { visibleText: "Please sign in to continue — enter your password" },
  });
  try {
    await navigate(s, `${base}products`);
    assert.equal(s.roleSurveyBlocked.has("alice"), true, "login wall served at the requested URL = dead session");
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
