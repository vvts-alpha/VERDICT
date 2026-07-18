// attended (manual multi-session) liveness detection: bounced back to the login screen = session expired.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { sessionLooksDead, availableRoles } from "./tools.js";
import type { PilotSession, RoleSession } from "./tools.js";
import { roleLabel } from "./run.js";

const sess = (p: Partial<PilotSession>): PilotSession => p as PilotSession;

// Regression: rolesLine (the survey's "log in EACH role before survey_done" gate in run.ts) is built from
// availableRoles(session). In attended mode the roles are pure-manual (no creds, no cookie file) — they live ONLY in
// roleSessions. If availableRoles omitted them, rolesLine collapsed to "none", the auth-surface gate never fired, and an
// attended run (operator logged in by hand) mapped only the PUBLIC surface (~1/3 of the screens). Lock the two branches.
test("availableRoles: attended live sessions (incl. pure-manual roles with no creds/cookie) are listed", () => {
  const rs = new Map<string, RoleSession>([
    ["admin", {} as RoleSession],
    ["user1", {} as RoleSession],
    ["user2", {} as RoleSession],
  ]);
  const s = sess({
    roleSessions: rs,
    roleCreds: new Map(),
    roleCookieFiles: new Map(),
    roleDescriptions: new Map([
      ["admin", "admin"],
      ["user1", "user"],
    ]),
  });
  const line = availableRoles(s)
    .map((r) => (r.description ? `${r.name} (${r.description})` : r.name))
    .join(", ");
  assert.equal(line, "admin (admin), user1 (user), user2"); // all three present → the auth gate fires
});

test("availableRoles: without attended, falls back to credentials + cookie-file keys", () => {
  const s = sess({
    roleSessions: undefined,
    roleCreds: new Map([["test", { username: "t", password: "p" }]]),
    roleCookieFiles: new Map([["viewer", "/tmp/v.cookie"]]),
    roleDescriptions: new Map(),
  });
  assert.deepEqual(
    availableRoles(s)
      .map((r) => r.name)
      .sort(),
    ["test", "viewer"],
  );
});

test("roleLabel: shows the privilege in the manual-login prompt when a description exists", () => {
  const d = new Map([["admin", "full-access admin"]]);
  assert.equal(roleLabel("admin", d), "'admin' (full-access admin)");
  assert.equal(roleLabel("viewer", d), "'viewer'"); // no description → bare name
  assert.equal(roleLabel("admin", undefined), "'admin'");
});

test("login-type URL paths are dead (re-login required)", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/login", visibleText: "Welcome" }), true);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/account/login?next=/", visibleText: "" }), true);
  assert.equal(sessionLooksDead({ url: "https://sso.example.com/auth/realms/x", visibleText: "" }), true);
});

test("visible text with login wording is dead", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/", visibleText: "Please sign in to continue" }), true);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/x", visibleText: "ログインが必要です" }), true);
});

test("an authenticated normal page is alive (not dead)", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/dashboard", visibleText: "Your orders: #1024, #1025" }), false);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/orders/42", visibleText: "Order total $39.00" }), false);
});

test("a URL containing login but outside the boundary (e.g. loginHistory) is not a false positive", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/loginhistory", visibleText: "Recent activity" }), false);
});
