// attended (manual multi-session) liveness detection: bounced back to the login screen = session expired.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { sessionLooksDead } from "./tools.js";
import { roleLabel } from "./run.js";

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
