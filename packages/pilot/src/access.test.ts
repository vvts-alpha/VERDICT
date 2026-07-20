// Regression for the hybrid auth-bypass verdict (classifyAccess). Verifies that FPs from the CRM review
// fall to not_bypass via the machine veto, and only true bypass candidates remain as needs_judgment.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { classifyAccess } from "./tools.js";

const authedDashboard = { status: 200, body: "<h1>Dashboard</h1><table>secret CRM data ...</table>" };

test("CRM auth-bypass FPs fall to not_bypass via the machine veto", () => {
  // HTML screens like /dashboard: unauth → 302 /login
  assert.equal(classifyAccess({ status: 302, location: "/login?next=/dashboard", body: "" }, authedDashboard).verdict, "not_bypass");
  // APIs like /api/v1/contacts: unauth → 401
  assert.equal(classifyAccess({ status: 401, body: '{"error":"auth required"}' }, { status: 200, body: "[...]" }).verdict, "not_bypass");
  // 403
  assert.equal(classifyAccess({ status: 403, body: "Forbidden" }, authedDashboard).verdict, "not_bypass");
  // unauth 200 but the body is a login page (the "200 means I could see it" FP)
  assert.equal(
    classifyAccess({ status: 200, body: "<form action=/login><input name=password type=password>Sign in</form>" }, authedDashboard).verdict,
    "not_bypass",
  );
  // unauth → 404 (no protected content)
  assert.equal(classifyAccess({ status: 404, body: "Not found" }, authedDashboard).verdict, "not_bypass");
});

test("a real bypass candidate (unauth 200 & non-login) is handed to Claude as needs_judgment", () => {
  const v = classifyAccess(
    { status: 200, body: "<h1>All Contacts</h1><table><tr>alice@corp / 555-1001 ...</table>" },
    { status: 200, body: "<h1>All Contacts</h1><table><tr>alice@corp / 555-1001 ...</table>" },
  );
  assert.equal(v.verdict, "needs_judgment");
});

test("session/comparison unavailable is inconclusive (don't let it claim a bypass)", () => {
  // no authenticated session
  assert.equal(classifyAccess({ status: 200, body: "<h1>data</h1>" }, null).verdict, "inconclusive");
  // the authenticated side is itself login/redirect = can't establish a protected-content baseline
  assert.equal(
    classifyAccess({ status: 200, body: "<h1>data</h1>" }, { status: 200, body: "please log in / password" }).verdict,
    "inconclusive",
  );
});

// A2: needs_judgment now requires the unauth response to REPRODUCE the authed protected content (mechanical body-match),
// so a generic/public 200 can't be recorded as auth-bypass on the model's judgment alone.
test("auth-bypass: unauth 200 with DIFFERENT content than authed → not_bypass (generic page, mechanical veto)", () => {
  const v = classifyAccess(
    { status: 200, body: "<html><body><h1>Welcome</h1><p>Our marketing homepage — sign up for great deals today, everyone is welcome!</p></body></html>" },
    { status: 200, body: '{"account":"12345","balance":9900,"transactions":[{"id":1,"amt":50},{"id":2,"amt":75}],"private":true}' },
  );
  assert.equal(v.verdict, "not_bypass");
});

test("auth-bypass: unauth 200 that REPRODUCES the authed protected content → needs_judgment", () => {
  const secret = '{"account":"12345","balance":9900,"transactions":[{"id":1,"amt":50},{"id":2,"amt":75}],"private":true}';
  assert.equal(classifyAccess({ status: 200, body: secret }, { status: 200, body: secret }).verdict, "needs_judgment");
});
