// probe_paths self-destruct guard: never hit logout/signout paths (they wipe out all auth diagnosis).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isSessionDestroyingPath } from "./tools.js";

test("logout/signout paths are detected as session-destroying", () => {
  for (const p of [
    "/logout",
    "/manage/logout",
    "https://central.sophos.com/logout",
    "/api/logout",
    "/auth/logout",
    "/account/sign-out",
    "/sso/logout",
    "/saml/logout?ret=/",
    "/oauth2/logout",
    "/signout",
    "/sign_out",
    "/logoff",
  ]) {
    assert.equal(isSessionDestroyingPath(p), true, `${p} should be flagged`);
  }
});

test("ordinary paths are not false-flagged", () => {
  for (const p of [
    "/login",
    "/dashboard",
    "/api/users",
    "/logout-history", // contains "logout" but not at a trailing boundary
    "/about/logoutpolicy",
    "/account/settings",
    "/blog/sign-out-best-practices", // hyphen continues (out of boundary)
  ]) {
    assert.equal(isSessionDestroyingPath(p), false, `${p} should NOT be flagged`);
  }
});
