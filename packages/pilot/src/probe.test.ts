// probe_paths のセッション自滅ガード: logout/signout 系は絶対に踏まない(認証診断を全滅させるため)。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isSessionDestroyingPath } from "./tools.js";

test("logout/signout 系はセッション破壊として検出", () => {
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

test("通常パスは誤検知しない", () => {
  for (const p of [
    "/login",
    "/dashboard",
    "/api/users",
    "/logout-history", // logout を含むが末尾境界でない
    "/about/logoutpolicy",
    "/account/settings",
    "/blog/sign-out-best-practices", // ハイフン続き(境界外)
  ]) {
    assert.equal(isSessionDestroyingPath(p), false, `${p} should NOT be flagged`);
  }
});
