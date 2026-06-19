// attended(手動マルチセッション)の死活検知: ログイン画面に戻された = セッション失効と判定する。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { sessionLooksDead } from "./tools.js";
import { roleLabel } from "./run.js";

test("roleLabel: description があれば手動ログイン窓に権限を出す", () => {
  const d = new Map([["admin", "全権管理者"]]);
  assert.equal(roleLabel("admin", d), "'admin' (全権管理者)");
  assert.equal(roleLabel("viewer", d), "'viewer'"); // 説明なしは素のまま
  assert.equal(roleLabel("admin", undefined), "'admin'");
});

test("ログイン系 URL パスは dead(再ログイン要求)", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/login", visibleText: "Welcome" }), true);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/account/login?next=/", visibleText: "" }), true);
  assert.equal(sessionLooksDead({ url: "https://sso.example.com/auth/realms/x", visibleText: "" }), true);
});

test("ログイン文言の可視テキストは dead", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/", visibleText: "Please sign in to continue" }), true);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/x", visibleText: "ログインが必要です" }), true);
});

test("認証済みの通常ページは生存(dead でない)", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/dashboard", visibleText: "Your orders: #1024, #1025" }), false);
  assert.equal(sessionLooksDead({ url: "https://app.example.com/orders/42", visibleText: "Order total $39.00" }), false);
});

test("URL に login を含むが境界外(loginHistory 等)は誤検知しない", () => {
  assert.equal(sessionLooksDead({ url: "https://app.example.com/loginhistory", visibleText: "Recent activity" }), false);
});
