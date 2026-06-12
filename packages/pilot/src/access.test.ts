// auth-bypass の hybrid 判定(classifyAccess)の回帰。CRM レビューで出た FP が機械 veto で
// not_bypass に落ちること、真の bypass 候補だけ needs_judgment に残ることを検証する。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { classifyAccess } from "./tools.js";

const authedDashboard = { status: 200, body: "<h1>Dashboard</h1><table>secret CRM data ...</table>" };

test("CRM の auth-bypass FP は機械 veto で not_bypass", () => {
  // /dashboard など HTML 画面: 未認証 → 302 /login
  assert.equal(classifyAccess({ status: 302, location: "/login?next=/dashboard", body: "" }, authedDashboard).verdict, "not_bypass");
  // /api/v1/contacts など API: 未認証 → 401
  assert.equal(classifyAccess({ status: 401, body: '{"error":"auth required"}' }, { status: 200, body: "[...]" }).verdict, "not_bypass");
  // 403
  assert.equal(classifyAccess({ status: 403, body: "Forbidden" }, authedDashboard).verdict, "not_bypass");
  // 未認証 200 だが本文がログインページ(「200 だから見れた」型 FP)
  assert.equal(
    classifyAccess({ status: 200, body: "<form action=/login><input name=password type=password>Sign in</form>" }, authedDashboard).verdict,
    "not_bypass",
  );
  // 未認証 → 404(保護コンテンツ無し)
  assert.equal(classifyAccess({ status: 404, body: "Not found" }, authedDashboard).verdict, "not_bypass");
});

test("真の bypass 候補(未認証200 & 非ログイン)は needs_judgment で Claude に渡す", () => {
  const v = classifyAccess(
    { status: 200, body: "<h1>All Contacts</h1><table><tr>alice@corp / 555-1001 ...</table>" },
    { status: 200, body: "<h1>All Contacts</h1><table><tr>alice@corp / 555-1001 ...</table>" },
  );
  assert.equal(v.verdict, "needs_judgment");
});

test("セッション/比較不能は inconclusive(bypass を主張させない)", () => {
  // 認証セッション無し
  assert.equal(classifyAccess({ status: 200, body: "<h1>data</h1>" }, null).verdict, "inconclusive");
  // 認証側もログイン/リダイレクト = 保護コンテンツの基準が取れない
  assert.equal(
    classifyAccess({ status: 200, body: "<h1>data</h1>" }, { status: 200, body: "please log in / password" }).verdict,
    "inconclusive",
  );
});
