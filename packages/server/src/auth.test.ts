// WebUI 認証の署名 Cookie ロジック(sign/verify・期限・改竄検知)を browser/server なしで検証。
import { test } from "node:test";
import assert from "node:assert/strict";

import { signSession, verifySession } from "./auth.js";

test("signSession/verifySession round-trips and rejects tampering", () => {
  const now = 1_700_000_000_000;
  const tok = signSession("hunter2", now);
  assert.match(tok, /^\d+\.[0-9a-f]{64}$/);
  assert.equal(verifySession("hunter2", tok, now), true);
  assert.equal(verifySession("hunter2", tok, now + 1000), true);
  // 別パスワードでは検証不可
  assert.equal(verifySession("wrong", tok, now), false);
  // HMAC 改竄
  assert.equal(verifySession("hunter2", tok.replace(/.$/, "0"), now), false);
  // 形式不正
  assert.equal(verifySession("hunter2", "garbage", now), false);
});

test("verifySession enforces expiry window (7 days)", () => {
  const now = 1_700_000_000_000;
  const tok = signSession("pw", now);
  assert.equal(verifySession("pw", tok, now + 7 * 24 * 3600 * 1000 - 1), true);
  assert.equal(verifySession("pw", tok, now + 7 * 24 * 3600 * 1000 + 1), false); // 期限切れ
  assert.equal(verifySession("pw", tok, now - 120_000), false); // 未来発行(時計ズレ上限超)
});
