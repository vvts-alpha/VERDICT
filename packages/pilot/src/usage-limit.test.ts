// トークン/利用上限の枯渇検出: 該当時はスキップせず run を一時停止(resume 可能)させるための判定。
// 一過性エラー(overloaded / maxTurns / ネットワーク)は止めない — それらは従来どおり best-effort。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isClaudeUsageLimit, usageLimitFromMessage } from "./run.js";

test("detects Claude subscription usage-limit phrasings → pause", () => {
  for (const s of [
    "Claude AI usage limit reached",
    "Your limit will reset at 3pm",
    "5-hour limit reached",
    "rate limit exceeded",
    "rate_limit_error",
    "HTTP 429 Too Many Requests",
    "You have exceeded your quota",
    "insufficient credit",
    "out of tokens",
    // 実際に skip に落ちた claude CLI のセッション上限メッセージ(resets <time>, "session limit")
    "Claude Code returned an error result: You've hit your session limit · resets 12:50am (Asia/Tokyo)",
    "You've hit your session limit · resets 12:50am (Asia/Tokyo)",
    "session limit reached",
    "Approaching your usage limit · resets 9:00pm",
  ]) {
    assert.equal(isClaudeUsageLimit(s), true, `should pause on: ${s}`);
  }
});

test("does NOT pause on transient / unrelated errors", () => {
  for (const s of [
    "overloaded_error: please retry", // 529 = 一過性、リトライで回復
    "error_max_turns",                // 正常な打ち切り
    "ECONNRESET socket hang up",      // ネットワークの一過性
    "tool execution failed",
    "",
  ]) {
    assert.equal(isClaudeUsageLimit(s), false, `should NOT pause on: ${s}`);
  }
});

test("structured SDK fields → pause (文字列に依存しない一次シグナル)", () => {
  // (1) 専用イベント: status==='rejected' = 今まさに弾かれている
  const e = usageLimitFromMessage({ type: "rate_limit_event", rate_limit_info: { status: "rejected", rateLimitType: "five_hour", resetsAt: 1_900_000_000 } });
  assert.ok(e && /rejected/.test(e), "rate_limit_event rejected should pause");
  assert.ok(/resets /.test(e!), "should surface the reset time from resetsAt");
  // (2) assistant.error
  assert.ok(usageLimitFromMessage({ type: "assistant", error: "rate_limit" }), "assistant rate_limit should pause");
  assert.ok(usageLimitFromMessage({ type: "assistant", error: "billing_error" }), "assistant billing_error should pause");
  // (3) result の HTTP 429
  assert.ok(usageLimitFromMessage({ type: "result", api_error_status: 429 }), "result 429 should pause");
});

test("structured SDK fields → does NOT pause on transient / normal", () => {
  for (const m of [
    { type: "rate_limit_event", rate_limit_info: { status: "allowed_warning", utilization: 80 } }, // 接近だが未到達
    { type: "rate_limit_event", rate_limit_info: { status: "allowed" } },
    { type: "assistant", error: "overloaded" }, // 一過性 = 止めない
    { type: "assistant" },                        // 通常の応答
    { type: "result", api_error_status: 500 },    // 429 以外
    { type: "result", subtype: "success" },
    null,
    "plain string",
  ]) {
    assert.equal(usageLimitFromMessage(m), null, `should NOT pause on: ${JSON.stringify(m)}`);
  }
});
