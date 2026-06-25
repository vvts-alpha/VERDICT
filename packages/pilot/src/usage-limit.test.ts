// トークン/利用上限の枯渇検出: 該当時はスキップせず run を一時停止(resume 可能)させるための判定。
// 一過性エラー(overloaded / maxTurns / ネットワーク)は止めない — それらは従来どおり best-effort。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isClaudeUsageLimit } from "./run.js";

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
