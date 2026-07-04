// Token/usage-limit exhaustion detection: when it applies, pause the run (resumable) instead of skipping.
// Don't stop on transient errors (overloaded / maxTurns / network) — those stay best-effort as before.
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
    // actual claude CLI session-limit messages that had fallen through to skip (resets <time>, "session limit")
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
    "overloaded_error: please retry", // 529 = transient, recovers on retry
    "error_max_turns",                // a normal cutoff
    "ECONNRESET socket hang up",      // transient network
    "tool execution failed",
    "",
  ]) {
    assert.equal(isClaudeUsageLimit(s), false, `should NOT pause on: ${s}`);
  }
});

test("structured SDK fields → pause (a primary signal not dependent on strings)", () => {
  // (1) dedicated event: status==='rejected' = being rejected right now
  const e = usageLimitFromMessage({ type: "rate_limit_event", rate_limit_info: { status: "rejected", rateLimitType: "five_hour", resetsAt: 1_900_000_000 } });
  assert.ok(e && /rejected/.test(e), "rate_limit_event rejected should pause");
  assert.ok(/resets /.test(e!), "should surface the reset time from resetsAt");
  // (2) assistant.error
  assert.ok(usageLimitFromMessage({ type: "assistant", error: "rate_limit" }), "assistant rate_limit should pause");
  assert.ok(usageLimitFromMessage({ type: "assistant", error: "billing_error" }), "assistant billing_error should pause");
  // (3) HTTP 429 in result
  assert.ok(usageLimitFromMessage({ type: "result", api_error_status: 429 }), "result 429 should pause");
});

test("structured SDK fields → does NOT pause on transient / normal", () => {
  for (const m of [
    { type: "rate_limit_event", rate_limit_info: { status: "allowed_warning", utilization: 80 } }, // approaching but not reached
    { type: "rate_limit_event", rate_limit_info: { status: "allowed" } },
    { type: "assistant", error: "overloaded" }, // transient = don't stop
    { type: "assistant" },                        // a normal response
    { type: "result", api_error_status: 500 },    // not 429
    { type: "result", subtype: "success" },
    null,
    "plain string",
  ]) {
    assert.equal(usageLimitFromMessage(m), null, `should NOT pause on: ${JSON.stringify(m)}`);
  }
});
