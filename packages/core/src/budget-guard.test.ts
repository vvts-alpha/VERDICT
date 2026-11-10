import { test } from "node:test";
import assert from "node:assert/strict";
import { recordTokens } from "./budget-guard.js";
import type { BudgetState } from "./types/budget.js";

const base = (): BudgetState => ({
  limits: { maxTokens: 1e9, maxWallClockMs: 1e9, maxTotalRequests: 1e9, maxRequestsPerTarget: 1e9 },
  startedAt: new Date().toISOString(),
  tokensUsed: 0,
  totalRequests: 0,
  requestsPerTarget: {},
});

test("recordTokens accumulates cache-read/creation buckets separately from the plain split", () => {
  let b = base();
  b = recordTokens(b, 120, { inputTokens: 100, outputTokens: 20, cacheReadTokens: 60, cacheCreationTokens: 15 });
  b = recordTokens(b, 30, { inputTokens: 10, outputTokens: 20, cacheReadTokens: 5 });
  assert.equal(b.tokensUsed, 150);
  assert.equal(b.inputTokens, 110);      // cache buckets are already included in the caller's inputTokens
  assert.equal(b.outputTokens, 40);
  assert.equal(b.cacheReadTokens, 65);
  assert.equal(b.cacheCreationTokens, 15); // absent on the second call → preserved, not zeroed
});

test("recordTokens leaves cache fields absent when the provider never reports them", () => {
  let b = base();
  b = recordTokens(b, 50, { inputTokens: 40, outputTokens: 10 });
  b = recordTokens(b, 30); // estimate-only call
  assert.equal(b.cacheReadTokens, undefined);
  assert.equal(b.cacheCreationTokens, undefined);
  assert.equal(b.inputTokens, 40);
});
