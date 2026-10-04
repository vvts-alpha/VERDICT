import { test } from "node:test";
import assert from "node:assert/strict";
import { boundedToolText, MAX_TOOL_RESULT_CHARS } from "./tool-output.js";

test("oversized JSON is explicitly abbreviated without returning broken JSON", () => {
  const exact = JSON.stringify({ text: "x".repeat(MAX_TOOL_RESULT_CHARS - 11) });
  assert.equal(exact.length, MAX_TOOL_RESULT_CHARS);
  assert.equal(boundedToolText(exact), exact);
  const output = boundedToolText(JSON.stringify({ text: "\"\\\nあ".repeat(10000) }));
  assert.ok(output.length <= MAX_TOOL_RESULT_CHARS);
  assert.equal(JSON.parse(output).truncated, true);
});
