// pilot tool allowlist: allow only the veritas MCP tools; deny the harness built-in / escape tools.
// (prevents the regression where, on a large inventory, the methodology stage escaped to Monitor/Skill/Agent and slipped past the Bash ban)

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isPilotAllowedTool } from "./run.js";

test("veritas MCP tools are allowed", () => {
  for (const n of [
    "mcp__veritas__get_inventory",
    "mcp__veritas__record_methodology",
    "mcp__veritas__http_request",
    "mcp__veritas__record_finding",
  ]) {
    assert.equal(isPilotAllowedTool(n), true, n);
  }
});

test("harness / built-in tools are denied (prevents slipping past the Bash ban)", () => {
  for (const n of [
    "Bash", "Read", "Write", "Monitor", "Skill", "Agent", "Task",
    "ToolSearch", "TaskCreate", "TaskGet", "Workflow", "WebFetch", "Glob",
    "mcp__other__tool", // a different MCP is not allowed either
  ]) {
    assert.equal(isPilotAllowedTool(n), false, n);
  }
});
