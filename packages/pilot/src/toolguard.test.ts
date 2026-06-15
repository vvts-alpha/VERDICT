// pilot のツール allowlist: veritas MCP ツールだけ許可し、ハーネスの組み込み/エスケープツールは拒否する。
// (大きな inventory で methodology stage が Monitor/Skill/Agent に逃げて Bash 禁止をすり抜けた回帰の防止)

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isPilotAllowedTool } from "./run.js";

test("veritas MCP ツールは許可", () => {
  for (const n of [
    "mcp__veritas__get_inventory",
    "mcp__veritas__record_methodology",
    "mcp__veritas__http_request",
    "mcp__veritas__record_finding",
  ]) {
    assert.equal(isPilotAllowedTool(n), true, n);
  }
});

test("ハーネス/組み込みツールは拒否(Bash 禁止すり抜けの防止)", () => {
  for (const n of [
    "Bash", "Read", "Write", "Monitor", "Skill", "Agent", "Task",
    "ToolSearch", "TaskCreate", "TaskGet", "Workflow", "WebFetch", "Glob",
    "mcp__other__tool", // 別 MCP も不可
  ]) {
    assert.equal(isPilotAllowedTool(n), false, n);
  }
});
