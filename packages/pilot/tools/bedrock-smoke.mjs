#!/usr/bin/env node
// Bedrock routing smoke test — one trivial query() through the agent SDK.
// Run from packages/pilot:  node tools/bedrock-smoke.mjs
// Required env:  CLAUDE_CODE_USE_BEDROCK=1 + AWS creds (AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY
//                or AWS_PROFILE) + AWS_REGION (or AWS_DEFAULT_REGION)
// Optional env:  VERDICT_BEDROCK_MODEL = Bedrock model/inference-profile id
//                (e.g. us.anthropic.claude-sonnet-4-5-20250929-v1:0)
import { query } from "@anthropic-ai/claude-agent-sdk";

const model = process.env.VERDICT_BEDROCK_MODEL;
const q = query({
  prompt: "Reply with exactly: ok",
  options: {
    ...(model ? { model } : {}),
    maxTurns: 1,
    tools: [],
    allowedTools: [],
    permissionMode: "bypassPermissions",
  },
});

let sawText = false;
for await (const msg of q) {
  if (msg.type === "assistant") {
    const text = (msg.message?.content ?? []).map((b) => b.text ?? "").join(" ").trim();
    if (text) { sawText = true; console.log("assistant:", text); }
  } else if (msg.type === "result") {
    console.log(`result: ${msg.subtype}${msg.model ? ` model=${msg.model}` : ""}${msg.num_turns != null ? ` turns=${msg.num_turns}` : ""}`);
    if (msg.subtype !== "success") process.exitCode = 1;
  } else if (msg.type === "system" && msg.subtype === "init") {
    console.log(`init: model=${msg.model ?? "?"} apiKeySource=${msg.apiKeySource ?? "?"}`);
  }
}
if (!sawText) { console.error("no assistant text — check env/credentials"); process.exitCode = 1; }
