import { test } from "node:test";
import assert from "node:assert/strict";
import { operatorContextBlock } from "./system.js";

// operatorContextBlock carries operator-supplied target FACTS into a stage's system prompt. The safety-critical
// property is that it is ADDITIVE and clearly fenced as facts-not-overrides — it must never read as license to
// disable the evidence-discipline / scope / safety rules the stage prompt already sets.

test("operatorContextBlock: includes the operator text verbatim (trimmed)", () => {
    const block = operatorContextBlock("  auth is a JWT in the X-Auth header  ");
    assert.match(block, /auth is a JWT in the X-Auth header/);
    // trimmed: no leading/trailing whitespace bleed from the operator input into the block body
    assert.ok(!block.includes("  auth is a JWT"));
});

test("operatorContextBlock: labels the text as facts that do NOT override the rules", () => {
    const block = operatorContextBlock("tenant id = last path segment");
    assert.match(block, /OPERATOR CONTEXT/);
    // must state it does not override safety/scope/evidence discipline (containment stays intact)
    assert.match(block, /do NOT override/i);
    assert.match(block, /evidence-discipline/i);
});

test("operatorContextBlock: is appended AFTER the stage prompt (additive, never a replacement)", () => {
    // Simulate the runStage composition: `${p.system}\n\n${operatorContextBlock(ctx)}`. The stage's own rules
    // (here a stand-in SAFETY line) must remain and precede the operator context.
    const stagePrompt = "STAGE RULES: confirm every finding with a negative control + >=2 positive replays.";
    const composed = `${stagePrompt}\n\n${operatorContextBlock("API is GraphQL at /graphql")}`;
    assert.ok(composed.startsWith(stagePrompt), "stage rules must come first");
    assert.ok(composed.indexOf("STAGE RULES") < composed.indexOf("OPERATOR CONTEXT"), "operator context must be appended after the stage rules");
    assert.match(composed, /GraphQL at \/graphql/);
});
