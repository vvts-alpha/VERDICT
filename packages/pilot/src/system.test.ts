import { test } from "node:test";
import assert from "node:assert/strict";
import { operatorContextBlock, outputLanguageBlock, resolveOutputLanguage } from "./system.js";

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

// outputLanguageBlock carries the launch-time output-language choice into every stage's system prompt. It must
// govern PROSE only — the structural tokens that dedup keys, categoryOfFinding, and the app-wide signatures
// parse (the [category] tag, endpoints, payloads, quoted evidence) have to stay verbatim.

test("resolveOutputLanguage: resolves codes and native spellings to a canonical name, unknown passes through", () => {
    assert.equal(resolveOutputLanguage("ja"), "Japanese");
    assert.equal(resolveOutputLanguage(" 日本語 "), "Japanese");
    assert.equal(resolveOutputLanguage("English"), "English");
    assert.equal(resolveOutputLanguage("Valyrian"), "Valyrian");
});

test("outputLanguageBlock: instructs prose in the language while keeping structural tokens verbatim", () => {
    const block = outputLanguageBlock("ja");
    assert.match(block, /in Japanese/);
    assert.match(block, /VERBATIM/);
    assert.match(block, /\[category\]/); // the tag must be named as an exception — categoryOfFinding parses it
    assert.match(block, /CLASS NAMES/); // plan/coverage class names — coarseClass binds them literally
});

test("outputLanguageBlock: composes additively with the stage prompt (same choke point as operatorContextBlock)", () => {
    // Mirrors the runStage composition: [p.system, operatorContextBlock?, outputLanguageBlock?].join("\n\n").
    const stagePrompt = "STAGE RULES: confirm every finding with a negative control + >=2 positive replays.";
    const composed = [stagePrompt, operatorContextBlock("tenant id = last segment"), outputLanguageBlock("ja")].join("\n\n");
    assert.ok(composed.startsWith(stagePrompt), "stage rules must come first");
    assert.ok(composed.indexOf("OPERATOR CONTEXT") < composed.indexOf("OUTPUT LANGUAGE"), "language block appends after operator context");
});
