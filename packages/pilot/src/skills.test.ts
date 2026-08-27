import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { resolveSkills, buildSkillTools, skillToolNamesForStage, skillTool, SKILLS, type Skill } from "./skills.js";
import type { PilotSession } from "./tools.js";

// A minimal stand-in session — the demo skill's tools don't touch it (skills that do get the real session at runtime).
const fakeSession = {} as unknown as PilotSession;

test("resolveSkills enables known skills with their config and skips unknown ids", () => {
    const unknown: string[] = [];
    const enabled = resolveSkills({ demo: { prefix: "hi" }, nope: {} }, (id) => unknown.push(id));
    assert.equal(enabled.length, 1);
    assert.equal(enabled[0]?.skill.id, "demo");
    assert.deepEqual(enabled[0]?.config, { prefix: "hi" });
    assert.deepEqual(unknown, ["nope"]);
});

test("resolveSkills on empty/undefined = no skills (core tools only, unchanged)", () => {
    assert.deepEqual(resolveSkills(undefined), []);
    assert.deepEqual(resolveSkills({}), []);
});

test("buildSkillTools builds each enabled skill's tools, tagged with its stages", () => {
    const enabled = resolveSkills({ demo: { prefix: "x" } });
    const tools = buildSkillTools(fakeSession, enabled);
    assert.equal(tools.length, 1);
    assert.equal((tools[0]?.tool as { name: string }).name, "demo_echo");
    assert.deepEqual([...(tools[0]?.stages ?? [])], ["diagnose"]);
});

test("a skill tool is offered ONLY in the stages its skill declares (containment via the stage allowlist)", () => {
    const tools = buildSkillTools(fakeSession, resolveSkills({ demo: {} }));
    assert.deepEqual(skillToolNamesForStage(tools, "diagnose"), ["demo_echo"]); // declared stage → present
    assert.deepEqual(skillToolNamesForStage(tools, "survey"), []); // not declared → absent
    assert.deepEqual(skillToolNamesForStage(tools, "scenario"), []);
});

test("no enabled skills → no extra tool names in any stage (byte-identical allowlist)", () => {
    const tools = buildSkillTools(fakeSession, resolveSkills(undefined));
    for (const stage of ["survey", "diagnose", "scenario", "fingerprint", "methodology", "reconGuess"] as const) {
        assert.deepEqual(skillToolNamesForStage(tools, stage), []);
    }
});

test("a custom skill plugs in with tools + declared stages (the extension contract)", () => {
    const mySkill: Skill = {
        id: "mailbox",
        description: "example",
        stages: ["survey", "diagnose"],
        buildTools: ({ config }) => [
            skillTool("email_address", "get an address", {}, async () => ({ content: [{ type: "text", text: String(config.address ?? "test@x") }] })),
            skillTool("email_inbox", "read inbox", { since: z.number().optional() }, async () => ({ content: [{ type: "text", text: "[]" }] })),
        ],
    };
    // register + resolve (simulating a real skill added to SKILLS)
    SKILLS.mailbox = mySkill;
    try {
        const tools = buildSkillTools(fakeSession, resolveSkills({ mailbox: { address: "vt@example.com" } }));
        assert.equal(tools.length, 2);
        assert.deepEqual(skillToolNamesForStage(tools, "survey").sort(), ["email_address", "email_inbox"]);
        assert.deepEqual(skillToolNamesForStage(tools, "diagnose").sort(), ["email_address", "email_inbox"]);
        assert.deepEqual(skillToolNamesForStage(tools, "scenario"), []); // not declared
    } finally {
        delete SKILLS.mailbox;
    }
});
