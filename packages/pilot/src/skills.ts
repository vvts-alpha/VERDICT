// Skill plugin framework. A Skill is an operator-enabled extension that contributes veritas TOOLS to the pilot
// (available in the stages it declares) — so new testing capabilities (a disposable mailbox for signup/verify
// flows, an SMS/OTP number, a test card, an upload file, …) plug in by adding tools + config, WITHOUT touching
// core code. Containment is preserved: a skill's tools are still veritas tools (mcp__veritas__*), gated by the
// per-stage allowlist and the onlyVeritasToolsHook — the LLM can only call a skill tool that is enabled AND allowed
// in the current stage. Skills are enabled per-run via the manifest's `skills` block.

import { tool } from "@anthropic-ai/claude-agent-sdk";
import type { SdkMcpToolDefinition } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import type { PilotSession } from "./tools.js";
import { STAGE_TOOLS } from "./tools.js";

export type Stage = keyof typeof STAGE_TOOLS;
/** A tool definition as returned by the SDK's tool() helper (same shape buildTools produces). Matches the SDK's own
 *  Array<SdkMcpToolDefinition<any>> so tools with different input schemas are assignable to a single list. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type SkillTool = SdkMcpToolDefinition<any>;

export interface SkillContext {
    session: PilotSession;
    /** This skill's per-run config from the manifest (e.g. { imap: {...}, address: "…" } for a mailbox skill). */
    config: Record<string, unknown>;
}

export interface Skill {
    id: string;
    description: string;
    /** Stages in which this skill's tools are offered to the model. */
    stages: readonly Stage[];
    /** Build the skill's tools for a run (closes over the session + config, like the core tools do). */
    buildTools(ctx: SkillContext): SkillTool[];
}

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

/** Define a skill tool. Thin wrapper over the SDK's tool() that returns the loose SkillTool type, so a skill's
 *  differently-shaped tools live in one SkillTool[] (the schema generic is invariant, so a single cast is needed). */
export function skillTool<S extends z.ZodRawShape>(
    name: string,
    description: string,
    inputSchema: S,
    handler: (args: z.infer<z.ZodObject<S>>) => Promise<{ content: { type: "text"; text: string }[] }>,
): SkillTool {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return tool(name, description, inputSchema, handler as any) as SkillTool;
}

// ── built-in skills ──────────────────────────────────────────────────────────
// Demo skill: proves the plugin point end to end (a skill adds a tool, gated to its declared stage, reading config).
// Real skills (email/mailbox, sms/otp, test-card, upload-file) follow this exact shape — no core changes needed.
const demoSkill: Skill = {
    id: "demo",
    description: "Demo skill — adds an `demo_echo` tool (proves the skill plugin point).",
    stages: ["diagnose"],
    buildTools: ({ config }) => [
        skillTool(
            "demo_echo",
            "Demo skill tool: echoes the message back (proof that a skill can contribute a tool).",
            { message: z.string() },
            async ({ message }) => txt(`demo_echo[${String(config.prefix ?? "")}]: ${message}`),
        ),
    ],
};

/** The registry of built-in skills, by id. Add a new skill here (or, later, load external ones) — nothing else changes. */
export const SKILLS: Record<string, Skill> = {
    [demoSkill.id]: demoSkill,
};

export interface EnabledSkill {
    skill: Skill;
    config: Record<string, unknown>;
}

/** Resolve the manifest's `skills` block ({ id: config }) into enabled skills. Unknown ids are skipped (with `onUnknown`). */
export function resolveSkills(
    config: Record<string, Record<string, unknown>> | undefined,
    onUnknown?: (id: string) => void,
): EnabledSkill[] {
    const out: EnabledSkill[] = [];
    for (const [id, cfg] of Object.entries(config ?? {})) {
        const skill = SKILLS[id];
        if (skill) out.push({ skill, config: cfg ?? {} });
        else onUnknown?.(id);
    }
    return out;
}

export interface SkillToolEntry {
    tool: SkillTool;
    /** The stages this tool is allowed in (from its skill). */
    stages: readonly Stage[];
}

/** Build every enabled skill's tools ONCE, tagged with the stages they're allowed in (used for both the tool
 *  registry and the per-stage allowlist, so tools aren't rebuilt per stage). */
export function buildSkillTools(session: PilotSession, enabled: EnabledSkill[]): SkillToolEntry[] {
    const out: SkillToolEntry[] = [];
    for (const e of enabled) {
        for (const t of e.skill.buildTools({ session, config: e.config })) out.push({ tool: t, stages: e.skill.stages });
    }
    return out;
}

/** The names of enabled skill tools available in a given stage (merged into that stage's allowlist). */
export function skillToolNamesForStage(skillTools: SkillToolEntry[], stage: Stage): string[] {
    return skillTools.filter((e) => e.stages.includes(stage)).map((e) => (e.tool as { name: string }).name);
}
