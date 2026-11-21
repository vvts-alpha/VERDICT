import { z } from "zod";
import type { PilotToolDef } from "./agent-loop.js";

export const TOOL_LOADER = "load_assessment_tools";
export const DIAGNOSIS_INITIAL_TOOLS = [
    "get_screen", "get_shared_context", "login", "http_request", "compose_check",
    "record_finding", "coverage_status", "screen_done", "skip_screen",
] as const;

/** Stage-local schema projection. Loading definitions never executes probes or expands the allowlist. */
export function stageToolCatalog(tools: PilotToolDef[], allowed: readonly string[], initial?: readonly string[]): Map<string, PilotToolDef> {
    const allowedSet = new Set(allowed);
    const available = new Map(tools.filter((t) => allowedSet.has(t.name)).map((t) => [t.name, t]));
    if (!initial) return available;
    if (available.has(TOOL_LOADER)) throw new Error("Assessment tool name conflicts with the schema loader");
    const active = new Map(initial.flatMap((name) => available.has(name) ? [[name, available.get(name)!] as const] : []));
    const deferred = [...available.keys()].filter((name) => !active.has(name));
    if (deferred.length === 0) return active;
    active.set(TOOL_LOADER, {
        name: TOOL_LOADER,
        description: `Load full tool definitions before calling specialized tools. This only loads schemas; it runs no assessment. Available tool names: ${deferred.join(", ")}. Load the tools needed for the current plan together.`,
        inputSchema: { names: z.array(z.string()).min(1).max(16) },
        handler: async (args) => {
            const names = args.names as string[];
            if (names.some((name) => !available.has(name))) {
                return { isError: true, content: [{ type: "text", text: "REJECTED: one or more tools are not allowed in this stage. No definitions were loaded." }] };
            }
            for (const name of names) active.set(name, available.get(name)!);
            return { content: [{ type: "text", text: `Loaded tool definitions: ${[...new Set(names)].join(", ")}. Their full instructions and argument schemas are available on the next model turn.` }] };
        },
    });
    return active;
}
