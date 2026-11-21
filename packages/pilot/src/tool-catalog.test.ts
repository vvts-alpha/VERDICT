import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { runOpenAiAgentLoop, toolParametersSchema, type PilotToolDef } from "./agent-loop.js";
import { DIAGNOSIS_INITIAL_TOOLS, stageToolCatalog, TOOL_LOADER } from "./tool-catalog.js";
import { buildTools, STAGE_TOOLS } from "./tools.js";
import type { PilotSession } from "./tools.js";

for (const mode of ["native", "text"] as const) {
    test(`${mode}: deferred schemas load atomically, retain full instructions and cannot expand stage permissions`, async () => {
        let calls = 0;
        let probes = 0;
        let done = false;
        const fullDescription = "EXACT probe instructions: negative control fails and two positive replays succeed.";
        const tools: PilotToolDef[] = [
            { name: "finish", description: "Finish", inputSchema: {}, handler: async () => { done = true; return {}; } },
            { name: "probe", description: fullDescription, inputSchema: { n: z.number().int().min(1) }, handler: async () => { probes++; return {}; } },
            { name: "forbidden", description: "Forbidden", inputSchema: {}, handler: async () => { throw new Error("must never run"); } },
        ];
        const actions = [
            { tool: TOOL_LOADER, args: { names: ["probe", "forbidden"] } },
            { tool: "forbidden", args: {} },
            { tool: TOOL_LOADER, args: { names: ["probe", "probe"] } },
            { tool: "probe", args: { n: 0 } },
            { tool: "probe", args: { n: 1 } },
            { tool: "finish", args: {} },
        ];
        const result = await runOpenAiAgentLoop({
            baseURL: "http://model.test/v1", model: "fake", system: "Keep evidence discipline.", goal: "Test", mode,
            tools, allowed: ["finish", "probe"], initialTools: ["finish"], maxTurns: 10, shouldStop: () => done,
            fetchImpl: async (_url, init) => {
                const request = JSON.parse(String(init.body));
                const spec = mode === "native" ? JSON.stringify(request.tools) : request.messages[0].content;
                assert.equal(spec.includes(fullDescription), calls >= 3, "failed mixed loads cannot partially activate tools");
                assert.equal(spec.includes('"name":"forbidden"'), false);
                if (calls >= 3 && mode === "native") {
                    const defs = request.tools.filter((t: { function: { name: string } }) => t.function.name === "probe");
                    assert.equal(defs.length, 1, "repeated loading does not duplicate schemas");
                    assert.deepEqual(defs[0].function.parameters, toolParametersSchema(tools[1]!.inputSchema));
                }
                if (calls === 3) assert.match(JSON.stringify(request.messages), /not available in this stage/);
                const action = actions[calls++]!;
                return Response.json({ choices: [{ message: mode === "native"
                    ? { content: null, tool_calls: [{ id: `c${calls}`, type: "function", function: { name: action.tool, arguments: JSON.stringify(action.args) } }] }
                    : { content: JSON.stringify(action) } }] });
            },
        });
        assert.equal(result.stopped, "shouldStop");
        assert.equal(probes, 1, "loading a schema and invalid arguments never run a probe");
    });
}

test("diagnosis starts with substantially fewer schema bytes while every allowed tool stays loadable", async () => {
    const defs = buildTools({} as PilotSession) as unknown as PilotToolDef[];
    const all = stageToolCatalog(defs, STAGE_TOOLS.diagnose);
    const active = stageToolCatalog(defs, STAGE_TOOLS.diagnose, DIAGNOSIS_INITIAL_TOOLS);
    const size = (catalog: Map<string, PilotToolDef>) => JSON.stringify([...catalog.values()].map((t) => ({ name: t.name, description: t.description, parameters: toolParametersSchema(t.inputSchema) }))).length;
    const before = size(all);
    const after = size(active);
    assert.ok(after < before * 0.3, `initial schemas ${after} bytes vs ${before} bytes`);
    const loader = active.get(TOOL_LOADER)!;
    for (const name of all.keys()) {
        await loader.handler({ names: [name] });
        assert.equal(active.get(name), all.get(name), "use original schemas, instructions and handlers");
    }
    assert.equal(active.size, all.size + 1);
});


for (const mode of ["native", "text"] as const) {
    test(`${mode}: loaded schemas survive repeated history summaries without replaying probes`, async () => {
        let probes = 0;
        let modelTurns = 0;
        let summaries = 0;
        const description = "Full loaded probe instructions remain available after compaction.";
        const result = await runOpenAiAgentLoop({
            baseURL: "http://model.test/v1", model: "fake", system: "Preserve evidence", goal: "Explore", mode,
            tools: [{ name: "probe", description, inputSchema: {}, handler: async () => {
                probes++;
                return { content: [{ type: "text", text: `ev-${probes} ${"x".repeat(4000)}` }] };
            } }],
            allowed: ["probe"], initialTools: [], maxTurns: 22, contextWindowTokens: 16_384, shouldStop: () => false,
            fetchImpl: async (_url, init) => {
                const request = JSON.parse(String(init.body));
                if (String(request.messages[0].content).startsWith("Summarize an ongoing")) {
                    summaries++;
                    return Response.json({ choices: [{ message: { content: "Evidence references remain in the assessment store. Continue the original goal." } }] });
                }
                const spec = mode === "native" ? JSON.stringify(request.tools) : request.messages[0].content;
                assert.equal(spec.includes(description), modelTurns > 0);
                const action = modelTurns++ === 0 ? { tool: TOOL_LOADER, args: { names: ["probe"] } } : { tool: "probe", args: {} };
                return Response.json({ choices: [{ message: mode === "native"
                    ? { content: null, tool_calls: [{ id: `c${modelTurns}`, type: "function", function: { name: action.tool, arguments: JSON.stringify(action.args) } }] }
                    : { content: JSON.stringify(action) } }] });
            },
        });
        assert.equal(result.stopped, "max_turns");
        assert.ok(summaries >= 2);
        assert.equal(probes, 21, "only requested probes run; summaries and catalog loading do no target work");
    });
}
