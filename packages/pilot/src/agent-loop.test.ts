import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { runOpenAiAgentLoop, toolParametersSchema, type PilotToolDef, type FetchLike } from "./agent-loop.js";

function toolCall(id: string, name: string, args: unknown) {
    return { id, type: "function", function: { name, arguments: JSON.stringify(args) } };
}
function assistantWithTools(tool_calls: unknown[]) {
    return new Response(JSON.stringify({ choices: [{ message: { content: null, tool_calls } }], usage: { total_tokens: 10 } }), {
        status: 200,
        headers: { "content-type": "application/json" },
    });
}

test("toolParametersSchema converts a zod shape to an object JSON Schema", () => {
    const s = toolParametersSchema({ url: z.string().describe("target"), n: z.number().optional(), kind: z.enum(["a", "b"]) });
    assert.equal(s.type, "object");
    const props = s.properties as Record<string, { type?: string; enum?: string[] }>;
    assert.equal(props.url?.type, "string");
    assert.deepEqual(props.kind?.enum, ["a", "b"]);
    assert.ok(Array.isArray(s.required) && (s.required as string[]).includes("url"));
    assert.equal((s as { $schema?: unknown }).$schema, undefined, "no $schema key for OpenAI");
});

test("runOpenAiAgentLoop drives tool handlers, refuses out-of-allowlist tools, and stops on a done flag", async () => {
    const calls: string[] = [];
    let done = false;
    const bodies: string[] = [];

    const tools: PilotToolDef[] = [
        {
            name: "probe",
            description: "probe something",
            inputSchema: { x: z.number() },
            handler: async (args) => {
                calls.push(`probe:${JSON.stringify(args)}`);
                return { content: [{ type: "text", text: "probe-result-42" }] };
            },
        },
        {
            name: "screen_done",
            description: "finish the screen",
            inputSchema: {},
            handler: async () => {
                calls.push("screen_done");
                done = true;
                return { content: [{ type: "text", text: "ok" }] };
            },
        },
        // A tool that exists but is NOT in the stage allowlist below — must never be dispatched.
        {
            name: "danger",
            description: "should be unreachable",
            inputSchema: {},
            handler: async () => {
                calls.push("DANGER-EXECUTED");
                return { content: [{ type: "text", text: "boom" }] };
            },
        },
    ];

    // Scripted model turns: (1) call probe, (2) try to call a name not offered at all + the un-allowlisted `danger`,
    // (3) call screen_done (sets the done flag → shouldStop).
    let turn = 0;
    const fetchImpl: FetchLike = async (_url, init) => {
        bodies.push(String(init.body));
        turn += 1;
        if (turn === 1) return assistantWithTools([toolCall("c1", "probe", { x: 7 })]);
        if (turn === 2) return assistantWithTools([toolCall("c2", "bash", { cmd: "rm -rf /" }), toolCall("c3", "danger", {})]);
        return assistantWithTools([toolCall("c4", "screen_done", {})]);
    };

    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1",
        apiKey: "k",
        model: "test-model",
        system: "sys",
        goal: "do the thing",
        tools,
        allowed: ["probe", "screen_done"], // `danger` is intentionally excluded
        maxTurns: 10,
        shouldStop: () => done,
        fetchImpl,
    });

    assert.equal(res.stopped, "shouldStop");
    assert.deepEqual(calls, ["probe:{\"x\":7}", "screen_done"], "probe + screen_done ran; danger/bash never dispatched");
    assert.ok(!calls.includes("DANGER-EXECUTED"), "an un-allowlisted tool is never executed");

    // Only allowed tools are offered to the model (danger absent from the request payload)
    const firstReq = JSON.parse(bodies[0]!) as { tools: Array<{ function: { name: string } }> };
    const offered = firstReq.tools.map((t) => t.function.name).sort();
    assert.deepEqual(offered, ["probe", "screen_done"]);

    // The probe result is fed back as a role:tool message on the next request
    const secondReq = JSON.parse(bodies[1]!) as { messages: Array<{ role: string; content: string | null; tool_call_id?: string }> };
    const toolMsg = secondReq.messages.find((m) => m.role === "tool");
    assert.equal(toolMsg?.content, "probe-result-42");

    // The out-of-allowlist calls were answered with a refusal (tool messages on the 3rd request)
    const thirdReq = JSON.parse(bodies[2]!) as { messages: Array<{ role: string; content: string | null }> };
    const refusals = thirdReq.messages.filter((m) => m.role === "tool" && String(m.content).includes("not available"));
    assert.equal(refusals.length, 2, "both bash and danger were refused, not executed");
});

test("runOpenAiAgentLoop tolerates endpoint variance: object arguments, content-part arrays, and missing tool_call ids", async () => {
    const seen: Array<Record<string, unknown>> = [];
    const texts: string[] = [];
    let done = false;
    const tools: PilotToolDef[] = [
        {
            name: "probe",
            description: "p",
            inputSchema: { x: z.number() },
            handler: async (args) => {
                seen.push(args);
                return { content: [{ type: "text", text: "ok" }] };
            },
        },
        { name: "fin", description: "finish", inputSchema: {}, handler: async () => { done = true; return { content: [{ type: "text", text: "done" }] }; } },
    ];
    let turn = 0;
    const fetchImpl: FetchLike = async () => {
        turn += 1;
        if (turn === 1) {
            // content as a parts-array; tool_call with an OBJECT arguments value and NO id
            return new Response(
                JSON.stringify({
                    choices: [{ message: { content: [{ type: "text", text: "working…" }], tool_calls: [{ type: "function", function: { name: "probe", arguments: { x: 5 } } }] } }],
                    usage: { total_tokens: 3 },
                }),
                { status: 200, headers: { "content-type": "application/json" } },
            );
        }
        return new Response(JSON.stringify({ choices: [{ message: { tool_calls: [{ id: "c9", type: "function", function: { name: "fin", arguments: "{}" } }] } }] }), {
            status: 200,
            headers: { "content-type": "application/json" },
        });
    };
    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1",
        model: "m",
        system: "s",
        goal: "g",
        tools,
        allowed: ["probe", "fin"],
        maxTurns: 5,
        onText: (t) => texts.push(t),
        shouldStop: () => done,
        fetchImpl,
    });
    assert.equal(res.stopped, "shouldStop");
    assert.deepEqual(seen, [{ x: 5 }], "object arguments parsed; no JSON.parse crash");
    assert.deepEqual(texts, ["working…"], "content-part array coerced to text");
});

test("runOpenAiAgentLoop surfaces a 200-with-error body as a stage error (not a crash)", async () => {
    const fetchImpl: FetchLike = async () =>
        new Response(JSON.stringify({ error: { message: "quota exceeded" } }), { status: 200, headers: { "content-type": "application/json" } });
    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1",
        model: "m",
        system: "s",
        goal: "g",
        tools: [],
        allowed: [],
        maxTurns: 3,
        shouldStop: () => false,
        fetchImpl,
    });
    assert.equal(res.stopped, "error");
    assert.match(res.error ?? "", /quota exceeded/);
});

test("runOpenAiAgentLoop stops when the model stops calling tools", async () => {
    const fetchImpl: FetchLike = async () =>
        new Response(JSON.stringify({ choices: [{ message: { content: "I'm done." } }], usage: { total_tokens: 5 } }), {
            status: 200,
            headers: { "content-type": "application/json" },
        });
    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1",
        model: "m",
        system: "s",
        goal: "g",
        tools: [],
        allowed: [],
        maxTurns: 5,
        mode: "native",
        shouldStop: () => false,
        fetchImpl,
    });
    assert.equal(res.stopped, "no_tool_calls");
    assert.equal(res.turns, 1);
});

test("text mode: model emits {tool,args} JSON in content (no native tool_calls) and it drives the same handlers + allowlist", async () => {
    const calls: string[] = [];
    let done = false;
    const bodies: string[] = [];
    const tools: PilotToolDef[] = [
        { name: "probe", description: "p", inputSchema: { x: z.number() }, handler: async (a) => { calls.push(`probe:${JSON.stringify(a)}`); return { content: [{ type: "text", text: "res-99" }] }; } },
        { name: "fin", description: "f", inputSchema: {}, handler: async () => { calls.push("fin"); done = true; return { content: [{ type: "text", text: "ok" }] }; } },
        { name: "danger", description: "x", inputSchema: {}, handler: async () => { calls.push("DANGER"); return { content: [{ type: "text", text: "!" }] }; } },
    ];
    const jsonMsg = (obj: unknown) => new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(obj) } }], usage: { total_tokens: 4 } }), { status: 200, headers: { "content-type": "application/json" } });
    let turn = 0;
    const fetchImpl: FetchLike = async (_u, init) => {
        bodies.push(String(init.body));
        turn += 1;
        if (turn === 1) return jsonMsg({ tool: "probe", args: { x: 3 } });
        if (turn === 2) return jsonMsg({ tool: "danger", args: {} }); // out-of-allowlist → refused
        return jsonMsg({ tool: "fin" });
    };
    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1", model: "m", system: "s", goal: "g",
        tools, allowed: ["probe", "fin"], maxTurns: 8, mode: "text", shouldStop: () => done, fetchImpl,
    });
    assert.equal(res.stopped, "shouldStop");
    assert.deepEqual(calls, ["probe:{\"x\":3}", "fin"], "probe + fin ran; danger refused, never executed");
    // text mode must NOT send a tools param (plain chat)
    assert.equal(JSON.parse(bodies[0]!).tools, undefined, "no tools param in text mode");
    // the tool result is fed back as a user message
    const secondReq = JSON.parse(bodies[1]!) as { messages: Array<{ role: string; content: string }> };
    assert.ok(secondReq.messages.some((m) => m.role === "user" && m.content.includes("res-99")));
});

test("auto mode falls back to text when the endpoint ignores the tools param (returns no tool_calls)", async () => {
    const calls: string[] = [];
    let done = false;
    const tools: PilotToolDef[] = [
        { name: "act", description: "a", inputSchema: { v: z.string() }, handler: async (a) => { calls.push(`act:${JSON.stringify(a)}`); return { content: [{ type: "text", text: "did it" }] }; } },
        { name: "fin", description: "f", inputSchema: {}, handler: async () => { done = true; return { content: [{ type: "text", text: "ok" }] }; } },
    ];
    let textTurn = 0;
    const fetchImpl: FetchLike = async (_u, init) => {
        const body = JSON.parse(String(init.body)) as { tools?: unknown };
        if (body.tools) {
            // native attempt: ignore the tools, answer in prose with NO tool_calls → auto should fall back
            return new Response(JSON.stringify({ choices: [{ message: { content: "Sure, I can help with that." } }] }), { status: 200, headers: { "content-type": "application/json" } });
        }
        // text attempt (no tools param): drive the tools via JSON
        textTurn += 1;
        const obj = textTurn === 1 ? { tool: "act", args: { v: "go" } } : { tool: "fin" };
        return new Response(JSON.stringify({ choices: [{ message: { content: JSON.stringify(obj) } }] }), { status: 200, headers: { "content-type": "application/json" } });
    };
    const res = await runOpenAiAgentLoop({
        baseURL: "http://x/v1", model: "m", system: "s", goal: "g",
        tools, allowed: ["act", "fin"], maxTurns: 8, mode: "auto", shouldStop: () => done, fetchImpl,
    });
    assert.equal(res.stopped, "shouldStop");
    assert.deepEqual(calls, ["act:{\"v\":\"go\"}"], "after falling back to text mode, tools actually ran");
});
