import { test } from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
import { runOpenAiAgentLoop, type FetchLike, type PilotToolDef } from "./agent-loop.js";
import type { ChatMessage } from "./agent-context.js";

type Request = { messages: ChatMessage[]; tools?: unknown; max_tokens?: number };
const reply = (message: unknown, finish_reason = "stop", usage = { total_tokens: 10 }) => new Response(JSON.stringify({ choices: [{ message, finish_reason }], usage }), { status: 200 });
const native = (n: number) => ({ content: null, tool_calls: [{ id: `c-${n}`, type: "function", function: { name: "probe", arguments: JSON.stringify({ n }) } }] });
const isSummary = (r: Request) => String(r.messages[0]?.content).startsWith("Summarize an ongoing");

function assertPaired(messages: ChatMessage[]): void {
    const pending = new Set<string>();
    for (const m of messages) {
        if (m.role === "assistant") {
            assert.equal(pending.size, 0);
            for (const call of m.tool_calls ?? []) pending.add(call.id!);
        } else if (m.role === "tool") {
            assert.ok(pending.delete(m.tool_call_id!), "each result belongs to a retained call");
        }
    }
    assert.equal(pending.size, 0);
}

for (const mode of ["native", "text"] as const) {
    test(`${mode}: long exploration continues across summaries with bounded requests and no repeated tool execution`, async () => {
        const executed: number[] = [];
        const requests: Request[] = [];
        let summaries = 0;
        let turns = 0;
        let tokens = 0;
        const tools: PilotToolDef[] = [{ name: "probe", description: "Read one in-scope page", inputSchema: { n: z.number() }, handler: async (args) => {
            executed.push(args.n as number);
            return { content: [{ type: "text", text: `evidence-${args.n} ${"x".repeat(4000)}` }] };
        } }];
        const fetchImpl: FetchLike = async (_url, init) => {
            const request = JSON.parse(String(init.body)) as Request;
            requests.push(request);
            assert.ok(request.max_tokens! > 0 && request.max_tokens! < 16384);
            if (isSummary(request)) {
                summaries++;
                assert.equal(request.tools, undefined, "summary calls cannot execute tools");
                return reply({ content: "Visited pages have stored evidence; pending /admin. Continue exploration." });
            }
            if (mode === "native") assertPaired(request.messages);
            turns++;
            return reply(mode === "native" ? native(turns) : { content: JSON.stringify({ tool: "probe", args: { n: turns } }) });
        };
        const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "scope and evidence rules", goal: "Explore", tools, allowed: ["probe"], mode,
            maxTurns: 22, contextWindowTokens: 16384, shouldStop: () => false, fetchImpl, onTokens: (n) => { tokens += n; }, contextCheckpoint: () => "pending /admin; latest evidence ev-42" });
        assert.equal(result.stopped, "max_turns");
        assert.deepEqual(executed, Array.from({ length: 22 }, (_, i) => i + 1));
        assert.ok(summaries >= 2, "summarizes repeatedly across a long exploration");
        assert.equal(tokens, requests.length * 10, "summary usage counts toward cumulative cost");
        const resumed = requests.find((r) => !isSummary(r) && r.messages.some((m) => String(m.content).includes("Earlier conversation summary")));
        assert.ok(resumed);
        assert.equal(resumed.messages[0]!.content, requests[0]!.messages[0]!.content);
        assert.equal(resumed.messages[1]!.content, "Explore");
        assert.match(JSON.stringify(resumed.messages), /ev-42/);
    });
}

test("summary truncation becomes a resumable context failure without retrying the tools via text fallback", async () => {
    let executed = 0;
    let summaryCalls = 0;
    const tools: PilotToolDef[] = [{ name: "probe", description: "p", inputSchema: {}, handler: async () => { executed++; return { content: [{ text: "x".repeat(16000) }] }; } }];
    const fetchImpl: FetchLike = async (_url, init) => {
        const r = JSON.parse(String(init.body)) as Request;
        if (isSummary(r)) { summaryCalls++; return reply({ content: "partial summary" }, "length"); }
        assert.ok(r.tools, "never switches to text mode after a context error");
        return reply(native(executed + 1));
    };
    const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "s", goal: "g", tools, allowed: ["probe"], maxTurns: 10, contextWindowTokens: 8192, shouldStop: () => false, fetchImpl });
    assert.equal(result.stopped, "error");
    assert.equal(result.contextFailure, true);
    assert.equal(executed, 2);
    assert.equal(summaryCalls, 1);
});

test("oversized initial instructions stop before contacting the model", async () => {
    const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "x".repeat(40_000), goal: "g", tools: [], allowed: [], maxTurns: 10, contextWindowTokens: 8192, shouldStop: () => false,
        fetchImpl: async () => { throw new Error("must not send an oversized initial prompt"); } });
    assert.equal(result.contextFailure, true);
    assert.match(result.error!, /instructions and tools exceed/);
});

test("provider context rejection compacts and retries the request without replaying completed tools", async () => {
    let executed = 0;
    let rejected = false;
    let summaries = 0;
    const tools: PilotToolDef[] = [{ name: "probe", description: "p", inputSchema: {}, handler: async () => { executed++; return { content: [{ text: "x".repeat(4000) }] }; } }];
    const fetchImpl: FetchLike = async (_url, init) => {
        const r = JSON.parse(String(init.body)) as Request;
        if (isSummary(r)) { summaries++; return reply({ content: "Explored /one, evidence ev-1. Next /two." }); }
        if (executed === 2 && !rejected) { rejected = true; return new Response('{"error":{"code":"context_length_exceeded","message":"maximum context length exceeded"}}', { status: 400 }); }
        assertPaired(r.messages);
        return reply(native(executed + 1));
    };
    const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "s", goal: "g", tools, allowed: ["probe"], maxTurns: 4, contextWindowTokens: 256000, shouldStop: () => false, fetchImpl });
    assert.equal(result.stopped, "max_turns");
    assert.equal(executed, 4);
    assert.equal(summaries, 1);
});

test("large cumulative total_tokens is not treated as the current context size", async () => {
    let summaries = 0;
    const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "s", goal: "g", tools: [], allowed: [], maxTurns: 2, mode: "native", contextWindowTokens: 8192, shouldStop: () => false,
        fetchImpl: async (_url, init) => {
            if (isSummary(JSON.parse(String(init.body)) as Request)) summaries++;
            return reply(native(1), "stop", { total_tokens: 1_000_000 });
        } });
    assert.equal(result.stopped, "max_turns");
    assert.equal(summaries, 0);
});

test("completion reserve supports endpoints that require max_completion_tokens without dropping the bound", async () => {
    const bodies: Array<Request & { max_completion_tokens?: number }> = [];
    const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "s", goal: "g", tools: [], allowed: [], maxTurns: 1, mode: "native", shouldStop: () => false,
        fetchImpl: async (_url, init) => {
            const r = JSON.parse(String(init.body)) as Request & { max_completion_tokens?: number };
            bodies.push(r);
            if (r.max_tokens) return new Response('{"error":{"message":"max_tokens is not supported. Use max_completion_tokens instead."}}', { status: 400 });
            return reply({ content: "Done" });
        } });
    assert.equal(result.stopped, "no_tool_calls");
    assert.equal(bodies.length, 2);
    assert.equal(bodies[0]!.max_tokens, bodies[1]!.max_completion_tokens);
    assert.equal(bodies[1]!.max_tokens, undefined);
});

test("truncated model replies pause before executing potentially incomplete tool calls", async () => {
    for (const mode of ["native", "text"] as const) {
        let executed = 0;
        const tools: PilotToolDef[] = [{ name: "probe", description: "p", inputSchema: {}, handler: async () => { executed++; return { content: [{ text: "ok" }] }; } }];
        const result = await runOpenAiAgentLoop({ baseURL: "http://model.test/v1", model: "m", system: "s", goal: "g", tools, allowed: ["probe"], maxTurns: 1, mode, shouldStop: () => false,
            fetchImpl: async () => reply(mode === "native" ? native(1) : { content: '{"tool":"probe","args":{}}' }, "length") });
        assert.equal(result.contextFailure, true);
        assert.equal(executed, 0);
    }
});
