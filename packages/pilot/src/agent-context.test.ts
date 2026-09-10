import { test } from "node:test";
import assert from "node:assert/strict";
import { AgentContext, ContextBudgetError, type ChatMessage, type ContextUsage } from "./agent-context.js";

const head: ChatMessage[] = [{ role: "system", content: "Preserve scope and evidence discipline." }, { role: "user", content: "Map https://example.test" }];
function round(n: number, size = 4000): ChatMessage[] {
    return [
        { role: "assistant", content: null, tool_calls: [{ id: `call-${n}`, function: { name: "navigate", arguments: `{"n":${n}}` } }] },
        { role: "tool", tool_call_id: `call-${n}`, content: `screen-${n} evidence-${n} ${"x".repeat(size)}` },
    ];
}

test("summary keeps original instructions, recent complete tool exchanges, and a durable checkpoint", async () => {
    const messages = [...head, ...Array.from({ length: 12 }, (_, i) => round(i)).flat()];
    const summaries: string[] = [];
    const context = new AgentContext({ windowTokens: 16_384,
        checkpoint: () => "Current role: user; pending: /admin; evidence: ev-42",
        summarize: async (request) => { summaries.push(String(request[1]!.content)); return "Visited /login. Next: /admin. evidence-0 is a negative control, not a finding."; },
    });
    await context.prepare(messages);
    assert.deepEqual(messages.slice(0, 2), head);
    assert.deepEqual(messages.slice(-4), [...round(10), ...round(11)]);
    assert.match(String(messages[2]!.content), /pending: \/admin; evidence: ev-42/);
    assert.match(String(messages[2]!.content), /negative control, not a finding/);
    assert.ok(summaries.join("").includes("evidence-0"));
    assert.ok(context.estimate(messages) < 16384 - context.reservedTokens);
});

test("oversized history is summarized in bounded chunks without dropping any transcript text", async () => {
    const messages = [...head, ...round(1, 100_000), ...round(2, 100_000)];
    const original = JSON.stringify(messages.slice(2));
    const chunks: string[] = [];
    const context = new AgentContext({ windowTokens: 8192, summarize: async (request) => {
        assert.ok(context.estimate(request, null) + context.reservedTokens < 8192);
        const input = JSON.parse(String(request[1]!.content)) as { transcriptChunk: string; previousSummary: string };
        if (chunks.length) assert.equal(input.previousSummary, "screen-1, screen-2, evidence references preserved.");
        chunks.push(input.transcriptChunk);
        return "screen-1, screen-2, evidence references preserved.";
    } });
    await context.prepare(messages);
    assert.ok(chunks.length > 1);
    assert.equal(chunks.join(""), original);
    assert.equal(messages.some((m) => m.role === "tool"), false, "the oversized exchanges were replaced as whole rounds");
});

test("failed or overlong summaries preserve the original history instead of dropping old evidence", async () => {
    for (const result of ["", "x".repeat(20_000), new Error("provider unavailable")]) {
        const messages = [...head, ...round(1, 16000), ...round(2, 16000)];
        const original = structuredClone(messages);
        const context = new AgentContext({ windowTokens: 8192, summarize: async () => {
            if (result instanceof Error) throw result;
            return result;
        } });
        await assert.rejects(context.prepare(messages), ContextBudgetError);
        assert.deepEqual(messages, original);
    }
});

test("prompt usage calibrates the estimate upward and tools count toward remaining context", async () => {
    const samples: ContextUsage[] = [];
    const context = new AgentContext({ windowTokens: 256000, tools: [{ description: "x".repeat(6000) }], onUsage: (u) => samples.push(u), summarize: async () => { throw new Error("unexpected summary"); } });
    const messages = [...head, ...round(1, 100)];
    await context.prepare(messages);
    const before = samples[0]!.inputTokens;
    assert.ok(before > 2000, "tool schemas are included");
    context.observe(messages, before * 2);
    await context.prepare(messages);
    assert.ok(samples[1]!.inputTokens >= before * 2);
    assert.equal(samples[1]!.remainingTokens, 256000 - samples[1]!.inputTokens - samples[1]!.reservedTokens);
});
