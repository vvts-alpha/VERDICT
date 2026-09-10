import { createProviderHeaders } from "@veritas/llm";
// Provider-agnostic agentic tool-calling loop for the pilot stages, against an OpenAI-compatible
// /chat/completions endpoint (OpenCodeGo, OpenAI, Ollama, vLLM, LiteLLM, …). This is the non-Anthropic
// alternative to the Claude Agent SDK's query(): same veritas tools, same per-stage allowlist, same
// stop-on-done-flag semantics — but no `claude` subprocess, so a run can be driven entirely by OpenCodeGo.
//
// Containment (the "locked toolbox" trust bet) is preserved structurally: only the stage's allowed tools are
// offered to the model, and the dispatcher refuses any call to a name outside the allowlist — so prompt
// injection cannot reach Bash/Task/etc. (they are never in the tool list, and an invented name is rejected).

import { z } from "zod";
import { zodToJsonSchema } from "zod-to-json-schema";
import { chatCompletionsUrl, extractJson, type FetchLike } from "@veritas/llm";
import { AgentContext, ContextBudgetError, isContextLimitError, type ChatMessage, type ContextUsage, type ToolCall } from "./agent-context.js";
export type { FetchLike } from "@veritas/llm";

/** MCP-style tool result (what the veritas tool handlers return: { content: [{ type:"text", text }] }). */
export interface ToolResult {
    content?: Array<{ type?: string; text?: string }>;
    isError?: boolean;
}

/** The subset of an SDK tool definition this loop needs. buildTools(session) is structurally assignable. */
export interface PilotToolDef {
    name: string;
    description: string;
    /** ZodRawShape (e.g. { url: z.string() }); wrapped with z.object() to emit JSON Schema for the model. */
    inputSchema: Record<string, unknown>;
    handler: (args: Record<string, unknown>, extra?: unknown) => Promise<ToolResult>;
}

export interface OpenAiLoopParams {
    baseURL: string;
    apiKey?: string;
    model: string;
    /** Full system prompt for this stage (no Claude-Code preset — AGENT_PREAMBLE is prepended). */
    system: string;
    /** The stage's initial user instruction (the "goal"). */
    goal: string;
    tools: PilotToolDef[];
    /** Allowlist by bare tool name — only these are offered + accepted (locked toolbox). */
    allowed: readonly string[];
    maxTurns: number;
    /** Total input + output capacity of this stage's model; defaults to 256,000 tokens. */
    contextWindowTokens?: number;
    onContext?: (usage: ContextUsage) => void;
    /** Small, credential-free snapshot of durable progress to accompany a history summary. */
    contextCheckpoint?: () => string;
    timeoutMs?: number;
    onText?: (t: string) => void;
    onToolUse?: (name: string, input: unknown) => void;
    /** Called with each response's total_tokens (real per-call spend, context re-billed each turn). */
    onTokens?: (delta: number) => void;
    /** Stop after the current turn when this returns true (a done tool set its session flag). */
    shouldStop: () => boolean;
    /** Injectable fetch (tests). Defaults to global fetch. */
    fetchImpl?: FetchLike;
    /** Extra HTTP headers. */
    headers?: Record<string, string>;
    /**
     * Tool transport. "native" = OpenAI function-calling (tools param + tool_calls). "text" = a ReAct-style protocol
     * where the model returns a {"tool","args"} JSON object in plain content (works on ANY chat endpoint, no function-
     * calling capability needed). "auto" (default) tries native, then falls back to text if the endpoint rejects the
     * tools param or the model ignores it (returns no tool_calls without doing any work).
     */
    mode?: "native" | "text" | "auto";
}

export interface OpenAiLoopResult {
    turns: number;
    stopped: "shouldStop" | "no_tool_calls" | "max_turns" | "error";
    error?: string;
    /** Context could not be recovered; preserve unfinished work and pause instead of advancing the stage. */
    contextFailure?: boolean;
}

const AGENT_PREAMBLE =
    "You are an autonomous web/API security testing agent. Accomplish the stage goal by CALLING the provided tools — " +
    "do not describe what you would do, actually call the tools. Only the tools listed are available; there is no shell, " +
    "file system, or web access beyond them. When the goal for this stage is complete, call the stage's done/record tool " +
    "(e.g. survey_done / screen_done / record_finding / record_methodology). Keep any prose brief.\n\n";

const MAX_TOOL_RESULT_CHARS = 16000; // cap each tool result so a large HTTP body can't blow up the context

interface ChatResponse {
    choices?: Array<{ message?: { content?: unknown; tool_calls?: ToolCall[] }; finish_reason?: string }>;
    usage?: { total_tokens?: number; prompt_tokens?: number; completion_tokens?: number };
    error?: { message?: string } | string;
}

/** Coerce a chat message's content (string, null, or a [{type:'text',text}] parts array) to a display string. */
function contentToString(content: unknown): string {
    if (typeof content === "string") return content;
    if (Array.isArray(content)) {
        return content
            .map((c) => (c && typeof c === "object" && typeof (c as { text?: unknown }).text === "string" ? (c as { text: string }).text : ""))
            .join("");
    }
    return "";
}

/** Tool-call arguments arrive as a JSON string (spec) OR, on some endpoints, an already-parsed object. Accept both. */
function parseToolArgs(raw: unknown): Record<string, unknown> {
    if (raw && typeof raw === "object") return raw as Record<string, unknown>;
    if (typeof raw === "string" && raw.trim()) {
        try {
            const v = JSON.parse(raw) as unknown;
            return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
        } catch {
            return {};
        }
    }
    return {};
}

/** Convert a ZodRawShape to a JSON Schema object suitable for an OpenAI function's `parameters`. */
export function toolParametersSchema(inputSchema: Record<string, unknown>): Record<string, unknown> {
    const obj = z.object(inputSchema as z.ZodRawShape);
    const schema = zodToJsonSchema(obj, { $refStrategy: "none", target: "jsonSchema7" }) as Record<string, unknown>;
    delete schema.$schema; // OpenAI wants a bare parameters object
    if (schema.type !== "object") return { type: "object", properties: {} };
    return schema;
}

function textOf(r: ToolResult): string {
    const t = (r.content ?? [])
        .map((c) => c.text ?? "")
        .filter(Boolean)
        .join("\n");
    const body = t || "(no output)";
    return body.length > MAX_TOOL_RESULT_CHARS ? `${body.slice(0, MAX_TOOL_RESULT_CHARS)}\n…(truncated)` : body;
}

// Some compatible models require the newer completion-limit spelling. Remember an explicit server rejection
// for the duration of this stage so summaries and subsequent turns use the same bounded transport.
const completionLimitFields = new WeakMap<OpenAiLoopParams, "max_tokens" | "max_completion_tokens">();

/** POST one /chat/completions request with a small retry on 429/5xx. Throws on a terminal failure. `tools` omitted (text mode) = a plain chat call. */
async function chatCompletion(
    p: OpenAiLoopParams,
    messages: ChatMessage[],
    tools?: Array<{ type: "function"; function: { name: string; description: string; parameters: Record<string, unknown> } }>,
    maxTokens?: number,
): Promise<ChatResponse> {
    const doFetch: FetchLike = p.fetchImpl ?? (fetch as FetchLike);
    const url = chatCompletionsUrl(p.baseURL);
    let lastErr = "";
    for (let attempt = 0; attempt < 3; attempt++) {
        const limitField = completionLimitFields.get(p) ?? "max_tokens";
        const body = JSON.stringify({ model: p.model, messages, ...(maxTokens ? { [limitField]: maxTokens } : {}), ...(tools && tools.length ? { tools, tool_choice: "auto" } : {}) });
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), p.timeoutMs ?? 180_000);
        try {
            const res = await doFetch(url, {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    ...(p.apiKey ? { authorization: `Bearer ${p.apiKey}` } : {}),
                    ...(p.headers ?? {}),
                },
                body,
                signal: ac.signal,
            });
            if (res.status === 429 || res.status >= 500) {
                lastErr = `HTTP ${res.status}`;
                await new Promise((r) => setTimeout(r, 800 * (attempt + 1)));
                continue;
            }
            if (!res.ok) {
                const t = await res.text().catch(() => "");
                if (isContextLimitError(t)) throw new ContextBudgetError(t.slice(0, 300));
                if (res.status === 400 && maxTokens && limitField === "max_tokens" && /max_tokens/i.test(t) && /max_completion_tokens/i.test(t)) {
                    completionLimitFields.set(p, "max_completion_tokens");
                    lastErr = "Endpoint requires max_completion_tokens";
                    continue;
                }
                throw new Error(`chat/completions ${res.status}: ${t.slice(0, 300)}`);
            }
            const response = (await res.json()) as ChatResponse;
            if (response.error && isContextLimitError(JSON.stringify(response.error))) throw new ContextBudgetError(JSON.stringify(response.error).slice(0, 300));
            if (response.usage?.total_tokens) p.onTokens?.(response.usage.total_tokens);
            return response;
        } catch (e) {
            if (e instanceof ContextBudgetError) throw e;
            if (ac.signal.aborted) {
                lastErr = `timeout after ${p.timeoutMs ?? 180_000}ms`;
            } else {
                lastErr = String(e instanceof Error ? e.message : e);
                if (attempt >= 2) throw e instanceof Error ? e : new Error(lastErr);
            }
        } finally {
            clearTimeout(timer);
        }
    }
    throw new Error(`chat/completions failed after retries: ${lastErr}`);
}

function createContext(p: OpenAiLoopParams, tools?: unknown): AgentContext {
    return new AgentContext({
        windowTokens: p.contextWindowTokens, tools, onUsage: p.onContext, onText: p.onText, checkpoint: p.contextCheckpoint,
        summarize: async (messages, maxTokens) => {
            const response = await chatCompletion(p, messages, undefined, maxTokens);
            const choice = response.choices?.[0];
            if (response.error || !choice || choice.finish_reason === "length" || choice.message?.tool_calls?.length) {
                throw new Error("The model could not complete the history summary.");
            }
            return contentToString(choice.message?.content);
        },
    });
}

/** Retry a context rejection once after compaction; never replay any already-executed tool handlers. */
async function managedCompletion(p: OpenAiLoopParams, context: AgentContext, messages: ChatMessage[], tools?: Parameters<typeof chatCompletion>[2]): Promise<ChatResponse> {
    await context.prepare(messages);
    for (let attempt = 0; ; attempt++) {
        try {
            const response = await chatCompletion(p, messages, tools, context.reservedTokens);
            context.observe(messages, response.usage?.prompt_tokens);
            return response;
        } catch (e) {
            if (!(e instanceof ContextBudgetError) || attempt > 0) throw e;
            await context.prepare(messages, true);
        }
    }
}

type ToolMap = Map<string, PilotToolDef>;
/** A tool action parsed from a text-mode model reply. */
interface AgentAction {
    tool?: string;
    name?: string;
    args?: unknown;
    arguments?: unknown;
}

/** Dispatch one tool call: allowlist check (locked toolbox) → zod-validate args → run handler → result text. */
async function dispatchTool(byName: ToolMap, name: string, args: Record<string, unknown>, onToolUse?: (n: string, i: unknown) => void): Promise<string> {
    onToolUse?.(name, args);
    const toolDef = byName.get(name);
    if (!toolDef) return `ERROR: tool "${name}" is not available in this stage`; // never dispatched — locked toolbox
    const parsed = z.object(toolDef.inputSchema as z.ZodRawShape).safeParse(args);
    if (!parsed.success) {
        return `ERROR: invalid arguments for ${name}: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ").slice(0, 240)}`;
    }
    try {
        return textOf(await toolDef.handler(parsed.data as Record<string, unknown>, {}));
    } catch (e) {
        return `ERROR: ${String(e instanceof Error ? e.message : e).slice(0, 300)}`;
    }
}

/** Native OpenAI function-calling loop. Returns the turn count + how many tool calls the model actually made (0 = the endpoint ignored the tools param). */
async function runNativeMode(p: OpenAiLoopParams, byName: ToolMap): Promise<OpenAiLoopResult & { toolCalls: number }> {
    const oaTools = [...byName.values()].map((t) => ({
        type: "function" as const,
        function: { name: t.name, description: t.description, parameters: toolParametersSchema(t.inputSchema) },
    }));
    const messages: ChatMessage[] = [
        { role: "system", content: AGENT_PREAMBLE + p.system },
        { role: "user", content: p.goal },
    ];
    const context = createContext(p, oaTools);
    let turns = 0;
    let toolCallCount = 0;
    for (let iter = 0; iter < p.maxTurns; iter++) {
        let resp: ChatResponse;
        try {
            resp = await managedCompletion(p, context, messages, oaTools);
        } catch (e) {
            return { turns, stopped: "error", error: String(e instanceof Error ? e.message : e).slice(0, 200), toolCalls: toolCallCount, ...(e instanceof ContextBudgetError ? { contextFailure: true } : {}) };
        }
        if (resp.error) {
            const em = typeof resp.error === "string" ? resp.error : resp.error.message ?? "unknown";
            return { turns, stopped: "error", error: `endpoint error: ${em.slice(0, 200)}`, toolCalls: toolCallCount };
        }
        if (resp.choices?.[0]?.finish_reason === "length") {
            return { turns, stopped: "error", error: "Model response exceeded the reserved output budget; unfinished work must pause.", contextFailure: true, toolCalls: toolCallCount };
        }
        const msg = resp.choices?.[0]?.message ?? {};
        const toolCalls = (msg.tool_calls ?? []).map((tc, i) => ({ ...tc, id: tc.id ?? `call_${iter}_${i}` }));
        messages.push({ role: "assistant", content: (msg.content as unknown) ?? null, ...(toolCalls.length ? { tool_calls: toolCalls } : {}) });
        const assistantText = contentToString(msg.content).trim();
        if (assistantText) {
            turns += 1;
            p.onText?.(assistantText);
        }
        if (toolCalls.length === 0) return { turns, stopped: "no_tool_calls", toolCalls: toolCallCount };
        for (const tc of toolCalls) {
            toolCallCount += 1;
            const text = await dispatchTool(byName, tc.function?.name ?? "", parseToolArgs(tc.function?.arguments), p.onToolUse);
            messages.push({ role: "tool", tool_call_id: tc.id, content: text });
        }
        if (p.shouldStop()) return { turns, stopped: "shouldStop", toolCalls: toolCallCount };
    }
    return { turns, stopped: "max_turns", toolCalls: toolCallCount };
}

const TEXT_MODE_INSTRUCTIONS = (spec: string): string =>
    "You do NOT have native tool calling here. To use a tool, reply with ONLY a single JSON object and nothing else:\n" +
    '  {"tool": "<tool_name>", "args": { <arguments> }}\n' +
    'When the stage goal is complete, call the stage\'s done/record tool the same way. If there is genuinely nothing left to do, reply {"tool": "stop"}.\n' +
    "After each tool call you will be shown its result and prompted again. Available tools:\n" +
    spec +
    "\n";

/** Text (ReAct) loop: the model emits a {\"tool\",\"args\"} JSON object in plain content. Works on any chat endpoint. */
async function runTextMode(p: OpenAiLoopParams, byName: ToolMap): Promise<OpenAiLoopResult> {
    const spec = [...byName.values()]
        .map((t) => {
            const props = (toolParametersSchema(t.inputSchema).properties as Record<string, unknown>) ?? {};
            return `- ${t.name}: ${t.description}\n    args: ${JSON.stringify(props)}`;
        })
        .join("\n");
    const messages: ChatMessage[] = [
        { role: "system", content: AGENT_PREAMBLE + TEXT_MODE_INSTRUCTIONS(spec) + p.system },
        { role: "user", content: p.goal },
    ];
    const context = createContext(p);
    let turns = 0;
    for (let iter = 0; iter < p.maxTurns; iter++) {
        let resp: ChatResponse;
        try {
            resp = await managedCompletion(p, context, messages); // no tools param — plain chat
        } catch (e) {
            return { turns, stopped: "error", error: String(e instanceof Error ? e.message : e).slice(0, 200), ...(e instanceof ContextBudgetError ? { contextFailure: true } : {}) };
        }
        if (resp.error) {
            const em = typeof resp.error === "string" ? resp.error : resp.error.message ?? "unknown";
            return { turns, stopped: "error", error: `endpoint error: ${em.slice(0, 200)}` };
        }
        if (resp.choices?.[0]?.finish_reason === "length") {
            return { turns, stopped: "error", error: "Model response exceeded the reserved output budget; unfinished work must pause.", contextFailure: true };
        }
        const content = contentToString(resp.choices?.[0]?.message?.content).trim();
        messages.push({ role: "assistant", content });
        // Parse a {tool,args} action from the content (extractJson tolerates fences / surrounding prose).
        let action: AgentAction | null = null;
        try {
            const j = extractJson(content);
            if (j && typeof j === "object") action = j as AgentAction;
        } catch {
            /* no JSON → treat as a final answer */
        }
        const toolName = action?.tool ?? action?.name;
        if (!toolName || toolName === "stop" || toolName === "final" || toolName === "done") {
            if (content) {
                turns += 1;
                p.onText?.(content);
            }
            return { turns, stopped: "no_tool_calls" };
        }
        turns += 1;
        const args = ((action?.args ?? action?.arguments) as Record<string, unknown>) ?? {};
        const result = await dispatchTool(byName, toolName, args, p.onToolUse);
        messages.push({ role: "user", content: `Tool ${toolName} returned:\n${result}\n\nCall the next tool as a JSON object, or reply {"tool":"stop"} if the goal is done.` });
        if (p.shouldStop()) return { turns, stopped: "shouldStop" };
    }
    return { turns, stopped: "max_turns" };
}

/**
 * Run one pilot stage as a tool-calling loop against an OpenAI-compatible endpoint. Mirrors runStage's query()
 * semantics: execute tool calls against the veritas handlers, stop when shouldStop() (a done tool fired), the model
 * stops, or maxTurns is reached. mode "auto" (default) uses native function-calling and falls back to a text (ReAct)
 * protocol if the endpoint rejects the tools param or the model never uses it — so a model without native tool
 * support (but able to emit JSON) still drives the pilot. Returns the assistant text-turn count for the turn budget.
 */
export async function runOpenAiAgentLoop(p: OpenAiLoopParams): Promise<OpenAiLoopResult> {
    p = { ...p, headers: { ...createProviderHeaders(p.baseURL), ...p.headers } };
    const allowedSet = new Set(p.allowed);
    const byName: ToolMap = new Map(p.tools.filter((t) => allowedSet.has(t.name)).map((t) => [t.name, t] as const));
    const mode = p.mode ?? "auto";

    if (mode === "text") return runTextMode(p, byName);

    const res = await runNativeMode(p, byName);
    if (mode === "native") {
        const { toolCalls: _drop, ...rest } = res;
        return rest;
    }
    // auto: fall back to text if the endpoint rejected the tools param, or the model ignored tools (did no work).
    const rejectedTools = res.stopped === "error" && !res.contextFailure && res.toolCalls === 0 && /tool|function|400|404|not support|unsupport|invalid/i.test(res.error ?? "");
    const ignoredTools = res.stopped === "no_tool_calls" && res.toolCalls === 0;
    if (rejectedTools || ignoredTools) {
        p.onText?.("(native tool-calling unavailable on this endpoint — using the text tool protocol)");
        return runTextMode(p, byName);
    }
    const { toolCalls: _drop, ...rest } = res;
    return rest;
}
