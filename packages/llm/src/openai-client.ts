// OpenAI-compatible chat-completions client. Speaks the /chat/completions REST shape that OpenAI, OpenCode,
// Ollama (/v1), LM Studio, vLLM, LiteLLM and most gateways expose, so one client covers all of them.
// Implements the SAME one-shot LlmClient contract as ClaudeCliClient: complete({prompt, system?, model?}) -> {text, model}.
// Structured output stays a downstream concern (extractJson + zod at the call sites), identical to the Claude path.

import type { LlmClient, LlmRequest, LlmResponse } from "./types.js";

/** Injectable fetch (tests / custom dispatchers). Global fetch satisfies this. */
export type FetchLike = (url: string, init: RequestInit) => Promise<Response>;

export interface OpenAiClientOptions {
    /** Base URL of an OpenAI-compatible endpoint, e.g. "https://api.openai.com/v1" or "http://localhost:11434/v1".
     *  "/chat/completions" is appended (unless the URL already ends with it). */
    baseURL: string;
    /** Bearer API key. Optional — keyless local endpoints (Ollama / LM Studio) don't need one. Secret; keep it in env. */
    apiKey?: string;
    /** Default model when a request doesn't set one. */
    defaultModel?: string;
    /** Default 120000ms. */
    defaultTimeoutMs?: number;
    /** Extra HTTP headers (org id, gateway token, etc.). */
    headers?: Record<string, string>;
    /** Injectable fetch (defaults to global fetch). */
    fetchImpl?: FetchLike;
}

interface ChatCompletionsResponse {
    model?: string;
    choices?: Array<{ message?: { role?: string; content?: string } }>;
}

/** Append /chat/completions to a base URL, tolerating a trailing slash or an already-suffixed URL. */
export function chatCompletionsUrl(baseURL: string): string {
    const b = baseURL.replace(/\/+$/, "");
    return b.endsWith("/chat/completions") ? b : `${b}/chat/completions`;
}

export class OpenAiClient implements LlmClient {
    constructor(private readonly opts: OpenAiClientOptions) {}

    async complete(req: LlmRequest): Promise<LlmResponse> {
        const model = req.model ?? this.opts.defaultModel;
        if (!model) throw new Error("OpenAiClient: no model — pass a per-request model or set defaultModel (VERDICT_LLM_MODEL)");
        const timeout = req.timeoutMs ?? this.opts.defaultTimeoutMs ?? 120_000;
        const url = chatCompletionsUrl(this.opts.baseURL);
        const messages: Array<{ role: "system" | "user"; content: string }> = [];
        if (req.system) messages.push({ role: "system", content: req.system });
        messages.push({ role: "user", content: req.prompt });

        const doFetch: FetchLike = this.opts.fetchImpl ?? (fetch as FetchLike);
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), timeout);
        try {
            const res = await doFetch(url, {
                method: "POST",
                headers: {
                    "content-type": "application/json",
                    ...(this.opts.apiKey ? { authorization: `Bearer ${this.opts.apiKey}` } : {}),
                    ...(this.opts.headers ?? {}),
                },
                body: JSON.stringify({ model, messages }),
                signal: ac.signal,
            });
            if (!res.ok) {
                const body = await res.text().catch(() => "");
                throw new Error(`OpenAI-compatible endpoint ${url} returned HTTP ${res.status}: ${body.slice(0, 300)}`);
            }
            const json = (await res.json()) as ChatCompletionsResponse;
            const text = json.choices?.[0]?.message?.content;
            if (typeof text !== "string") {
                throw new Error(`OpenAI-compatible response from ${url} had no choices[0].message.content: ${JSON.stringify(json).slice(0, 300)}`);
            }
            return { text, model: json.model ?? model };
        } catch (e) {
            if (ac.signal.aborted) throw new Error(`OpenAI-compatible request to ${url} timed out after ${timeout}ms`);
            throw e instanceof Error ? e : new Error(String(e));
        } finally {
            clearTimeout(timer);
        }
    }
}
