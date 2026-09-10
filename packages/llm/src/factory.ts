// Provider selection for the one-shot LlmClient. Default is claude-cli (Max subscription auth) so an
// unconfigured install is byte-identical to `new ClaudeCliClient(...)`; setting VERDICT_LLM_PROVIDER=openai
// (+ base URL / key / model) routes the deterministic pipeline through an OpenAI-compatible endpoint instead.
//
// NB: this covers the *one-shot* complete() path (label / assess / logic / server chat). The pilot's
// agentic loop still runs on the Claude Agent SDK (query()) and is NOT affected by this — see the 2026 roadmap.

import { ClaudeCliClient } from "./claude-cli.js";
import { OpenAiClient } from "./openai-client.js";
import type { LlmClient } from "./types.js";

export type LlmProvider = "claude-cli" | "openai";

export interface LlmProviderConfig {
    provider: LlmProvider;
    /** Model to use (default for the client). */
    model?: string;
    /** OpenAI-compatible endpoint base URL (required for provider "openai"). */
    baseURL?: string;
    /** Bearer API key (openai; optional for keyless local endpoints). */
    apiKey?: string;
    /** Default request timeout (ms). */
    timeoutMs?: number;
    /** Extra HTTP headers (openai). */
    headers?: Record<string, string>;
}

export interface LlmConfigOverrides {
    /** The operator's explicitly chosen model (a --model flag / manifest.model). Wins over env + provider default. */
    explicitModel?: string;
    /** The historical Claude default model for this call site. Applied ONLY when the provider is claude-cli
     *  (so non-Claude providers never get a Claude model id silently posted to them — they fail loudly instead). */
    claudeDefaultModel?: string;
    /** Force a provider regardless of env (rarely needed). */
    provider?: LlmProvider;
}

function parseProvider(v: string | undefined): LlmProvider {
    const s = (v ?? "").trim().toLowerCase();
    if (s === "openai" || s === "openai-compatible" || s === "oai") return "openai";
    return "claude-cli"; // default: empty, "claude", "claude-cli", "cli", or anything unrecognized
}

/**
 * Resolve the active LLM provider config from env (+ per-site overrides).
 *
 * Env: VERDICT_LLM_PROVIDER (claude-cli | openai), VERDICT_LLM_BASE_URL, VERDICT_LLM_API_KEY (or OPENAI_API_KEY),
 *      VERDICT_LLM_MODEL. Model precedence: explicit override (--model/manifest) > VERDICT_LLM_MODEL >
 *      (claude-cli only) the call site's historical Claude default. For a non-Claude provider with no model
 *      resolved, `model` is left unset and makeLlmClient() throws a clear error rather than guessing.
 */
export function resolveLlmConfig(env: Record<string, string | undefined> = process.env, ov: LlmConfigOverrides = {}): LlmProviderConfig {
    const provider = ov.provider ?? parseProvider(env.VERDICT_LLM_PROVIDER);
    const model = ov.explicitModel ?? env.VERDICT_LLM_MODEL ?? (provider === "claude-cli" ? ov.claudeDefaultModel : undefined);
    const cfg: LlmProviderConfig = { provider };
    if (model) cfg.model = model;
    if (provider === "openai") {
        if (env.VERDICT_LLM_BASE_URL) cfg.baseURL = env.VERDICT_LLM_BASE_URL;
        const apiKey = env.VERDICT_LLM_API_KEY ?? env.OPENAI_API_KEY;
        if (apiKey) cfg.apiKey = apiKey;
    }
    return cfg;
}

/** Build the LlmClient for a resolved config. Default provider (claude-cli) is byte-identical to a direct ClaudeCliClient. */
export function makeLlmClient(cfg: LlmProviderConfig): LlmClient {
    if (cfg.provider === "openai") {
        if (!cfg.baseURL) throw new Error("LLM provider 'openai' requires a base URL — set VERDICT_LLM_BASE_URL (e.g. https://api.openai.com/v1)");
        if (!cfg.model) throw new Error("LLM provider 'openai' requires a model — set VERDICT_LLM_MODEL or pass --model (no default model exists for non-Claude providers)");
        return new OpenAiClient({
            baseURL: cfg.baseURL,
            ...(cfg.apiKey ? { apiKey: cfg.apiKey } : {}),
            ...(cfg.model ? { defaultModel: cfg.model } : {}),
            ...(cfg.timeoutMs ? { defaultTimeoutMs: cfg.timeoutMs } : {}),
            ...(cfg.headers ? { headers: cfg.headers } : {}),
        });
    }
    // default: claude-cli (Max subscription auth) — byte-identical to `new ClaudeCliClient({ defaultModel: cfg.model })`
    return new ClaudeCliClient({
        ...(cfg.model ? { defaultModel: cfg.model } : {}),
        ...(cfg.timeoutMs ? { defaultTimeoutMs: cfg.timeoutMs } : {}),
    });
}

/** Convenience: resolve config from env (+ per-site overrides) and build the client in one call. */
export function createLlmClient(ov: LlmConfigOverrides = {}, env?: Record<string, string | undefined>): LlmClient {
    return makeLlmClient(resolveLlmConfig(env, ov));
}
