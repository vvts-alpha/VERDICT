import { parseContextTokens, type ModelContextSettings } from "@veritas/core/llm-context";

/** Desktop service names map onto the two supported runtime transports. */
export type ModelProvider = "claude-cli" | "opencode-go" | "orcarouter" | "other";

// Official endpoint references: https://opencode.ai/docs/go/ and https://docs.orcarouter.ai/introduction
export const MODEL_PROVIDERS: Record<ModelProvider, { label: string; baseURL: string }> = {
    "claude-cli": { label: "Claude", baseURL: "" },
    "opencode-go": { label: "OpenCodeGo", baseURL: "https://opencode.ai/zen/go/v1" },
    orcarouter: { label: "OrcaRouter", baseURL: "https://api.orcarouter.ai/v1" },
    other: { label: "Other", baseURL: "" },
};

/** Migrate the old openai setting without changing its URL, credentials, or models. */
export function normalizeModelProvider(provider: unknown, baseURL?: string): ModelProvider {
    if (typeof provider === "string" && Object.hasOwn(MODEL_PROVIDERS, provider)) return provider as ModelProvider;
    if (provider === "openai") {
        const url = baseURL?.trim().replace(/\/+$/, "");
        for (const p of ["opencode-go", "orcarouter"] as const) {
            if (url === MODEL_PROVIDERS[p].baseURL) return p;
        }
        return "other";
    }
    return "claude-cli";
}

export function modelConnectionEnv(s: ModelContextSettings & { provider: ModelProvider; baseURL?: string; apiKey?: string; deepModel?: string; lightModel?: string }): Record<string, string> {
    const provider = normalizeModelProvider(s.provider, s.baseURL);
    const env: Record<string, string> = { VERDICT_LLM_PROVIDER: provider === "claude-cli" ? "claude-cli" : "openai" };
    const baseURL = s.baseURL?.trim() || MODEL_PROVIDERS[provider].baseURL;
    if (baseURL) env.VERDICT_LLM_BASE_URL = baseURL;
    if (s.apiKey) env.VERDICT_LLM_API_KEY = s.apiKey;
    if (s.deepModel) env.VERDICT_LLM_MODEL = s.deepModel;
    if (s.lightModel) env.VERDICT_LLM_FAST_MODEL = s.lightModel;
    if (provider !== "claude-cli") {
        const deep = parseContextTokens(s.deepContextTokens);
        const light = parseContextTokens(s.lightContextTokens);
        if (deep !== undefined) env.VERDICT_LLM_CONTEXT_TOKENS = String(deep);
        if (light !== undefined) env.VERDICT_LLM_FAST_CONTEXT_TOKENS = String(light);
    }
    return env;
}
