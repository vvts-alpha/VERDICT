/** Model context windows include input, tool definitions, and room for the response. */
export interface ModelContextSettings {
  deepContextTokens?: number;
  lightContextTokens?: number;
}

export const DEFAULT_CONTEXT_TOKENS = 256_000;
export const MIN_CONTEXT_TOKENS = 8_192;

/** Accept an unset value or an explicit token count; never silently replace an invalid limit. */
export function parseContextTokens(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  const n = typeof value === "string" && /^\d+$/.test(value.trim()) ? Number(value) : value;
  if (typeof n !== "number" || !Number.isSafeInteger(n) || n < MIN_CONTEXT_TOKENS) {
    throw new Error(`Max context must be a whole number of at least ${MIN_CONTEXT_TOKENS} tokens.`);
  }
  return n;
}

export function modelContextWindows(env: Record<string, string | undefined>): { deep: number; light: number } {
  const deep = parseContextTokens(env.VERDICT_LLM_CONTEXT_TOKENS) ?? DEFAULT_CONTEXT_TOKENS;
  const light = parseContextTokens(env.VERDICT_LLM_FAST_CONTEXT_TOKENS)
    ?? (!env.VERDICT_LLM_FAST_MODEL || env.VERDICT_LLM_FAST_MODEL === env.VERDICT_LLM_MODEL ? deep : DEFAULT_CONTEXT_TOKENS);
  return { deep, light };
}
