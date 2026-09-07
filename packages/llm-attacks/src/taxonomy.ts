/**
 * OWASP LLM Top 10 (2025) attack classes for the red-team mode, `llm-`-prefixed to disambiguate from
 * web-app finding categories in a shared report.
 */
export const LLM_CATEGORIES = [
  "llm-prompt-injection-direct",
  "llm-prompt-injection-indirect",
  "llm-sensitive-info-disclosure",
  "llm-improper-output-handling",
  "llm-excessive-agency",
  "llm-system-prompt-leakage",
  "llm-vector-embedding-weakness",
  "llm-unbounded-consumption",
  "llm-cross-tenant-leak",
  "llm-memory-persistence",
] as const;

export type LlmCategory = (typeof LLM_CATEGORIES)[number];

export interface OwaspRef {
  /** OWASP LLM Top 10 (2025) identifier, e.g. "LLM01". */
  id: string;
  /** Official 2025 title. */
  title: string;
}

/** Map each red-team category to its OWASP LLM Top 10 (2025) entry. */
export const OWASP_LLM_2025: Record<LlmCategory, OwaspRef> = {
  "llm-prompt-injection-direct": { id: "LLM01", title: "Prompt Injection" },
  "llm-prompt-injection-indirect": { id: "LLM01", title: "Prompt Injection" },
  "llm-sensitive-info-disclosure": { id: "LLM02", title: "Sensitive Information Disclosure" },
  "llm-improper-output-handling": { id: "LLM05", title: "Improper Output Handling" },
  "llm-excessive-agency": { id: "LLM06", title: "Excessive Agency" },
  "llm-system-prompt-leakage": { id: "LLM07", title: "System Prompt Leakage" },
  "llm-vector-embedding-weakness": { id: "LLM08", title: "Vector and Embedding Weaknesses" },
  "llm-unbounded-consumption": { id: "LLM10", title: "Unbounded Consumption" },
  // cross-tenant leakage is a sensitive-information disclosure across the tenant boundary (LLM02 variant).
  "llm-cross-tenant-leak": { id: "LLM02", title: "Sensitive Information Disclosure" },
  // persistent injection that survives into brand-new conversations (LLM01 variant).
  "llm-memory-persistence": { id: "LLM01", title: "Prompt Injection" },
};
