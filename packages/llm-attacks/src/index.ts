// @veritas/llm-attacks — LLM / AI-assistant red-team mode.
// Slice 1: the offline-testable deterministic core (canary oracle + taxonomy). No workspace deps yet;
// chat-adapter (Playwright), Finding/report wiring, and the adaptive runStage loop land in later slices.
export * from "./canary.js";
export * from "./taxonomy.js";
export * from "./adapter.js";
export * from "./fake.js";
export * from "./oracle.js";
export * from "./driver.js";
export * from "./browser-adapter.js";
export * from "./fake-driver.js";
export * from "./redteam.js";
export * from "./corpus.js";
