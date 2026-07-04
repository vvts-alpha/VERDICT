// @veritas/pilot — Claude-led autonomous assessment (the Agent SDK tool-use loop).
export { runPilot } from "./run.js";
export type { RunPilotOptions, PilotResult } from "./run.js";
export { buildTools, STAGE_TOOLS } from "./tools.js";
export type { PilotSession } from "./tools.js";
export { SURVEY_PROMPT, METHODOLOGY_PROMPT, DIAGNOSE_PROMPT } from "./system.js";
export { verifyBurpFindings, triageAndDeepDiveBurp } from "./verify.js";
export type { VerifyBurpDeps, VerifyBurpResult, TriageDeepDiveResult } from "./verify.js";
