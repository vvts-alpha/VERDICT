// @veritas/agent — Phase2 ビジネスロジック: 仮説生成(LLM)→ 証拠規律で検証。

export {
  generateHypotheses,
  ruleHypotheses,
  buildHypothesisPrompt,
  HYPOTHESIS_SYSTEM_PROMPT,
} from "./hypothesize.js";
export type { HypothesizeOptions } from "./hypothesize.js";

export { verifyHypothesis } from "./verify.js";
export type { VerifyOutcome } from "./verify.js";

export { assessScreenLogic, assessLogicInventory } from "./agent.js";
export type { AssessScreenHooks, LogicResult, LogicInventoryResult } from "./agent.js";

export { authDiffScreen } from "./authdiff.js";
export type { RoleContext, AuthDiffOutcome } from "./authdiff.js";
