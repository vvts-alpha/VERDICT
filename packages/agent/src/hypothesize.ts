// DESIGN §7.4 — 画面の screenType/description/params/apis/labels から攻撃仮説(Hypothesis)を生成。
// LLM(構造化出力)を主とし、失敗時は object_ref param からルールベースで IDOR 仮説を補完。

import { z } from "zod";
import type { Hypothesis, Screen } from "@veritas/core";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";

const HYPO_CLASSES = [
  "idor",
  "privilege_escalation",
  "price_tampering",
  "qty_tampering",
  "state_skip",
  "mass_assignment",
  "race",
  "auth_bypass",
  "info_disclosure",
  "other",
] as const;

const DraftSchema = z.object({
  class: z.enum(HYPO_CLASSES),
  statement: z.string().min(1).max(300),
  testPlan: z.string().min(1).max(600),
});
const ResponseSchema = z.object({ hypotheses: z.array(DraftSchema).max(8) });

export const HYPOTHESIS_SYSTEM_PROMPT =
  "You are a web application security tester reasoning about business-logic flaws on one screen. " +
  "Given its structured surface, propose concrete, testable attack hypotheses. " +
  "Respond with ONLY a JSON object {\"hypotheses\":[{class,statement,testPlan}]} — no prose, no fences.";

export function buildHypothesisPrompt(screen: Screen): string {
  const surface = {
    urlTemplate: screen.urlTemplate,
    screenType: screen.screenType,
    description: screen.description,
    labels: screen.labels,
    params: screen.params.map((p) => ({ name: p.name, in: p.in, guessedType: p.guessedType, example: p.example })),
    apis: screen.apis.map((a) => ({ method: a.method, urlTemplate: a.urlTemplate, auth: a.auth })),
  };
  return [
    "Propose business-logic attack hypotheses for this screen.",
    "",
    "SCREEN SURFACE:",
    JSON.stringify(surface, null, 2),
    "",
    `Each hypothesis: { "class": one of [${HYPO_CLASSES.join(", ")}], "statement": one sentence, "testPlan": concrete steps }.`,
    'Focus on object_ref params (IDOR), price/qty params (tampering), and auth boundaries. Respond with ONLY {"hypotheses":[...]}.',
  ].join("\n");
}

let counter = 0;
function hypothesisId(screenId: string): string {
  counter += 1;
  return `h-${screenId}-${counter.toString().padStart(2, "0")}`;
}

function toHypothesis(screen: Screen, draft: z.infer<typeof DraftSchema>): Hypothesis {
  return {
    id: hypothesisId(screen.screenId),
    screenId: screen.screenId,
    class: draft.class,
    statement: draft.statement,
    testPlan: draft.testPlan,
    status: "queued",
    evidenceIds: [],
  };
}

/** IDOR 仮説をルールで生成(LLM 不在/失敗時の保険)。
 *  GET API(id付き)を持つ画面、または post-login で object_ref path param を持つページが対象。 */
export function ruleHypotheses(screen: Screen): Hypothesis[] {
  const hasIdParam = screen.params.some((p) => p.guessedType === "object_ref" || p.guessedType === "id");
  const hasGetApiWithId = screen.apis.some((a) => a.method.toUpperCase() === "GET" && /\{[^}]+\}/.test(a.urlTemplate));
  const isPostLoginIdPage =
    screen.authState === "post-login" &&
    /\{[^}]+\}/.test(screen.urlTemplate) &&
    screen.params.some((p) => p.in === "path" && (p.guessedType === "object_ref" || p.guessedType === "id"));
  if (!hasIdParam || (!hasGetApiWithId && !isPostLoginIdPage)) return [];
  return [
    toHypothesis(screen, {
      class: "idor",
      statement: `Object reference on ${screen.urlTemplate} may allow accessing other users' objects (IDOR)`,
      testPlan: "Enumerate a neighbouring object id (page or API); a valid neighbour returns data while an invalid id does not.",
    }),
  ];
}

export interface HypothesizeOptions {
  model?: string;
  timeoutMs?: number;
  /** LLM を使わずルールのみ(テスト/オフライン) */
  ruleOnly?: boolean;
}

export async function generateHypotheses(
  screen: Screen,
  client: LlmClient | null,
  opts: HypothesizeOptions = {},
): Promise<{ hypotheses: Hypothesis[]; usedFallback: boolean }> {
  if (opts.ruleOnly || !client) {
    return { hypotheses: ruleHypotheses(screen), usedFallback: true };
  }
  try {
    const res = await client.complete({
      system: HYPOTHESIS_SYSTEM_PROMPT,
      prompt: buildHypothesisPrompt(screen),
      ...(opts.model ? { model: opts.model } : {}),
      ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}),
    });
    const parsed = ResponseSchema.safeParse(extractJson(res.text));
    if (!parsed.success || parsed.data.hypotheses.length === 0) {
      return { hypotheses: ruleHypotheses(screen), usedFallback: true };
    }
    return { hypotheses: parsed.data.hypotheses.map((d) => toHypothesis(screen, d)), usedFallback: false };
  } catch {
    return { hypotheses: ruleHypotheses(screen), usedFallback: true };
  }
}
