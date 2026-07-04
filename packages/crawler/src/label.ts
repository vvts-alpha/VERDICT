// DESIGN §6.5 — LLM labeling (structured output + type validation). The LLM overrides/augments the M1 rule labels.
// On LLM failure / malformed output, fall back to the rule labels (M1).

import { z } from "zod";
import type { AssessmentStore, Screen } from "@veritas/core";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";

const SCREEN_TYPES = [
  "listing",
  "detail",
  "form",
  "auth",
  "dashboard",
  "search",
  "upload",
  "payment",
  "admin",
  "other",
] as const;

const GUESSED_TYPES = [
  "object_ref",
  "id",
  "enum",
  "free_text",
  "file",
  "price",
  "qty",
  "unknown",
] as const;

const ScreenLabelSchema = z.object({
  screenType: z.enum(SCREEN_TYPES),
  description: z.string().min(1).max(500),
  labels: z.array(z.string().min(1).max(40)).max(12),
  params: z.array(z.object({ name: z.string(), guessedType: z.enum(GUESSED_TYPES) })).optional(),
});

export type ScreenLabel = z.infer<typeof ScreenLabelSchema>;

export const LABEL_SYSTEM_PROMPT =
  "You are a web application security recon assistant. Given one screen's structured surface " +
  "(URL template, parameters, observed API calls), classify it for downstream vulnerability testing. " +
  "Respond with ONLY a JSON object — no prose, no markdown fences.";

export function buildLabelPrompt(screen: Screen): string {
  const surface = {
    urlTemplate: screen.urlTemplate,
    observedUrls: screen.observedUrls.slice(0, 3),
    ruleGuess: { screenType: screen.screenType, labels: screen.labels },
    params: screen.params.map((p) => ({ name: p.name, in: p.in, example: p.example, guessedType: p.guessedType })),
    apis: screen.apis.map((a) => ({ method: a.method, urlTemplate: a.urlTemplate, auth: a.auth })),
  };
  return [
    "Classify this web screen for security testing.",
    "",
    "SCREEN SURFACE:",
    JSON.stringify(surface, null, 2),
    "",
    "Output a JSON object with exactly these fields:",
    `- "screenType": one of [${SCREEN_TYPES.join(", ")}]`,
    '- "description": one sentence stating what the screen does AND the most likely vulnerability angle ' +
      '(e.g. "order detail; IDOR via order id may expose other users\' orders")',
    '- "labels": array of short attack-hint tags (e.g. idor-candidate, pii, payment, ssrf-candidate, auth, price-tampering-candidate)',
    `- "params" (optional): array of {name, guessedType} where guessedType is one of [${GUESSED_TYPES.join(", ")}]`,
    "",
    "Respond with ONLY the JSON object.",
  ].join("\n");
}

export type ParseResult =
  | { ok: true; label: ScreenLabel }
  | { ok: false; error: string };

export function parseScreenLabel(text: string): ParseResult {
  let raw: unknown;
  try {
    raw = extractJson(text);
  } catch (e) {
    return { ok: false, error: `extractJson: ${(e as Error).message}` };
  }
  const parsed = ScreenLabelSchema.safeParse(raw);
  if (!parsed.success) {
    return { ok: false, error: parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ") };
  }
  return { ok: true, label: parsed.data };
}

/** Apply a validated label to a Screen (labels = union of rule + LLM; description/screenType prefer the LLM). */
export function applyLabel(screen: Screen, label: ScreenLabel): Screen {
  const refine = new Map((label.params ?? []).map((p) => [p.name, p.guessedType]));
  return {
    ...screen,
    screenType: label.screenType,
    description: label.description,
    labels: [...new Set([...screen.labels, ...label.labels])],
    params: screen.params.map((p) => {
      const g = refine.get(p.name);
      return g ? { ...p, guessedType: g } : p;
    }),
  };
}

export interface LabelOptions {
  model?: string;
  timeoutMs?: number;
}

/** Label one screen with the LLM. On failure, return the original rule-labeled screen (usedFallback=true). */
export async function labelScreen(
  screen: Screen,
  client: LlmClient,
  opts: LabelOptions = {},
): Promise<{ screen: Screen; usedFallback: boolean; error?: string }> {
  let text: string;
  try {
    const res = await client.complete({
      system: LABEL_SYSTEM_PROMPT,
      prompt: buildLabelPrompt(screen),
      ...(opts.model ? { model: opts.model } : {}),
      ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}),
    });
    text = res.text;
  } catch (e) {
    return { screen, usedFallback: true, error: `llm: ${(e as Error).message}` };
  }
  const parsed = parseScreenLabel(text);
  if (!parsed.ok) return { screen, usedFallback: true, error: parsed.error };
  return { screen: applyLabel(screen, parsed.label), usedFallback: false };
}

export interface LabelInventoryHooks {
  store?: AssessmentStore;
  assessmentId?: string;
  onLabeled?: (screen: Screen, usedFallback: boolean, error?: string) => void;
}

export interface LabelInventoryResult {
  screens: Screen[];
  labeled: number;
  fallback: number;
}

/**
 * Label every screen in the inventory sequentially (serial to respect rate limits; parallelism is future work).
 * When wired to the store, set phase to phase1_label and update each screen via upsertScreen.
 */
export async function labelInventory(
  screens: Screen[],
  client: LlmClient,
  opts: LabelOptions & LabelInventoryHooks = {},
): Promise<LabelInventoryResult> {
  if (opts.store && opts.assessmentId) opts.store.setPhase(opts.assessmentId, "phase1_label");
  const out: Screen[] = [];
  let labeled = 0;
  let fallback = 0;
  for (const screen of screens) {
    const r = await labelScreen(screen, client, { ...(opts.model ? { model: opts.model } : {}), ...(opts.timeoutMs ? { timeoutMs: opts.timeoutMs } : {}) });
    out.push(r.screen);
    if (r.usedFallback) fallback += 1;
    else labeled += 1;
    if (opts.store && opts.assessmentId) opts.store.upsertScreen(opts.assessmentId, r.screen);
    opts.onLabeled?.(r.screen, r.usedFallback, r.error);
  }
  return { screens: out, labeled, fallback };
}
