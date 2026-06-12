// DESIGN §7.2 / §9 — 能動探索。受動 BFS では発火しない API/状態を、エージェントが
// ブラウザを操作して引き出す(検索/フィルタ/作成/更新フォーム送信 等)。完全自動(承認ゲート無し)。
// 認可済みアセスメント前提。スコープ/レート/マーカーは driver/crawl 側で担保。

import { z } from "zod";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";
import type { CapturedExchange } from "./types.js";
import type { PageSnapshot } from "./drivers/playwright.js";

/** exploreScreen が必要とするブラウザ操作(PlaywrightDriver が構造的に満たす。テストは Fake)。 */
export interface ExploreDriver {
  gotoUrl(url: string): Promise<void>;
  snapshot(): Promise<PageSnapshot>;
  fill(selector: string, value: string): Promise<boolean>;
  clickFirst(selectors: string[]): Promise<boolean>;
  pressEnter(selector: string): Promise<void>;
  drainApiCalls(): CapturedExchange[];
  currentUrl(): string;
}

export interface ExploreResult {
  firedApis: CapturedExchange[];
  newUrls: string[];
  actions: string[];
}

const SUBMIT_SELECTORS = ['button[type="submit"]', 'input[type="submit"]', "form button", "button"];

const ActionSchema = z.object({ formIndex: z.number().int().min(0), values: z.record(z.string()).optional() });
const PlanSchema = z.object({ actions: z.array(ActionSchema).max(8) });
export type ExplorePlan = z.infer<typeof ActionSchema>[];

function testValue(field: { name: string; type: string }): string {
  const n = field.name.toLowerCase();
  if (field.type === "email" || /mail/.test(n)) return "veritas@example.com";
  if (field.type === "number" || /(price|amount|qty|quantity|count|num|stock)/.test(n)) return "1";
  if (field.type === "date") return "2025-01-01";
  if (field.type === "checkbox" || field.type === "radio") return "on";
  if (/(url|uri|link|redirect|callback)/.test(n)) return "https://veritas-test.example/";
  return "veritas-test";
}

/** LLM にどのフォームをどんな値で送信するか選ばせる。失敗時は全フォームをテスト値で送信。 */
export async function planExplore(llm: LlmClient, snap: PageSnapshot, model?: string): Promise<ExplorePlan> {
  if (snap.forms.length === 0) return [];
  const prompt = [
    "You drive a browser to explore an authorized web app and surface its functionality and APIs by interacting.",
    `URL: ${snap.url}`,
    "Forms on the page:",
    JSON.stringify(snap.forms.map((f, i) => ({ index: i, action: f.action, method: f.method, fields: f.fields })), null, 2),
    "Choose which forms to submit and realistic test values to exercise behaviour (search, filter, create, update — all in scope).",
    'Respond ONLY with {"actions":[{"formIndex":0,"values":{"q":"test"}}]}.',
  ].join("\n");
  try {
    const res = await llm.complete({ system: "You drive a browser to explore. JSON only.", prompt, ...(model ? { model } : {}) });
    const parsed = PlanSchema.safeParse(extractJson(res.text));
    if (parsed.success && parsed.data.actions.length > 0) return parsed.data.actions;
  } catch {
    /* fall through */
  }
  return snap.forms.map((_, index) => ({ formIndex: index }));
}

/** 画面を能動操作(完全自動): 計画フォームを全送信し、発火した API と新 URL を回収。 */
export async function exploreScreen(
  driver: ExploreDriver,
  llm: LlmClient,
  opts: { model?: string } = {},
): Promise<ExploreResult> {
  const firedApis: CapturedExchange[] = [];
  const newUrls: string[] = [];
  const actions: string[] = [];
  const startUrl = driver.currentUrl();
  const snap = await driver.snapshot();
  driver.drainApiCalls(); // 探索開始時点のバッファをクリア

  for (const action of (await planExplore(llm, snap, opts.model)).slice(0, 8)) {
    const form = snap.forms[action.formIndex];
    if (!form) continue;
    for (const field of form.fields) {
      await driver.fill(`[name="${field.name}"]`, action.values?.[field.name] ?? testValue(field));
    }
    if (!(await driver.clickFirst(SUBMIT_SELECTORS))) {
      const first = form.fields[0];
      if (first) await driver.pressEnter(`[name="${first.name}"]`);
    }
    firedApis.push(...driver.drainApiCalls());
    const after = driver.currentUrl();
    if (after !== startUrl) newUrls.push(after);
    actions.push(`submit form#${action.formIndex} ${form.method} ${form.action ?? ""}`);
    if (after !== startUrl) await driver.gotoUrl(startUrl); // 次のフォームのため元ページへ
  }
  return { firedApis, newUrls, actions };
}
