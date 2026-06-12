// DESIGN §6.3 — LLM 補助のログイン。資格情報だけ渡せば、ログインページもフォーム項目も自分で発見する。
//  発見: ①Phase1 の auth 画面 → ②既知パス/リンク文言 → ③LLM。 項目: ヒューリスティック → LLM。
//  Cookie 注入ではなく実フォーム入力。CAPTCHA/MFA は needsHuman で返し、呼び出し側が人手へ切替。

import { z } from "zod";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";
import type { PageSnapshot } from "./drivers/playwright.js";
import type { FormObservation } from "./types.js";
import { detectStuck } from "./auth.js";

/** smartLogin が必要とする最小ブラウザ操作(PlaywrightDriver が構造的に満たす。テストは Fake)。 */
export interface LoginDriver {
  gotoUrl(url: string): Promise<void>;
  snapshot(): Promise<PageSnapshot>;
  fill(selector: string, value: string): Promise<boolean>;
  clickFirst(selectors: string[]): Promise<boolean>;
  pressEnter(selector: string): Promise<void>;
}

export interface LoginCreds {
  username: string;
  password: string;
}

export interface SmartLoginResult {
  ok: boolean;
  needsHuman: boolean;
  reason: string;
  loginUrl: string | null;
}

export interface SmartLoginOptions {
  targetUrl: string;
  /** Phase1 で見つかった auth 画面の URL(あれば最優先) */
  loginScreenUrl?: string;
  model?: string;
}

const COMMON_LOGIN_PATHS = [
  "/login",
  "/signin",
  "/sign-in",
  "/sign_in",
  "/users/sign_in",
  "/account/login",
  "/auth/login",
  "/session/new",
  "/user/login",
];
const LOGINISH = /(log[\s-]?in|sign[\s-]?in|サインイン|ログイン|認証)/i;
const SUBMIT_SELECTORS = [
  'button[type="submit"]',
  'input[type="submit"]',
  'button:has-text("ログイン")',
  'button:has-text("Log in")',
  'button:has-text("Login")',
  'button:has-text("Sign in")',
];

function passwordForm(forms: FormObservation[]): FormObservation | null {
  return forms.find((f) => f.fields.some((x) => x.type === "password")) ?? null;
}

function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

/** ヒューリスティックでフォーム項目を特定(password + 近傍の user 欄)。 */
export function heuristicFields(form: FormObservation): { username?: string; password?: string } | null {
  const pw = form.fields.find((x) => x.type === "password");
  if (!pw?.name) return null;
  const candidates = form.fields.filter(
    (x) => x.name && !["password", "hidden", "submit", "checkbox", "radio"].includes(x.type),
  );
  const user = candidates.find((x) => /user|email|login|account|mail|名前|メール/i.test(x.name)) ?? candidates[0];
  return { username: user?.name, password: pw.name };
}

async function llmSuggestLoginUrl(llm: LlmClient, snap: PageSnapshot, model?: string): Promise<string | null> {
  const prompt = [
    "Find the login page for this site.",
    `Current URL: ${snap.url}`,
    `Links: ${JSON.stringify(snap.links.slice(0, 40))}`,
    `Visible text (excerpt): ${snap.visibleText.slice(0, 600)}`,
    'Respond with ONLY {"loginUrl": "<url or path>"} or {"loginUrl": null}.',
  ].join("\n");
  try {
    const res = await llm.complete({ system: "You locate login pages. JSON only.", prompt, ...(model ? { model } : {}) });
    const parsed = z.object({ loginUrl: z.string().nullable() }).safeParse(extractJson(res.text));
    return parsed.success ? parsed.data.loginUrl : null;
  } catch {
    return null;
  }
}

async function llmMapFields(llm: LlmClient, form: FormObservation, model?: string): Promise<{ username?: string; password?: string }> {
  const prompt = [
    "Map a login form's input fields.",
    `Fields: ${JSON.stringify(form.fields)}`,
    'Respond with ONLY {"username": "<input name or null>", "password": "<input name>"}.',
  ].join("\n");
  try {
    const res = await llm.complete({ system: "You map login form fields. JSON only.", prompt, ...(model ? { model } : {}) });
    const parsed = z
      .object({ username: z.string().nullable().optional(), password: z.string() })
      .safeParse(extractJson(res.text));
    if (parsed.success) return { username: parsed.data.username ?? undefined, password: parsed.data.password };
  } catch {
    /* fall through */
  }
  return {};
}

export async function smartLogin(
  driver: LoginDriver,
  llm: LlmClient,
  creds: LoginCreds,
  opts: SmartLoginOptions,
): Promise<SmartLoginResult> {
  const { model } = opts;

  // 1) ログインページの発見
  await driver.gotoUrl(opts.loginScreenUrl ?? opts.targetUrl);
  let snap = await driver.snapshot();
  let form = passwordForm(snap.forms);
  let loginUrl: string | null = form ? snap.url : null;

  if (!form) {
    const origin = resolveUrl(opts.targetUrl, "/")?.replace(/\/$/, "") ?? opts.targetUrl;
    const fromLinks = snap.links
      .filter((h) => LOGINISH.test(h))
      .map((h) => resolveUrl(snap.url, h))
      .filter((u): u is string => u !== null);
    const llmHint = await llmSuggestLoginUrl(llm, snap, model);
    const llmUrl = llmHint ? resolveUrl(opts.targetUrl, llmHint) : null;
    const candidates = [
      ...new Set(
        [
          ...(opts.loginScreenUrl ? [opts.loginScreenUrl] : []),
          ...(llmUrl ? [llmUrl] : []),
          ...fromLinks,
          ...COMMON_LOGIN_PATHS.map((p) => origin + p),
        ].filter(Boolean),
      ),
    ];
    for (const candidate of candidates.slice(0, 8)) {
      await driver.gotoUrl(candidate);
      const s = await driver.snapshot();
      const f = passwordForm(s.forms);
      if (f) {
        form = f;
        snap = s;
        loginUrl = candidate;
        break;
      }
    }
  }
  if (!form) return { ok: false, needsHuman: false, reason: "no login form found (links + common paths + LLM)", loginUrl: null };

  // 2) フォーム項目の特定(ヒューリスティック → LLM)
  let fields = heuristicFields(form);
  if (!fields?.password) fields = await llmMapFields(llm, form, model);
  if (!fields.password) return { ok: false, needsHuman: false, reason: "could not identify password field", loginUrl };

  // 3) 入力 + 送信
  if (fields.username) await driver.fill(`[name="${fields.username}"]`, creds.username);
  await driver.fill(`[name="${fields.password}"]`, creds.password);
  const clicked = await driver.clickFirst(SUBMIT_SELECTORS);
  if (!clicked) await driver.pressEnter(`[name="${fields.password}"]`);

  // 4) 成否判定(CAPTCHA/MFA → needsHuman、フォーム残存 → creds 不正)
  const after = await driver.snapshot();
  const stuck = detectStuck({
    requestedUrl: loginUrl ?? opts.targetUrl,
    finalUrl: after.url,
    status: 200,
    title: after.title,
    domSkeleton: after.domSkeleton,
    visibleText: after.visibleText,
    forms: after.forms,
    links: after.links,
    virtualRoutes: after.virtualRoutes,
    apiCalls: [],
  });
  if (stuck) return { ok: false, needsHuman: true, reason: `stuck: ${stuck.detail}`, loginUrl };
  if (passwordForm(after.forms)) {
    return { ok: false, needsHuman: false, reason: "still on a login form (bad credentials or extra step)", loginUrl };
  }
  return { ok: true, needsHuman: false, reason: `logged in (now at ${after.url})`, loginUrl };
}
