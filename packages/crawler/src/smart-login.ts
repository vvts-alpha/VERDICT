// DESIGN §6.3 — LLM-assisted login. Give it just credentials and it discovers the login page and form fields itself.
//  Detection is STRUCTURAL: a login page is one rendering a visible password input — regardless of <form>
//  membership or a name attribute. The DOM snapshot is the sole authority on page state; the LLM only picks
//  navigation ACTIONS (goto / click / fill_user), never declares state. No path lists or button-text matching —
//  those heuristics are what broke this on real apps (SPA hash routes, lazy menus, nameless inputs).

import { z } from "zod";
import type { LlmClient } from "@veritas/llm";
import { extractJson } from "@veritas/llm";
import type { PageSnapshot } from "./drivers/playwright.js";
import type { FormObservation, InputObservation } from "./types.js";
import { detectStuck } from "./auth.js";

/** Minimal browser operations smartLogin needs (structurally satisfied by PlaywrightDriver; Fake in tests). */
export interface LoginDriver {
  gotoUrl(url: string): Promise<void>;
  snapshot(): Promise<PageSnapshot>;
  fill(selector: string, value: string): Promise<boolean>;
  clickFirst(selectors: string[]): Promise<boolean>;
  pressEnter(selector: string): Promise<void>;
  /** Post-action render wait — menu reveals / SPA route changes need it. Optional for tests. */
  settle?(): Promise<void>;
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
  /** URL of the auth screen found in Phase1 (top priority if present) */
  loginScreenUrl?: string;
  model?: string;
}

/** Bounded LLM discovery: how many navigation actions the model may take before we give up. */
const MAX_DISCOVERY_ACTIONS = 8;
/** Structural submit controls only — button TEXT is a heuristic; a real submit declares its type. */
const SUBMIT_SELECTORS = ['button[type="submit"]', 'input[type="submit"]'];
/** Input types that can never hold a username. */
const NON_TEXT_TYPES = new Set(["hidden", "submit", "button", "checkbox", "radio", "file", "image", "password", "reset"]);

function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

/** Every fillable control on the page: the snapshot's inputs catalog + legacy <form> fields (deduped by selector). */
function inputCatalog(snap: PageSnapshot): InputObservation[] {
  const out: InputObservation[] = [...(snap.inputs ?? [])];
  const seen = new Set(out.map((i) => i.selector));
  for (const f of snap.forms) {
    for (const fld of f.fields) {
      const selector = `[name="${fld.name.replace(/"/g, '\\"')}"]`;
      if (!seen.has(selector)) {
        seen.add(selector);
        out.push({ selector, name: fld.name, id: "", type: fld.type, label: "", autocomplete: "" });
      }
    }
  }
  return out;
}

/** The login widget's anchor: a rendered password input. autocomplete is a secondary structural hint
 *  (type is sometimes rebound, e.g. Angular [type]="hide ? 'password' : 'text'"). */
function findPasswordInput(snap: PageSnapshot): InputObservation | null {
  const cat = inputCatalog(snap);
  return (
    cat.find((i) => i.type === "password") ??
    cat.find((i) => i.autocomplete === "current-password" || i.autocomplete === "new-password") ??
    null
  );
}

/** Best-guess username field among the remaining inputs: declared autocomplete → email type.
 *  Ambiguous leftovers go to the LLM; "first text-ish input" is the final deterministic fallback — on a page
 *  already proven (by the password input) to be an auth screen, that's nearly always the identifier. */
function pickUsernameInput(cat: InputObservation[], pw: InputObservation): InputObservation | null {
  const rest = cat.filter((i) => i.selector !== pw.selector && !NON_TEXT_TYPES.has(i.type));
  return (
    rest.find((i) => i.autocomplete === "username" || i.autocomplete === "email") ??
    rest.find((i) => i.type === "email") ??
    null
  );
}

const Action = z.object({
  action: z.enum(["goto", "click", "fill_user", "stop"]),
  url: z.string().optional(),
  selector: z.string().optional(),
});
type LoginAction = z.infer<typeof Action>;

/** The discovery loop's prompt: hand the model the live page digest and let it choose the next move. */
async function llmNextAction(llm: LlmClient, snap: PageSnapshot, tried: Set<string>, model?: string): Promise<LoginAction | null> {
  const prompt = [
    "Navigate this site toward its LOGIN page — a page that renders a password input. Pick ONE next action.",
    `Current URL: ${snap.url}`,
    `Title: ${snap.title}`,
    `Links: ${JSON.stringify(snap.links.slice(0, 40))}`,
    `Buttons/controls: ${JSON.stringify((snap.clickables ?? []).slice(0, 30))}`,
    `Inputs: ${JSON.stringify((snap.inputs ?? []).slice(0, 40))}`,
    `SPA routes seen: ${JSON.stringify(snap.virtualRoutes.slice(0, 20))}`,
    `Visible text (excerpt): ${snap.visibleText.slice(0, 600)}`,
    `Already tried (do not repeat): ${JSON.stringify([...tried].slice(-12))}`,
    "Respond with ONLY one JSON object:",
    '  {"action":"goto","url":"<absolute url or path>"} — navigate to a likely login URL (SPA hash routes like "/#/login" are valid)',
    '  {"action":"click","selector":"<one of the Buttons/controls selectors>"} — open a menu/button that may reveal the login entry',
    '  {"action":"fill_user","selector":"<one of the Inputs selectors>"} — this page is a username-FIRST login: fill the identifier and continue',
    '  {"action":"stop"} — no plausible route to a login page',
  ].join("\n");
  try {
    const res = await llm.complete({
      system: "You navigate websites to their login page. JSON only.",
      prompt,
      ...(model ? { model } : {}),
    });
    const parsed = Action.safeParse(extractJson(res.text));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/** When the catalog can't decide (no autocomplete/email-type username candidate, or no submit button), the model
 *  maps the ambiguous fields/controls by their labels and types. */
async function llmMapLogin(
  llm: LlmClient,
  snap: PageSnapshot,
  cat: InputObservation[],
  model?: string,
): Promise<{ username?: string; submit?: string }> {
  const prompt = [
    "Identify the fields of this login form.",
    `Inputs: ${JSON.stringify(cat.map((i) => ({ selector: i.selector, type: i.type, name: i.name, id: i.id, label: i.label })))}`,
    `Buttons/controls: ${JSON.stringify((snap.clickables ?? []).slice(0, 30))}`,
    'Respond with ONLY {"username": "<input selector or null>", "submit": "<clickable selector or null>"}.',
  ].join("\n");
  try {
    const res = await llm.complete({ system: "You map login form fields. JSON only.", prompt, ...(model ? { model } : {}) });
    const parsed = z
      .object({ username: z.string().nullable().optional(), submit: z.string().nullable().optional() })
      .safeParse(extractJson(res.text));
    if (parsed.success) return { username: parsed.data.username ?? undefined, submit: parsed.data.submit ?? undefined };
  } catch {
    /* fall through */
  }
  return {};
}

/** Identify form fields heuristically (password + the nearby user field). Kept for compat — new code uses the
 *  page-level inputCatalog so nameless/form-less inputs are also covered. */
export function heuristicFields(form: FormObservation): { username?: string; password?: string } | null {
  const pw = form.fields.find((x) => x.type === "password");
  if (!pw?.name) return null;
  const candidates = form.fields.filter(
    (x) => x.name && !["password", "hidden", "submit", "checkbox", "radio"].includes(x.type),
  );
  const user = candidates.find((x) => /user|email|login|account|mail|名前|メール/i.test(x.name)) ?? candidates[0];
  return { username: user?.name, password: pw.name };
}

export async function smartLogin(
  driver: LoginDriver,
  llm: LlmClient,
  creds: LoginCreds,
  opts: SmartLoginOptions,
): Promise<SmartLoginResult> {
  const { model } = opts;
  const targetOrigin = (() => {
    try {
      return new URL(opts.targetUrl).origin;
    } catch {
      return "";
    }
  })();

  // 1) Start at the operator/Phase1-provided auth screen (authoritative config, not a guess) or the target root.
  await driver.gotoUrl(opts.loginScreenUrl ?? opts.targetUrl);
  let snap = await driver.snapshot();
  if (!snap.domSkeleton || snap.domSkeleton === "empty" || snap.url === "about:blank") {
    // A dead origin is NOT "no login form" — distinguish it honestly so operators see the real failure.
    return { ok: false, needsHuman: false, reason: `cannot reach ${opts.loginScreenUrl ?? opts.targetUrl} (page did not load)`, loginUrl: null };
  }
  let password = findPasswordInput(snap);
  let loginUrl: string | null = password ? snap.url : null;

  // 2) LLM-guided discovery loop — each turn the model picks an action from the live page digest; the DOM
  //    re-snapshot decides whether a login widget appeared. No canned path list: hash routes, menu reveals and
  //    username-first flows are all things the model can do and hardcoding can't.
  const tried = new Set<string>([`goto:${snap.url}`]);
  for (let i = 0; i < MAX_DISCOVERY_ACTIONS && !password; i++) {
    const act = await llmNextAction(llm, snap, tried, model);
    if (!act || act.action === "stop") break;
    if (act.action === "goto" && act.url) {
      const u = resolveUrl(snap.url, act.url);
      if (!u) { tried.add(`goto:${act.url}`); continue; }
      const key = `goto:${u}`;
      if (tried.has(key)) break; // model is repeating itself — stop instead of spinning
      tried.add(key);
      // Same-origin always allowed; cross-origin only if the URL actually appears in this page's links
      // (a real SSO link the site itself offered — not a hallucinated host).
      const isOrigin = (() => { try { return new URL(u).origin === targetOrigin; } catch { return false; } })();
      const inPageLinks = snap.links.some((h) => resolveUrl(snap.url, h) === u);
      if (!isOrigin && !inPageLinks) continue;
      await driver.gotoUrl(u);
    } else if (act.action === "click" && act.selector) {
      const key = `click:${act.selector}`;
      if (tried.has(key)) break;
      tried.add(key);
      await driver.clickFirst([act.selector]);
      await driver.settle?.(); // menu reveals / SPA rerenders land after the click returns
    } else if (act.action === "fill_user" && act.selector) {
      const key = `fill_user:${act.selector}`;
      if (tried.has(key)) break;
      tried.add(key);
      await driver.fill(act.selector, creds.username);
      if (!(await driver.clickFirst(SUBMIT_SELECTORS))) await driver.pressEnter(act.selector);
      await driver.settle?.();
    } else {
      break; // malformed action shape — stop rather than guess
    }
    snap = await driver.snapshot();
    password = findPasswordInput(snap);
    if (password) loginUrl = snap.url;
  }
  if (!password) return { ok: false, needsHuman: false, reason: "no login form found (LLM-guided navigation exhausted)", loginUrl: null };

  // 3) Field mapping — structural picks first; the model only arbitrates what the catalog can't.
  const cat = inputCatalog(snap);
  let llmMap: { username?: string; submit?: string } | null = null;
  const mapped = async () => (llmMap ??= await llmMapLogin(llm, snap, cat, model));
  let user = pickUsernameInput(cat, password);
  if (!user) {
    const m = await mapped();
    user = (m.username ? (cat.find((i) => i.selector === m.username) ?? { selector: m.username, name: "", id: "", type: "text", label: "", autocomplete: "" }) : null)
      ?? cat.find((i) => i.selector !== password.selector && !NON_TEXT_TYPES.has(i.type))
      ?? null;
  }
  if (user) await driver.fill(user.selector, creds.username);
  await driver.fill(password.selector, creds.password);

  // 4) Submit — structural [type=submit] first; an LLM-picked clickable for JS-only buttons; Enter last.
  if (!(await driver.clickFirst(SUBMIT_SELECTORS))) {
    const m = await mapped();
    if (!m.submit || !(await driver.clickFirst([m.submit]))) await driver.pressEnter(password.selector);
  }

  // 5) Success/failure decision (CAPTCHA/MFA → needsHuman; widget still present → bad creds).
  //    SPA logins are async — the password input stays mounted until the POST resolves, so judging
  //    on the immediate post-click snapshot misreads a slow-but-successful login as bad creds.
  //    Poll briefly for the input to detach before concluding anything.
  let after = await driver.snapshot();
  for (let i = 0; i < 12 && findPasswordInput(after); i++) {
    await new Promise((r) => setTimeout(r, 400));
    after = await driver.snapshot();
  }
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
  if (findPasswordInput(after)) {
    return { ok: false, needsHuman: false, reason: "still on a login form (bad credentials or extra step)", loginUrl };
  }
  return { ok: true, needsHuman: false, reason: `logged in (now at ${after.url})`, loginUrl };
}
