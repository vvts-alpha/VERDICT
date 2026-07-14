// Claude-led 3-stage orchestrator.
//
// If everything is thrown at once the AI elides work, so we segment into survey -> methodology -> diagnosis,
// running query() separately per stage. Each stage narrows the tools via allowedTools and advances the phase.
// Diagnosis runs the screens one at a time in a bounded context (= driving every queued entry in the coverage
// ledger to terminal), so screens can't be structurally missed.

import { createSdkMcpServer, query } from "@anthropic-ai/claude-agent-sdk";
import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import type { AssessmentStore, Screen, ScopePolicy } from "@veritas/core";
import { isInScope, isScannable, recordTokens } from "@veritas/core";
import type { LoginCreds } from "@veritas/crawler";
import { InventoryBuilder, PlaywrightDriver, smartLogin } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient, fingerprintTech, stackAttackHints } from "@veritas/scanner";
import type { TechSample } from "@veritas/scanner";
import type { BurpAuditConn } from "@veritas/scanner";
import { join } from "node:path";
import { buildTools, STAGE_TOOLS, dedupKey, isAuthWalled, loadCookieFile, mergeSetCookie, touchIsDead, stripHash, backfillParentPrefixes } from "./tools.js";
import type { PilotSession, RoleSession } from "./tools.js";
import { LiveControl } from "./live-control.js";
import { DEFAULT_SCENARIOS, DIAGNOSE_PROMPT, FINGERPRINT_PROMPT, METHODOLOGY_PROMPT, RECON_GUESS_PROMPT, SCENARIO_PROMPT, SURVEY_PROMPT } from "./system.js";

export interface RunPilotOptions {
  store: AssessmentStore;
  assessmentId: string;
  targetUrl: string;
  scope: ScopePolicy;
  /** Multiple seeds (list of URLs to diagnose). survey starts from all of them. If unset, equivalent to [targetUrl]. */
  seedUrls?: string[];
  /** Hard-lock to the URL list: survey maps only the seeds and does not follow discovered links (no crawling across).
   *  Diagnosis is limited to the mapped screens = seeds + the APIs each screen calls. For "target is rigidly URL-locked". */
  lockToSeeds?: boolean;
  /** Site-wide HTTP Basic/Digest auth (operator-provided). The browser auto-responds via httpCredentials,
   *  and raw http (FetchHttpClient) gets Authorization: Basic injected (Digest is browser-path only). */
  httpBasic?: { user: string; pass: string };
  /** Operator-provided custom headers (WAF evasion / engagement-mandated required headers, etc.). Applied to both
   *  the browser (same-origin only) and the raw http path. */
  customHeaders?: Record<string, string>;
  profileDir: string;
  artifactsDir: string;
  roleCreds: Map<string, LoginCreds>;
  /** Role name -> path of a pre-captured cookie file (in place of credentials; for walls that can't be auto-logged-in). */
  roleCookieFiles?: Map<string, string>;
  /** Role name -> that role's own login entry URL (for apps whose roles log in at different pages, e.g. a user login vs an
   *  admin login). Attended opens that role's window there; the login() tool starts smartLogin there. Falls back to loginUrl/target. */
  roleLoginUrls?: Map<string, string>;
  /** Role name -> free-text privilege description (e.g. "full admin" / "regular user (read-only)").
   *  Context for the agent to tell high/low privilege apart in auth-diff. Not secret, but not persisted in state. */
  roleDescriptions?: Map<string, string>;
  /** The "deep" model for diagnosis (high-value screens that need emergent reasoning). e.g. claude-opus-4-8. If unset, SDK default. */
  model?: string;
  /** The "fast" model for survey/methodology/login and low-value screens (e.g. claude-sonnet-5).
   *  If unset, same as model (= no model tiering, behaviour unchanged). Setting it tiers Opus/Sonnet. */
  fastModel?: string;
  /** Whether to run the post-diagnosis A04 scenario (cross-screen multi-step logic abuse) stage. Default true.
   *  Auto-skipped if there is no transactional surface (cart/order/checkout/coupon/transfer/privilege change). Pinned to the deep model. */
  scenarioPass?: boolean;
  /** Whether to inject the standing default scenarios (cross-cutting objectives like credential hunting) into the scenario stage. Default true. Off with --no-default-scenarios. */
  defaultScenarios?: boolean;
  /** Whether to run the A06 fingerprint (version collection -> known-CVE assessment) stage. Default true. Off with --no-fingerprint. */
  fingerprintPass?: boolean;
  /** Whether to query an online CVE DB (OSV/NVD) for detected versions in A06. Default false (egress to a third party = opt-in). On with --cve-lookup. */
  cveLookup?: boolean;
  maxTurns?: number;
  rateMs?: number;
  headless?: boolean;
  browserPath?: string;
  noSandbox?: boolean;
  /** Cap on the number of screens to diagnose (default 40). */
  maxScreens?: number;
  /** Cap on the number of screens survey maps (--max-survey-screens). Stops exploration once reached. Unset = unlimited. */
  maxSurveyScreens?: number;
  /** Resume an existing run: skip survey/methodology and diagnose only the un-diagnosed (non-terminal) screens. */
  resume?: boolean;
  /** Exhaustive (screen survey): disable survey's dynamic pruning (ignore_paths) and map every screen.
   *  If unset, ignore_paths is active (the model prunes low-value CMS content trees etc. itself to curb frontier blow-up). */
  exhaustiveSurvey?: boolean;
  /** Survey only: run just the survey stage, no methodology/diagnosis (emits screens/screenshots/APIs, no findings).
   *  Can later be chained into diagnosis via `resume` (map now / diagnose later). */
  surveyOnly?: boolean;
  /** Upstream proxy such as Burp (e.g. http://127.0.0.1:8080). Routes HTTP + browser through it only when set. Unset = as-is. */
  burpProxy?: string;
  /** Keep the auth session alive: during diagnosis, if the gap between screens exceeds this many minutes, do a raw-HTTP
   *  GET of a safe authed URL (NOT the top page — some sites reset the session on a cold hit to `/` or a full reload,
   *  and an SPA holding auth in memory is rebooted by any page load) and re-sync the rotated cookie. No browser
   *  navigation. 0 disables. Guards against sliding/short-lived tokens going stale. Default 4 min. */
  keepAliveMinutes?: number;
  /** Explicit URL for the keepalive touch (power-user override). If unset, keepalive uses the authed page currently
   *  being diagnosed (falling back to the last one), and skips entirely rather than ever touch `/`. */
  keepAliveUrl?: string;
  /** Goto-safe authenticated hub (the app menu). For sites where deep routes die on a cold/direct navigation: a route
   *  that bounces to an error page is reached by clicking its link from here instead, and it becomes the keepalive
   *  target. Unset = unchanged (no anchor recovery). */
  anchorUrl?: string;
  /** attended (manual multi-session auth): launch one headed persistent context per role and have a human log in
   *  (clearing CAPTCHA/MFA/Arkose too) before running survey/diagnosis. Diagnosis uses each role's live
   *  cookie. For walls that auto-login / cookie files can't cross (CAPTCHA/MFA, absolute-TTL expiry, etc.). */
  attended?: boolean;
  /** The full set of role names to open windows for in attended (manifest's auth.roles[].name). "Purely manual" roles
   *  with neither credentials nor a cookie file also get a window if included here (manual N accounts). If unset, derived from creds/cookie keys. */
  attendedRoles?: string[];
  /** Parent directory of the per-role attended profiles (each role is <dir>/<role>). Default is `profiles/` next to profileDir. */
  attendedProfilesDir?: string;
  /** The URL each role window opens first in attended (the manual-login entry point). If unset, targetUrl. */
  loginUrl?: string;
  /** attended wait for human action: show a message and resolve when the operator presses Enter.
   *  Supplied by the CLI via readline (the pilot package assumes no TTY). Required in attended (not needed when controlUrl is set). */
  promptOperator?: (message: string) => Promise<void>;
  /** attended x LiveHands: reverse-connect to serve to screencast the role sessions to the WebUI.
   *  When set, launches headless and resolves manual-login completion via the operator's "Done" (no terminal Enter needed). */
  controlUrl?: string;
  onText?: (text: string) => void;
  onTool?: (name: string, input: unknown) => void;
  /** Hook for an extra scan to run **while the session is still held** after diagnosis/scenarios (Burp active scan, etc.).
   *  Only when set does it insert phase2_burpscan before report. Calling keepWarm() periodically keeps the authed session alive
   *  (so tokens/cookies don't go stale during a long Burp scan). The driver is still alive at this point. */
  onBurpScanPhase?: (ctx: { keepWarm: () => Promise<void>; cookie: string; bearer: string }) => Promise<void>;
  /** OOB (Burp Collaborator) connection. When set, probe_oob is usable during diagnosis (confirming blind SSRF/XXE/SQLi).
   *  The CLI resolves it from BURP_AUDIT_API/BURP_AUDIT_TOKEN and passes it. If unset, probe_oob is not-available. */
  oob?: BurpAuditConn;
  /** Operator emphasis hint (free text). Injected as the **top-priority objective of the scenario stage** (not mixed into per-screen diagnosis).
   *  e.g. "focus on the checkout flow and IDOR on /api/orders. Coupon/price tampering too." Emphasis, not exclusion. */
  focus?: string;
  /** Input sweep: on every browser_navigate, submit forms/searches with benign values to discover new routes/APIs (default on). */
  inputSweep?: boolean;
  /** In the input sweep, also submit POST forms (= writes data to the target). Default true. If false, GET/search only. */
  aggressiveForms?: boolean;
}

export interface PilotResult {
  findings: PilotSession["findings"];
  summary: string;
  turns: number;
  /** Tokens used by this run (input+output+cache total). */
  tokensUsed: number;
  /** Approximate cost of this run (USD; for a subscription, an API-equivalent estimate). */
  costUsd: number;
}

// disallowedTools is the "don't show the model" list. onlyVeritasToolsHook is the real boundary (deny all non-veritas),
// but **built-in tools not listed here are presented to the model by the claude_code preset** -> the model calls
// ToolSearch/TodoWrite/Task etc., gets PreToolUse-denied, and wastes turns and log space (frequent in real runs). So we
// enumerate and hide the preset's built-ins.
const DISALLOWED = [
  // file / exec / web
  "Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "WebFetch", "WebSearch",
  // agentic / meta (this is the culprit behind "tools search unusable". Hide them and the model won't reach for them)
  "Task", "Agent", "ToolSearch", "TodoWrite", "Skill", "Monitor", "Workflow", "EnterPlanMode", "ExitPlanMode", "SendMessage",
  "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskStop", "TaskOutput", "CronCreate", "CronList", "CronDelete",
];

/** pilot runs on veritas MCP tools only (bounded design). But the SDK exposes Task/Agent/
 *  Monitor/Skill/ToolSearch/TaskCreate... beyond Bash/Read, and under bypassPermissions the model can call them
 *  (Monitor/Skill are effectively shell execution = a Bash-ban bypass, Agent spawns unbounded sub-agents).
 *  The PreToolUse hook denies anything that isn't mcp__veritas__*. It's an allowlist that doesn't depend on the
 *  disallowedTools enumeration, and PreToolUse deny works even under bypassPermissions (SDK behaviour). New tools are auto-blocked. */
/** Whether a tool may be called in pilot (veritas MCP tools only). Task/Agent/Monitor/Skill/ToolSearch etc. are false. */
export function isPilotAllowedTool(name: string): boolean {
  return name.startsWith("mcp__veritas__");
}

const onlyVeritasToolsHook: HookCallback = async (input) => {
  const name = (input as { tool_name?: string }).tool_name ?? "";
  if (isPilotAllowedTool(name)) return { continue: true };
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `pilot only permits veritas tools. '${name}' is denied (process get_inventory results directly with record_methodology; do not offload to external tools).`,
    },
  };
};

/** Model tiering for diagnosis: "high-value screens" — authenticated / object-ref & id params / labels like
 *  idor-candidate / screens with authenticated APIs — are diagnosed on deep (e.g. opus); input-less static screens on fast (e.g. sonnet). */
function screenIsHighValue(sc: Screen): boolean {
  if (sc.authState === "post-login") return true;
  if (sc.labels.some((l) => /idor|pii|upload|admin|payment|auth/i.test(l))) return true;
  if (sc.params.some((p) => p.guessedType === "object_ref" || p.guessedType === "id")) return true;
  if (sc.apis.some((a) => a.auth !== "none")) return true;
  return false;
}

/** Pure function that decides how far survey / methodology got in the previous run (for resume).
 *  The survey_done marker may not appear because the model didn't call it (the stage ended on maxTurns), so we
 *  also OR in the phase (past recon = phase1_label or later) and methodology's 📋 PLAN events. */
export function resumeStageState(
  prev: { phase: string; events: ReadonlyArray<{ type: string; payload: unknown }> } | null,
): { surveyDone: boolean; methodologyDone: boolean } {
  if (!prev) return { surveyDone: false, methodologyDone: false };
  const notes = prev.events
    .filter((e) => e.type === "note")
    .map((e) => {
      const m = (e.payload as { message?: unknown }).message;
      return typeof m === "string" ? m : "";
    });
  const methodologyDone = notes.some((m) => /📋 PLAN s-\d+/.test(m));
  const DONE_PHASES = new Set(["phase1_label", "phase2_scan", "report", "done"]);
  const surveyDone = DONE_PHASES.has(prev.phase) || methodologyDone || notes.some((m) => m.includes("SURVEY done"));
  return { surveyDone, methodologyDone };
}

/** Pure function that decides whether an error is a Claude (subscription CLI / SDK) usage-limit / token-exhaustion error.
 *  On a match we pause the run (resumable) rather than "skip and move on".
 *  A 429 from the network target (the site under diagnosis) doesn't reach this path (an LLM-call failure), so no false positive.
 *  Transient overloaded (529) is excluded — a retry recovers, so we shouldn't stop. */
export function isClaudeUsageLimit(text: string): boolean {
  const s = (text || "").toLowerCase();
  return (
    /usage limit|usage_limit/.test(s) ||
    /session limit/.test(s) || // "You've hit your session limit ..." (claude CLI subscription cap)
    /limit reached/.test(s) ||
    /hit your\b[\s\S]{0,30}\blimit/.test(s) || // "(you've) hit your session/usage limit"
    /\blimit\b[\s\S]{0,40}\bresets?\b/.test(s) || // "... limit · resets 12:50am" (limit and resets co-occur)
    /rate.?limit/.test(s) ||
    /too many requests/.test(s) ||
    /\b429\b/.test(s) ||
    /quota/.test(s) ||
    /resets?\s+(at\b|\d)/.test(s) || // both "reset at ..." and "resets 12:50am"
    /insufficient (credit|quota|balance|funds)/.test(s) ||
    /out of (credit|tokens)/.test(s)
  );
}

/** Format an epoch (seconds or milliseconds) as "(resets <ISO>)". Empty string if indeterminate. */
function fmtReset(epoch: unknown): string {
  if (typeof epoch !== "number" || !Number.isFinite(epoch) || epoch <= 0) return "";
  const ms = epoch < 1e12 ? epoch * 1000 : epoch; // normalize seconds to ms
  try {
    return ` (resets ${new Date(ms).toISOString()})`;
  } catch {
    return "";
  }
}

/**
 * Primary signal that decides a usage limit from the SDK message's **structured fields** (sturdier than string matching).
 * Returns a pause-reason string on a match, null otherwise. In order of strength:
 *  1. `rate_limit_event` ... a dedicated event. `status==='rejected'` = being rejected right now (+ recovery time).
 *  2. `assistant.error` ...  `'rate_limit' | 'billing_error'` (`'overloaded'` is transient, so **excluded**).
 *  3. `result.api_error_status` ... HTTP 429.
 * This pins it down without relying on wording variants like "You've hit your session limit ...". Only the throw path
 * has just a string, so isClaudeUsageLimit() stays as a fallback.
 */
export function usageLimitFromMessage(msg: unknown): string | null {
  const m = msg as { type?: string; error?: string; rate_limit_info?: Record<string, unknown>; api_error_status?: number | null };
  if (!m || typeof m !== "object") return null;
  if (m.type === "rate_limit_event") {
    const info = m.rate_limit_info ?? {};
    if (info.status === "rejected") {
      return `rate_limit_event: ${String(info.rateLimitType ?? "rate limit")} rejected${fmtReset(info.resetsAt)}`;
    }
    return null; // allowed / allowed_warning don't stop the run
  }
  if (m.type === "assistant" && (m.error === "rate_limit" || m.error === "billing_error")) {
    return `assistant error: ${m.error}`;
  }
  if (m.type === "result" && m.api_error_status === 429) {
    return "result api_error_status 429";
  }
  return null;
}

/** Collapse SDK usage into "tokens processed" = fresh input + output + newly-cached input.
 *  EXCLUDES cache_read_input_tokens on purpose: in a multi-turn agent loop the cached system/context prefix is re-read
 *  (and re-reported) on EVERY turn, so summing it counts the same tokens once per turn — a ~10x inflation on a 40-turn
 *  screen (this is why a run showed ~38M against a 5M cap). cache_read is also near-free under the prompt cache. Counting
 *  only fresh input + cache-creation + output yields the unique tokens actually processed. */
export function usageTokens(u: Record<string, number> | undefined): number {
  return u ? (u.input_tokens ?? 0) + (u.output_tokens ?? 0) + (u.cache_creation_input_tokens ?? 0) : 0;
}

/** Token tally for one stage. If the result (cumulative) can be read, use it; otherwise (early break on the done tool /
 *  maxTurns) fall back to the per-turn assistant accumulation. Taking the max is insurance against dropping tokens. */
export function stageTokenDelta(assistantTokens: number, resultTokens: number, sawResult: boolean): number {
  return sawResult ? Math.max(resultTokens, assistantTokens) : assistantTokens;
}

/** Role label for operator-facing display. If a description exists, render it as 'role' (description) so the
 *  manual-login window makes clear which account to log in as (admin / regular, etc.). */
export function roleLabel(role: string, descriptions?: Map<string, string>): string {
  const d = descriptions?.get(role);
  return d ? `'${role}' (${d})` : `'${role}'`;
}

export async function runPilot(opts: RunPilotOptions): Promise<PilotResult> {
  const launchBase = {
    headless: opts.headless ?? true,
    // The x-verdict marker is added driver-side "same-origin only" (never cross-origin = doesn't break third parties).
    // Scope is a separate concept and may widen to include other domains/APIs (diagnosis can hit anything in-scope over the http path).
    ...(opts.browserPath ? { executablePath: opts.browserPath } : {}),
    ...(opts.noSandbox ? { args: ["--no-sandbox"] } : {}),
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
    // Site-wide Basic/Digest: Playwright auto-responds to 401 (across all launched drivers = including attended role windows).
    ...(opts.httpBasic ? { httpCredentials: { username: opts.httpBasic.user, password: opts.httpBasic.pass } } : {}),
    // Operator's custom headers (WAF evasion etc.). Applied same-origin only (gated driver-side).
    ...(opts.customHeaders && Object.keys(opts.customHeaders).length ? { extraHeaders: opts.customHeaders } : {}),
  };

  // ── attended: launch one headed persistent context per role and have a human log in ──
  //    Keep the live session per role; diagnosis swaps driver/cookie via login() to use them.
  let driver: PlaywrightDriver;
  let roleSessions: Map<string, RoleSession> | undefined;
  let primaryRole = "";
  let primaryCookie = "";
  let liveControl: LiveControl | undefined;
  if (opts.attended) {
    if (!opts.promptOperator && !opts.controlUrl)
      throw new Error("attended mode requires promptOperator (Enter-confirm) or controlUrl (WebUI login)");
    // Roles to open windows for: explicit attendedRoles take precedence (including purely-manual roles). Otherwise from creds/cookie keys.
    const roles = [
      ...new Set([...(opts.attendedRoles ?? []), ...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])]),
    ];
    if (roles.length === 0) roles.push("primary"); // even with no roles set, a single manual session can be established
    const baseDir = opts.attendedProfilesDir ?? join(opts.profileDir, "..", "profiles");
    roleSessions = new Map();
    // With controlUrl set, login happens in the WebUI, so headless (the server needs no display).
    const viaWeb = !!opts.controlUrl;
    if (viaWeb) liveControl = new LiveControl(opts.controlUrl!, opts.onText);
    opts.onText?.(
      viaWeb
        ? `👤 attended (WebUI): ${roles.length} session(s) — log in via the Sessions tab`
        : `👤 attended: launching ${roles.length} headed session(s) per role (manual login)`,
    );
    // Launch each role and resolve auth. cookie -> inject / creds -> smartLogin (manual on failure) / no material -> manual.
    // viaWeb manual roles are registered together later and their Done awaited in parallel (N tabs at once). CLI (non-viaWeb) is sequential Enter as before.
    const manual: Array<{ role: string; driver: PlaywrightDriver }> = [];
    const earlyLlm = viaWeb ? new ClaudeCliClient({ defaultModel: opts.fastModel ?? "claude-sonnet-5" }) : undefined;
    // Each role's login entry: its own loginUrl (user vs admin log in at different pages) → global loginUrl → target.
    const roleLoginUrl = (role: string): string => opts.roleLoginUrls?.get(role) ?? opts.loginUrl ?? opts.targetUrl;
    for (const role of roles) {
      const d = await PlaywrightDriver.launch({ ...launchBase, userDataDir: join(baseDir, role), headless: viaWeb });
      const cookieFile = opts.roleCookieFiles?.get(role);
      const creds = opts.roleCreds.get(role);
      let deferred = false;
      if (cookieFile) {
        try {
          const { browserCookies } = loadCookieFile(cookieFile, opts.targetUrl);
          await d.clearSession();
          await d.addCookies(browserCookies);
          await d.gotoUrl(opts.targetUrl);
          opts.onText?.(`🍪 role ${roleLabel(role, opts.roleDescriptions)}: injected ${browserCookies.length} pre-captured cookie(s) (no manual login needed)`);
        } catch (e) {
          opts.onText?.(`⚠ role '${role}' cookie file error: ${String(e).slice(0, 120)}`);
        }
      } else if (viaWeb && creds && earlyLlm) {
        // Credentials present -> auto-login. On failure (CAPTCHA/MFA) fall back to a manual tab.
        await d.gotoUrl(roleLoginUrl(role));
        let ok = false;
        try {
          await d.clearSession();
          const r = await smartLogin(d, earlyLlm, creds, { targetUrl: opts.targetUrl, ...(opts.roleLoginUrls?.get(role) ? { loginScreenUrl: opts.roleLoginUrls.get(role)! } : {}), ...(opts.model ? { model: opts.model } : {}) });
          ok = r.ok;
          opts.onText?.(
            ok
              ? `🔑 role ${roleLabel(role, opts.roleDescriptions)}: auto-logged in`
              : `↪ role ${roleLabel(role, opts.roleDescriptions)}: auto-login failed (${r.reason}) → manual`,
          );
        } catch (e) {
          opts.onText?.(`↪ role ${roleLabel(role, opts.roleDescriptions)}: auto-login error → manual (${String(e).slice(0, 80)})`);
        }
        if (!ok) {
          manual.push({ role, driver: d });
          deferred = true;
        }
      } else if (viaWeb) {
        await d.gotoUrl(roleLoginUrl(role));
        manual.push({ role, driver: d });
        deferred = true;
      } else {
        // CLI attended: confirm one role at a time with Enter, as before.
        await d.gotoUrl(roleLoginUrl(role));
        await opts.promptOperator!(`▶ Please log in manually in the browser window for role ${roleLabel(role, opts.roleDescriptions)} (clear CAPTCHA/MFA too). Press Enter when done…`);
      }
      if (!deferred) {
        const cookie = await d.sessionCookieHeader();
        roleSessions.set(role, { driver: d, cookie });
        opts.onText?.(`✅ role ${roleLabel(role, opts.roleDescriptions)} session established (cookie ${cookie ? "present" : "absent"})`);
      }
    }
    // Register all viaWeb manual roles -> await Done **in parallel** (N tabs appear at once) -> sessions established.
    if (liveControl && manual.length > 0) {
      opts.onText?.(`🖥 ${manual.length} session(s) need manual login — open the Sessions tab, log in each, then press Done.`);
      for (const m of manual) await liveControl.register(m.role, m.driver);
      await Promise.all(manual.map((m) => liveControl!.waitForDone(m.role)));
      for (const m of manual) {
        const cookie = await m.driver.sessionCookieHeader();
        roleSessions.set(m.role, { driver: m.driver, cookie });
        opts.onText?.(`✅ role ${roleLabel(m.role, opts.roleDescriptions)} session established (cookie ${cookie ? "present" : "absent"})`);
      }
    }
    primaryRole = roles[0]!;
    const prim = roleSessions.get(primaryRole)!;
    driver = prim.driver;
    primaryCookie = prim.cookie;
  } else {
    driver = await PlaywrightDriver.launch({ ...launchBase, userDataDir: opts.profileDir });
  }

  const http = new FetchHttpClient({
    allow: (u) => isInScope(u, opts.scope),
    minDelayMs: opts.rateMs ?? 250,
    headers: {
      "x-verdict": "assessment",
      // Site-wide Basic: inject Authorization on the raw http path too (Digest is browser-path only).
      ...(opts.httpBasic ? { authorization: `Basic ${Buffer.from(`${opts.httpBasic.user}:${opts.httpBasic.pass}`, "utf8").toString("base64")}` } : {}),
      ...(opts.customHeaders ?? {}), // apply operator's custom headers (WAF evasion etc.) to the raw http path too
    },
    ...(opts.burpProxy ? { proxy: opts.burpProxy } : {}),
  });

  // Model tiering: deep = high-value diagnosis screens (opus etc.), fast = survey/methodology/login/low-value screens (sonnet etc.).
  // If fastModel is unset, same as deep = no tiering (behaviour unchanged).
  const deepModel = opts.model;
  const fastModel = opts.fastModel ?? opts.model;

  // ── keepalive (raw-HTTP touch) ── the warm target is a concrete, in-scope, non-root, non-logout URL. Never `/`:
  //    some sites reset the session on a cold hit to root or a full reload, and an SPA holding auth in memory is
  //    rebooted by any page load — so keepalive GETs a real authed page instead (no navigation). Updated as diagnosis
  //    walks authed screens; shared by the diagnosis loop and the Burp scan phase.
  const warmSeed = opts.keepAliveUrl ?? opts.anchorUrl; // the anchor hub is a goto-safe authed page = an ideal warm target
  let lastWarmUrl: string | null = warmSeed && isInScope(warmSeed, opts.scope) ? warmSeed : null;
  const isRootUrl = (u: string): boolean => {
    try {
      const p = new URL(u).pathname;
      return p === "" || p === "/";
    } catch {
      return false;
    }
  };
  const warmTarget = (u: string | undefined): string | null =>
    u && isInScope(u, opts.scope) && !isRootUrl(u) && !/logout|signout|sign-out|logoff/i.test(u) ? u : null;
  /** GET a safe authed URL to keep the sliding session alive (no browser navigation). Merges a rotated Set-Cookie back
   *  into the caller's cookie. Returns dead=true if the touch shows the session expired; null on a network error. */
  const warmTouch = async (url: string, cookie: string, bearer: string): Promise<{ cookie: string; dead: boolean } | null> => {
    try {
      const headers: Record<string, string> = {};
      if (cookie) headers.cookie = cookie;
      if (bearer) headers.authorization = `Bearer ${bearer}`;
      const res = await http.send({ method: "GET", url, headers, body: null });
      return { cookie: mergeSetCookie(cookie, res.headers["set-cookie"]), dead: touchIsDead(res.status, res.headers.location, res.body) };
    } catch {
      return null;
    }
  };

  const session: PilotSession = {
    driver,
    http,
    evidence: new EvidenceStore(opts.artifactsDir),
    store: opts.store,
    assessmentId: opts.assessmentId,
    artifactsDir: opts.artifactsDir,
    scope: opts.scope,
    targetUrl: opts.targetUrl,
    anchorUrl: opts.anchorUrl,
    roleCreds: opts.roleCreds,
    roleCookieFiles: opts.roleCookieFiles ?? new Map(),
    roleLoginUrls: opts.roleLoginUrls,
    roleDescriptions: opts.roleDescriptions ?? new Map(),
    loginLlm: new ClaudeCliClient({ defaultModel: fastModel ?? "claude-sonnet-5" }),
    currentCookie: primaryCookie, // attended starts with the primary role's live cookie (normally "")
    currentBearer: "", // login() loads each role's localStorage Bearer JWT
    currentRole: primaryRole,
    findings: [],
    findCounter: 0,
    findingsByKey: new Map(),
    accessVerdicts: new Map(),
    recordCalls: 0,
    httpProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
    screenProbes: 0,
    done: false,
    doneSummary: "",
    paused: false,
    model: fastModel, // the login tool (smartLogin) is mechanical -> fast model
    inv: new InventoryBuilder(),
    visited: new Set(),
    frontier: new Set(),
    refererGated: new Set(),
    ignorePaths: [],
    exhaustive: !!opts.exhaustiveSurvey,
    ...(opts.maxSurveyScreens != null ? { maxSurveyScreens: opts.maxSurveyScreens } : {}),
    lockToSeeds: !!opts.lockToSeeds,
    inputSweep: opts.inputSweep ?? true,
    aggressiveForms: opts.aggressiveForms ?? true,
    cveLookup: opts.cveLookup ?? false, // opt-in: egress to a third-party CVE DB only when explicitly on
    plans: new Map(),
    currentScreenId: null,
    screenVerdict: null,
    screenSkipReason: null,
    surveyDone: false,
    reconGuessDone: false,
    methodologyDone: false,
    screenDone: false,
    scenarioDone: false,
    fingerprintDone: false,
    ...(opts.oob ? { oob: opts.oob } : {}),
    ...(roleSessions ? { roleSessions } : {}),
  };

  // Multiple seeds: push seed URLs other than target onto the frontier as survey starting points
  // (even under hard-lock the initial seeds are pushed; only later discovered-link expansion is suppressed by recordObservation).
  const seedList = [...new Set([opts.targetUrl, ...(opts.seedUrls ?? [])])];
  for (const u of seedList) {
    if (stripHash(u) !== stripHash(opts.targetUrl)) session.frontier.add(stripHash(u));
  }

  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: buildTools(session) });
  const rolesLine =
    [...new Set([...opts.roleCreds.keys(), ...(opts.roleCookieFiles?.keys() ?? [])])]
      .map((r) => {
        const d = opts.roleDescriptions?.get(r);
        return d ? `${r} (${d})` : r;
      })
      .join(", ") || "none";
  const maxTurns = opts.maxTurns ?? 80; // matches the CLI default (main.ts is also 80). WebUI blank -> CLI default lands on 80.

  // ── resume: reseed from an existing run (skip survey/methodology, diagnose only un-diagnosed screens) ──
  const prev = opts.resume ? opts.store.loadAssessment(opts.assessmentId) : null;
  const resumeStatus = prev ? new Map(prev.screenScans.map((s) => [s.screenId, s.status] as const)) : null;
  if (prev) {
    session.inv.seed(prev.screens); // continue screenId numbering + dedup
    session.currentCookie = await driver.sessionCookieHeader(); // reuse the run's auth session (browser-profile)
    session.currentBearer = (await driver.bearerToken().catch(() => null)) ?? ""; // reuse the SPA's Bearer JWT too
    session.currentRole = [...opts.roleCreds.keys()][0] ?? "";
    // Restore methodology plans from the event log (📋 PLAN <id>: ...)
    for (const e of prev.events) {
      if (e.type === "note") {
        const m = /📋 PLAN (s-\d+): (.+)/.exec(e.payload.message);
        if (m && m[1] && m[2]) session.plans.set(m[1], m[2]);
      }
    }
    // Carry over existing findings (continue id numbering + best-effort dedup key to suppress double-reporting)
    for (const f of prev.findings) {
      session.findings.push(f);
      const num = Number.parseInt(f.id.replace(/^f-/, ""), 10);
      if (Number.isFinite(num)) session.findCounter = Math.max(session.findCounter, num);
      const cat = /^\[([a-z0-9-]+)\]/.exec(f.title)?.[1] ?? "other";
      const ep = /(\/[A-Za-z0-9_{}/.-]+)/.exec(f.title)?.[1] ?? "";
      session.findingsByKey.set(dedupKey(cat, ep, undefined, opts.targetUrl), f);
      session.recordCalls += 1;
    }
    opts.store.appendEvent(opts.assessmentId, {
      type: "note",
      payload: { message: `↺ resume: ${prev.screens.length} screens / ${prev.findings.length} findings carried over` },
    });
  }

  // Token usage: pick tokens from each query()'s result, accumulate into the run's budget (cumulative), and persist.
  let budget = (prev ?? opts.store.loadAssessment(opts.assessmentId))?.budget ?? null;
  let runTokens = 0; // this run's increment (for the summary display)
  let costUsd = 0;

  // If a stage dies from token/usage-limit exhaustion, pause the run rather than skipping to the next screen.
  //   done=true stops all subsequent stages/screens; paused=true keeps the final step from dropping to report (resumable).
  //   Once the quota recovers, `pilot --resume --id <id>` (the WebUI's ▶ resume) continues from the un-diagnosed queued screens.
  const pauseRun = (detail: string): void => {
    if (session.paused) return; // don't double-count
    session.done = true;
    session.paused = true;
    session.doneSummary = `⏸ paused — Claude usage/token limit reached. Resume when it resets: pilot --resume --id ${opts.assessmentId}`;
    opts.onText?.(`${session.doneSummary}${detail ? ` (${detail})` : ""}`);
    opts.store.appendEvent(opts.assessmentId, {
      type: "note",
      payload: { message: `${session.doneSummary}${detail ? ` — ${detail}` : ""}` },
    });
    opts.store.setPaused(opts.assessmentId, true, "Claude usage/token limit reached");
  };

  // One stage = one query(). Exit when the stage's done flag is set or Claude stops on its own.
  const runStage = async (p: {
    system: string;
    goal: string;
    allowed: readonly string[];
    maxTurns: number;
    model?: string;
    shouldStop: () => boolean;
  }): Promise<number> => {
    let turns = 0;
    // Token tally: the result message (cumulative usage at query end) arrives after shouldStop's early break, so
    // collapsing the stage with a done tool almost always left it unread at 0. So we accumulate per-turn assistant
    // usage (which survives an early break) and only overwrite with the authoritative total when the result is readable.
    const tally = usageTokens;
    let assistantTokens = 0;
    let resultTokens = 0;
    let sawResult = false;
    const q = query({
      prompt: p.goal,
      options: {
        mcpServers: { veritas: server },
        allowedTools: p.allowed.map((n) => `mcp__veritas__${n}`),
        disallowedTools: DISALLOWED,
        permissionMode: "bypassPermissions",
        // allowlist that PreToolUse-denies everything other than veritas MCP tools (incl. Task/Agent/Monitor/Skill/ToolSearch/...).
        hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
        ...(p.model ? { model: p.model } : {}),
        systemPrompt: { type: "preset", preset: "claude_code", append: p.system },
        maxTurns: p.maxTurns,
      },
    });
    try {
      for await (const msg of q) {
        // Use structured fields as the primary signal (rate_limit_event / assistant.error / api_error_status 429).
        // On detection pauseRun sets done=true, and the `session.done` check below exits this stage.
        const structuredLimit = usageLimitFromMessage(msg);
        if (structuredLimit) pauseRun(structuredLimit.slice(0, 160));
        if (msg.type === "assistant") {
          assistantTokens += tally((msg.message as unknown as { usage?: Record<string, number> }).usage);
          for (const block of msg.message.content) {
            if (block.type === "text" && block.text.trim()) {
              turns += 1;
              const t = block.text.trim();
              opts.onText?.(t);
              opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: t.slice(0, 400) } });
            } else if (block.type === "tool_use") {
              opts.onTool?.(block.name, block.input);
            }
          }
        } else if (msg.type === "result") {
          const r = msg as unknown as { usage?: Record<string, number>; total_cost_usd?: number; subtype?: string; is_error?: boolean; result?: string };
          sawResult = true;
          resultTokens = tally(r.usage);
          costUsd += r.total_cost_usd ?? 0;
          // Error result (returned via result rather than a throw). error_max_turns is a normal cutoff, so excluded.
          if ((r.is_error || (r.subtype && r.subtype !== "success")) && r.subtype !== "error_max_turns") {
            const detail = `${r.subtype ?? "error"} ${r.result ?? ""}`.trim();
            if (isClaudeUsageLimit(detail)) pauseRun(detail.slice(0, 160));
          }
        }
        if (p.shouldStop() || session.done) break;
      }
    } catch (err) {
      // When a stage dies with a throw. If it's token/usage-limit exhaustion, **pause instead of skipping** (resumable).
      // Otherwise (maxTurns / transient SDK error) proceed best-effort to the next screen/stage as before.
      // Tools already fired by this point (record_finding etc.) are already reflected in the store, so no finding is lost.
      const m = String(err instanceof Error ? err.message : err).slice(0, 160);
      if (isClaudeUsageLimit(m)) {
        pauseRun(m);
      } else {
        opts.onText?.(`⚠ stage ended early: ${m}`);
        opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ stage ended early: ${m}` } });
      }
    }
    try {
      await q.return?.(undefined as never);
    } catch {
      /* generator already done */
    }
    // Tally once after the stage ends (never dropped on early break / maxTurns / normal finish).
    // If the result is readable use its cumulative; otherwise fall back to the assistant accumulation.
    const delta = stageTokenDelta(assistantTokens, resultTokens, sawResult);
    if (delta > 0) {
      runTokens += delta;
      if (budget) {
        budget = recordTokens(budget, delta);
        opts.store.updateBudget(opts.assessmentId, budget); // live-reflect to WebUI/status
      }
    }
    return turns;
  };

  let turns = 0;
  try {
    // resume = we just started running = no longer paused. Clear the "⏸ paused" set on the previous token exhaustion
    //   (if it lingers, the WebUI keeps showing paused while actually running).
    if (opts.resume && opts.store.isPaused(opts.assessmentId)) {
      opts.store.setPaused(opts.assessmentId, false, "resumed");
    }
    // On resume, decide from events how far survey/methodology got last time.
    // Note: survey-only is also "done" but the phase stays phase1_recon, so phase can't distinguish it from an interruption.
    //   Decide via the "SURVEY done" marker survey_done emits and methodology's "📋 PLAN" events.
    const { surveyDone: surveyDonePrev, methodologyDone: methodologyDonePrev } = resumeStageState(prev);
    const doSurvey = !opts.resume || !surveyDonePrev; // even on resume, if survey is incomplete start from survey
    const doMethodology = !opts.surveyOnly && (!surveyDonePrev || !methodologyDonePrev);

    if (doSurvey) {
      // ── STAGE 1: survey (mapping only) ── on resume with survey incomplete, continue with the existing screens seeded.
      if (opts.resume) opts.onText?.("↻ survey was incomplete, resuming from recon");
      opts.store.setPhase(opts.assessmentId, "phase1_recon");
      // If there are roles, "empty frontier ≠ done" — force mapping the post-login surface (survey_done is auth-gated).
      const authClause =
        rolesLine === "none"
          ? ""
          : ` CRITICAL: an empty frontier is NOT a reason to call survey_done while roles are still unauthenticated. After mapping the public surface you MUST login(role) for EACH role (${rolesLine}), confirm the response shows a cookie/bearer is present, and navigate the authenticated pages it unlocks (orders / basket / wallet / admin / settings / etc.) so they enter the inventory. survey_done is GATED on having an active authenticated session and will be refused otherwise.`;
      const surveyGoal = opts.lockToSeeds
        ? // URL-list lock: map only the seeds, no crawling across.
          `URL-list mode — LOCKED. Diagnose ONLY these exact URLs; do NOT follow links or explore beyond this list:\n${seedList.map((u, i) => `  ${i + 1}. ${u}`).join("\n")}\nFor EACH url: browser_navigate to it (its screen and the APIs it calls are recorded automatically). Log in as needed — roles for login(): ${rolesLine}. When survey_status shows the frontier empty (all ${seedList.length} mapped), call survey_done.${authClause}`
        : seedList.length > 1
          ? // Multiple seeds (with crawling): map the scope surface starting from each seed.
            `Map the in-scope surface starting from these ${seedList.length} seed URLs:\n${seedList.map((u) => `  - ${u}`).join("\n")}\nIn-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Visit each seed, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.${authClause}`
          : `Map the entire in-scope surface of ${opts.targetUrl}. In-scope hosts: ${opts.scope.inScopeHosts.join(", ")}. Roles for login(): ${rolesLine}. Start at the target, follow links, log in as each role, and keep going until survey_status shows the frontier empty. Then survey_done.${authClause}`;
      turns += await runStage({
        system: SURVEY_PROMPT,
        goal: surveyGoal,
        allowed: STAGE_TOOLS.survey,
        maxTurns,
        model: fastModel, // survey is mechanical -> fast
        shouldStop: () => session.surveyDone || session.done,
      });
    }

    // ── Parent-prefix backfill (deterministic, no LLM) ── survey only enrolls what it navigated, so a controller/
    //   directory prefix (/Account implied by /Account/AccountEdit) that is itself a live page but was never linked
    //   stays unmapped — an un-clickable folder in the site tree. Probe each unmapped static ancestor and enroll the
    //   real ones (a 404 / error-catch-all is dropped). Runs whenever survey ran (survey-only included) so those parents
    //   enter the inventory before methodology plans them.
    if (doSurvey && !session.done) {
      try {
        const bf = await backfillParentPrefixes(session);
        if (bf.enrolled > 0) opts.onText?.(`🧭 parent-prefix backfill: +${bf.enrolled} screen(s) from ${bf.probed} unmapped parent path(s)`);
      } catch (e) {
        opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ parent-prefix backfill skipped: ${String(e).slice(0, 120)}` } });
      }
    }

    // ── Recon extrapolation (LLM URL guessing) ── the deterministic backfill only fills structural PARENTS; here a
    //   bounded LLM pass reads the mapped surface, infers the app's URL/naming convention, and probe_guesses the endpoints
    //   it predicts exist but were never linked (missing CRUD actions, sibling controllers, admin variants, API
    //   resources). Real hits enroll; 404s drop. A fresh, single-job query() guesses far better than tacking this onto the
    //   survey loop (where the model drifts to survey_done). Skipped under a URL-list lock or once the survey cap is hit.
    if (doSurvey && !session.done && !opts.lockToSeeds && !session.surveyCapped && session.inv.screens().length > 0) {
      opts.store.setPhase(opts.assessmentId, "phase1_recon");
      turns += await runStage({
        system: RECON_GUESS_PROMPT,
        goal: `${session.inv.screens().length} screens were mapped. Call get_inventory, infer the app's URL/naming convention, then probe_guesses the endpoints you predict exist but were not linked (missing CRUD actions on known controllers, sibling controllers by analogy, admin/privileged variants, API resources matching the observed style). Real pages are enrolled automatically; wrong guesses are dropped. Iterate AT MOST twice, then guess_done.`,
        allowed: STAGE_TOOLS.reconGuess,
        maxTurns: Math.min(maxTurns, 12),
        model: fastModel, // guessing is mechanical -> fast
        shouldStop: () => session.reconGuessDone || session.done,
      });
    }

    // ── Early fingerprint (before methodology) ── detect the stack and produce tech-aware attack-plan hints.
    //    The A06 fingerprint stage runs *after* diagnosis, too late for planning. Here we lightly GET root/login/first screens
    //    (deterministic, no LLM) and inject detected-stack -> target-attack-classes into the methodology goal.
    let techClause = "";
    if (doMethodology && !session.done) {
      try {
        const seeds: string[] = [opts.targetUrl];
        if (opts.loginUrl) seeds.push(opts.loginUrl);
        for (const sc of session.inv.screens().slice(0, 2)) {
          const u = sc.observedUrls[0];
          if (u) seeds.push(u);
        }
        const samples: TechSample[] = [];
        const seen = new Set<string>();
        for (const u of seeds) {
          if (seen.has(u) || samples.length >= 3) continue;
          seen.add(u);
          try {
            const r = await http.send({ method: "GET", url: u, headers: session.currentCookie ? { cookie: session.currentCookie } : {}, body: null });
            samples.push({ url: u, headers: r.headers, body: r.body });
          } catch {
            /* best-effort */
          }
        }
        const components = fingerprintTech(samples);
        if (components.length > 0) {
          const hints = stackAttackHints(components);
          const stackStr = components.map((c) => (c.version ? `${c.name} ${c.version}` : c.name)).join(", ");
          opts.store.appendEvent(opts.assessmentId, {
            type: "note",
            payload: { message: `🔎 early fingerprint (pre-plan): ${stackStr}${hints.length ? ` → ${hints.length} stack-specific attack hint(s) fed into planning` : ""}` },
          });
          techClause =
            `DETECTED TECH STACK (fingerprinted BEFORE planning): ${stackStr}.\n` +
            (hints.length ? `Stack-specific attack surface — BAKE these classes into the relevant per-screen plans:\n${hints.map((h) => `  - ${h}`).join("\n")}\n` : "") +
            `\n`;
        }
      } catch {
        /* fingerprint failure must not block planning */
      }
    }

    // ── STAGE 2: methodology (attack plan for every screen) ── survey-only skips it. resume runs it only when incomplete.
    if (doMethodology && !session.done) {
      opts.store.setPhase(opts.assessmentId, "phase1_label");
      turns += await runStage({
        system: METHODOLOGY_PROMPT,
        goal: `${techClause}${session.inv.screens().length} screens were mapped. Call get_inventory, then record_methodology for EVERY screen, then methodology_done.`,
        allowed: STAGE_TOOLS.methodology,
        maxTurns: Math.min(maxTurns, 30),
        model: fastModel, // methodology is fast too (structured plan authoring)
        shouldStop: () => session.methodologyDone || session.done,
      });
    }

    // ── STAGE 3: diagnosis (one screen at a time; drive every queued ledger entry to done) ── skipped if survey-only
    if (!opts.surveyOnly && !session.done) {
      opts.store.setPhase(opts.assessmentId, "phase2_scan");
      // On resume, skip terminal (clean/finding/excluded) **first**, then run only the un-diagnosed up to maxScreens.
      // Note: slicing first ends with 0 without looking at queued when the head is all terminal (this was a bug).
      const TERMINAL = new Set(["clean", "finding", "suspected", "excluded"]);
      const candidates = resumeStatus
        ? session.inv.screens().filter((sc) => !TERMINAL.has(resumeStatus.get(sc.screenId) ?? "queued"))
        : session.inv.screens();
      const screens = candidates.slice(0, opts.maxScreens ?? 40);
      opts.onText?.(
        `🔬 diagnosing ${screens.length} screen(s)${resumeStatus ? ` of ${candidates.length} queued` : ""}${candidates.length > screens.length ? ` (capped at ${opts.maxScreens ?? 40}; resume again or raise --max-screens for the rest)` : ""}`,
      );
      // Screens with multiple endpoints need >25 turns to confirm IDOR. At 25 it capped out just before recording.
      const perScreen = Math.min(maxTurns, 40);

      // ── Keep the auth session alive (A) ── if the gap between screens grows, do a raw-HTTP GET of a safe authed URL
      //   (never `/`, no page load) to keep a sliding/short-lived token from going stale, and re-sync the rotated cookie.
      //   attended holds a live context per role: re-read each role's live cookie jar (no navigation) and touch to detect
      //   expiry — a role bounced to login (401/login body) prompts the operator to re-login (handoff).
      const keepAliveMs = (opts.keepAliveMinutes ?? (opts.attended ? 1 : 4)) * 60_000;
      let lastTouch = Date.now();
      const keepAttendedWarm = async (): Promise<void> => {
        if (!roleSessions) return;
        for (const [role, rs] of roleSessions) {
          try {
            // The operator's live browser is authoritative — re-read its cookie jar (no navigation) to pick up rotation.
            const jar = await rs.driver.sessionCookieHeader().catch(() => "");
            if (jar) rs.cookie = jar;
            let dead = false;
            if (lastWarmUrl) {
              const r = await warmTouch(lastWarmUrl, rs.cookie, role === session.currentRole ? session.currentBearer : "");
              dead = r?.dead ?? false;
            }
            if (dead && opts.promptOperator) {
              opts.onText?.(`🔴 role ${roleLabel(role, opts.roleDescriptions)} session appears to have expired (bounced back to the login page)`);
              await opts.promptOperator(`▶ Please log in again in the browser window for role ${roleLabel(role, opts.roleDescriptions)}. Press Enter when done…`);
              const fresh = await rs.driver.sessionCookieHeader().catch(() => "");
              if (fresh) rs.cookie = fresh;
            }
            if (role === session.currentRole) session.currentCookie = rs.cookie; // for the active role, update the http path too
          } catch (e) {
            opts.onText?.(`⚠ keepalive '${role}' failed: ${String(e).slice(0, 100)}`);
          }
        }
        opts.store.appendEvent(opts.assessmentId, {
          type: "note",
          payload: { message: `🫀 keepalive (attended): re-synced ${roleSessions.size} role(s) (keep session alive)` },
        });
      };
      const keepSessionWarm = async (warm: string | null): Promise<void> => {
        if (keepAliveMs <= 0) return;
        if (Date.now() - lastTouch < keepAliveMs) return;
        if (opts.attended) {
          await keepAttendedWarm();
          lastTouch = Date.now();
          return;
        }
        if (!session.currentCookie && !session.currentBearer) return; // unauth: nothing to keep warm
        const url = warm ?? lastWarmUrl;
        if (!url) return; // no safe authed URL yet — skip rather than touch `/`
        const r = await warmTouch(url, session.currentCookie, session.currentBearer);
        if (r) {
          session.currentCookie = r.cookie; // re-sync the raw HTTP path cookie (rotated Set-Cookie)
          opts.store.appendEvent(opts.assessmentId, {
            type: "note",
            payload: { message: `🫀 keepalive: touched ${new URL(url).pathname} (keep session alive, no reload)` },
          });
        }
        lastTouch = Date.now();
      };

      // Diagnose one screen (shared body called from both the primary path and the drain). "break" stops the outer loop.
      const diagnoseOne = async (sc: Screen): Promise<"continue" | "break"> => {
        const scUrl = warmTarget(sc.observedUrls?.[0]); // the authed page we're about to diagnose = a safe warm target
        await keepSessionWarm(opts.anchorUrl ?? scUrl); // with an anchor set, keep warming the stable hub
        if (scUrl && !opts.anchorUrl) lastWarmUrl = scUrl; // else remember it for attended/Burp keepalive (no per-screen context)
        session.currentScreenId = sc.screenId;
        session.screenDone = false;
        session.screenVerdict = null;
        session.screenSkipReason = null;
        session.screenProbes = 0; // reset per screen for the coverage-gate cross-check
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, "scanning");
        turns += await runStage({
          system: DIAGNOSE_PROMPT,
          goal: `Diagnose screen ${sc.screenId} (${sc.urlTemplate}). Call get_screen for its detail and plan, test that plan with evidence discipline, then screen_done.`,
          allowed: STAGE_TOOLS.diagnose,
          maxTurns: perScreen,
          model: screenIsHighValue(sc) ? deepModel : fastModel, // only high-value screens go deep (opus)
          shouldStop: () => session.screenDone || session.done,
        });
        // If interrupted by token/usage-limit exhaustion: return this screen to queued **still un-diagnosed** (not clean),
        // pause, and exit. On resume it continues from the queued screens (this one and the untouched rest).
        if (session.paused) {
          opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, "queued");
          return "break";
        }
        // The ledger decides terminal by the **confidence of the finding actually recorded** (confirmed->finding / suspected->suspected /
        //   none->clean). screenVerdict is the authoritative value record_finding maintains (upgrade-only; the model's screen_done self-report never overwrites it).
        //   skip_screen flags the screen out-of-scope for active testing (high-harm / out-of-ROE) → excluded (terminal), and the run continues.
        const status = session.screenSkipReason
          ? "excluded"
          : session.screenVerdict === "finding"
            ? "finding"
            : session.screenVerdict === "suspected"
              ? "suspected"
              : "clean";
        opts.store.setScreenScanStatus(opts.assessmentId, sc.screenId, status);

        // ── Auth-wall circuit breaker ── if every probe returns 401 and nothing gets through (zero 2xx, zero findings),
        //    running more screens is pointless. Stop and prompt the operator to set auth (httpBasic/creds/cookie).
        if (isAuthWalled(session)) {
          const msg = `🛑 auth wall: ${session.httpAuthWall}/${session.httpProbes} probes returned 401 and 0 got through — stopping. Set auth (httpBasic / credentials / cookie) and resume.`;
          opts.onText?.(msg);
          opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: msg } });
          opts.store.upsertHandoff(opts.assessmentId, {
            id: "ho-authwall",
            reason: "auth",
            url: opts.targetUrl,
            message: `Diagnosis is fully behind an auth wall (${session.httpAuthWall}/${session.httpProbes} probes 401, none authenticated). Configure site auth (httpBasic / credentials / cookie) and resume.`,
            status: "pending",
            createdAt: new Date().toISOString(),
            resolvedAt: null,
          });
          session.done = true;
          session.doneSummary = msg;
          return "break";
        }
        return "continue";
      };

      const handled = new Set<string>();
      const maxScan = opts.maxScreens ?? 40;
      // primary path: run the start-time snapshot (in priority order).
      for (const sc of screens) {
        if (session.done) break;
        handled.add(sc.screenId);
        if ((await diagnoseOne(sc)) === "break") break;
      }
      // ── Drain (reusable) ── pick up every queued screen newly enrolled by the input sweep / browser_navigate /
      //    **the later scenario & fingerprint stages**. for(screens) is a start-time snapshot, so screens added to the
      //    ledger afterward fall out of that fixed list and stay queued (= the "scanned 2/5" symptom). To honour the design
      //    intent "drive every queued ledger entry to terminal", re-load the ledger each time and clear scannable, unhandled
      //    screens up to maxScan / pause. Called after each stage.
      const drainQueued = async (): Promise<void> => {
        let drained = 0;
        while (!session.done && handled.size < maxScan) {
          const live = opts.store.loadAssessment(opts.assessmentId);
          if (!live) break;
          const scanById = new Map(live.screenScans.map((s) => [s.screenId, s] as const));
          const next = live.screens.find((s) => {
            if (handled.has(s.screenId)) return false;
            const scan = scanById.get(s.screenId);
            return !!scan && isScannable(scan);
          });
          if (!next) break;
          if (drained === 0) opts.onText?.("🔁 draining screens discovered mid-run (input sweep / new routes / scenario navigation) so coverage closes");
          drained += 1;
          handled.add(next.screenId);
          if ((await diagnoseOne(next)) === "break") break;
        }
        if (drained > 0)
          opts.store.appendEvent(opts.assessmentId, {
            type: "note",
            payload: { message: `🔁 drained ${drained} screen(s) discovered during the run (coverage closed: no queued screens stranded)` },
          });
      };
      await drainQueued();
      session.currentScreenId = null;

      // ── STAGE 4: scenario (A04 cross-screen logic) ── once, after per-screen diagnosis. Inherit real ids / confirmed auth /
      //    observed behaviour to target multi-step workflow abuse (coupon / price & qty tampering / step skip / privilege escalation). Pinned to the deep model.
      //    Leave the contextual call "is there a transactional flow" **to the LLM** (no brittle lexical regex): the model reads
      //    get_inventory, finds workflows, and if there are none closes immediately with scenario_done. Disable with --no-scenario.
      if (opts.scenarioPass !== false && !session.done) {
        session.scenarioDone = false;
        // The operator emphasis hint (--focus) is **carried out in this scenario stage** (cross-cutting/objective-driven, so here rather than per-screen diagnosis is right).
        const focusClause = opts.focus
          ? `OPERATOR FOCUS (highest priority): ${opts.focus}\nTreat this as the PRIMARY objective of THIS stage. Build and test the scenario(s) it implies FIRST, and do NOT call scenario_done until you have ACTIVELY attempted the focus (log in, probe the relevant endpoints, build probe_scenario control/exploit flows for it). After the focus is covered, also handle any other obvious multi-step workflows. `
          : "";
        // Default scenarios (standing objectives): cross-cutting goals pursued every time regardless of --focus (credential hunting etc.).
        const defaultsOn = opts.defaultScenarios !== false && DEFAULT_SCENARIOS.length > 0;
        const defaultClause = defaultsOn
          ? `STANDING OBJECTIVES — pursue every one of these THIS stage, regardless of operator focus or whether any workflow exists:\n${DEFAULT_SCENARIOS.map((s, i) => `  ${i + 1}. [${s.key}] ${s.directive}`).join("\n")}\n\n`
          : "";
        opts.onText?.(
          opts.focus
            ? `🧩 scenario stage: operator focus → ${opts.focus.slice(0, 120)}${defaultsOn ? ` (+ ${DEFAULT_SCENARIOS.length} default scenario(s))` : ""}`
            : `🧩 scenario stage: ${defaultsOn ? `${DEFAULT_SCENARIOS.length} default scenario(s) + ` : ""}surveying the inventory for multi-step (A04) workflows`,
        );
        turns += await runStage({
          system: SCENARIO_PROMPT,
          goal: `${focusClause}${defaultClause}Per-screen diagnosis is done. Call get_inventory, then (a) carry out the STANDING OBJECTIVES above, and (b) decide FROM THE INVENTORY whether this app has any multi-step / state-changing workflow worth abusing (e.g. a cart→checkout→order flow, a coupon/voucher redemption, a fund/points transfer, a multi-step registration/approval, a role/privilege change). For each workflow: log in, walk the legitimate flow once, then build probe_scenario(control, exploit, effectMarker) threading captured ids via {{var}}, and record_finding only on a confirmed verdict. Call scenario_done ONLY after the standing objectives AND every workflow have been covered${defaultsOn ? " (if there are no workflows, still finish the standing objectives before scenario_done)" : opts.focus ? " (if there is none beyond the operator focus, finish the focus first)" : " — if there is no workflow and nothing else to do, call scenario_done"}.`,
          allowed: STAGE_TOOLS.scenario,
          maxTurns: Math.min(maxTurns, 40),
          model: deepModel, // discovering and building workflows is the hardest reasoning -> pinned deep
          shouldStop: () => session.scenarioDone || session.done,
        });
      }

      // ── STAGE: fingerprint (A06 known-vulnerable components) ── collect tech-stack versions and match known CVE/EOL.
      //    Collection is deterministic (fingerprint_scan extracts versions from headers/cookies/meta/script), CVE assessment relies on the deep model's knowledge.
      //    WebFetch is banned, so no external CVE DB is queried; findings are recorded honestly as "version-based, needs confirmation".
      if (opts.fingerprintPass !== false && !session.done) {
        session.fingerprintDone = false;
        opts.onText?.(`🔎 fingerprint stage: collecting tech/version banners → ${session.cveLookup ? "online CVE-DB (OSV/NVD)" : "model-knowledge"} CVE assessment (A06)`);
        // When CVE DB lookup is off, don't offer cve_lookup (avoids wasted turns).
        const fpTools = session.cveLookup ? STAGE_TOOLS.fingerprint : STAGE_TOOLS.fingerprint.filter((t) => t !== "cve_lookup");
        const cveClause = session.cveLookup
          ? "After fingerprint_scan, call cve_lookup with the detected components to get AUTHORITATIVE CVE ids from OSV/NVD, and cite those ids. "
          : "Assess each (component, version) against your own CVE/EOL knowledge (online CVE-DB lookup is off). ";
        turns += await runStage({
          system: FINGERPRINT_PROMPT,
          goal: `Per-screen diagnosis and scenarios are done. Inventory the technology stack: call fingerprint_scan on ${opts.targetUrl} (plus a couple of representative in-scope URLs / the main JS bundle). ${cveClause}record_finding(category vulnerable-component) for every component with a real known issue — name the CVE, cite the version evidence (the banner/script that revealed it), set severity by the worst known issue, and state plainly it is version-based unless actively confirmed. Skip patched/current versions. Call fingerprint_done when every detected component has been assessed.`,
          allowed: fpTools,
          maxTurns: Math.min(maxTurns, 25),
          model: deepModel, // mapping version <-> CVE is knowledge-intensive -> pinned deep
          shouldStop: () => session.fingerprintDone || session.done,
        });
      }

      // ── Final drain ── diagnose queued screens newly enrolled by the scenario / fingerprint stages before report.
      //    (The post-diagnosis drain can't catch screens dug up by the later navigation. e.g. --focus's TOCTOU probing
      //     found /admin_panel etc. -> it fell to report still queued and became "scanned 2/5".)
      await drainQueued();
      session.currentScreenId = null;
    }

    // ── Burp scan phase ── after diagnosis/scenarios, before dropping to report, run it **while the session is alive**.
    //    (Previously runPilot returned -> driver disposed -> cmdPilot ran Burp, so the authed surface couldn't be reached.)
    //    keepWarm does a raw-HTTP touch of a safe authed URL (never `/`, no page load) to keep the session alive.
    if (!opts.surveyOnly && !session.done && opts.onBurpScanPhase) {
      opts.store.setPhase(opts.assessmentId, "phase2_burpscan");
      opts.onText?.("🐝 burp scan phase — active scan with the auth session kept warm");
      const keepWarm = async (): Promise<void> => {
        if (!lastWarmUrl) return; // no safe authed URL mapped — don't fall back to `/`
        try {
          if (roleSessions) {
            for (const [role, rs] of roleSessions) {
              const jar = await rs.driver.sessionCookieHeader().catch(() => "");
              if (jar) rs.cookie = jar;
              const r = await warmTouch(lastWarmUrl, rs.cookie, role === session.currentRole ? session.currentBearer : "");
              if (r && role === session.currentRole) session.currentCookie = r.cookie;
            }
          } else if (session.currentCookie || session.currentBearer) {
            const r = await warmTouch(lastWarmUrl, session.currentCookie, session.currentBearer);
            if (r) session.currentCookie = r.cookie;
          }
        } catch {
          /* best-effort keepalive */
        }
      };
      try {
        await opts.onBurpScanPhase({ keepWarm, cookie: session.currentCookie, bearer: session.currentBearer });
      } catch (e) {
        const m = String(e instanceof Error ? e.message : e).slice(0, 160);
        opts.onText?.(`⚠ burp scan phase error: ${m}`);
        opts.store.appendEvent(opts.assessmentId, { type: "note", payload: { message: `⚠ burp scan phase error: ${m}` } });
      }
    }

    // survey-only stays at phase1_recon (all screens queued = un-diagnosed) -> can be resumed later.
    if (session.paused) {
      // Paused on token exhaustion = still incomplete. Don't drop the phase to report (keep the diagnosis phase),
      // so queued screens can be continued on resume. The WebUI shows "⏸ paused" via control_changed.
      opts.store.appendEvent(opts.assessmentId, {
        type: "note",
        payload: { message: `⏸ run paused (token/usage limit) — ${session.inv.screens().length} screens mapped; resume to finish diagnosis` },
      });
    } else if (!opts.surveyOnly) {
      opts.store.setPhase(opts.assessmentId, "report");
    } else {
      // survey-only finished normally (no crash) = survey is treated as complete. Leave a marker so resume advances to diagnosis, not recon.
      opts.store.appendEvent(opts.assessmentId, {
        type: "note",
        payload: { message: `🗺  SURVEY done (survey-only): ${session.inv.screens().length} screens` },
      });
    }
  } finally {
    liveControl?.close();
    if (roleSessions) {
      // attended closes each role's context (primary is included in roleSessions, so it isn't double-closed).
      for (const rs of roleSessions.values()) await rs.driver.close().catch(() => {});
    } else {
      await driver.close();
    }
  }

  const summary = opts.surveyOnly
    ? `survey only: ${session.inv.screens().length} screen(s) mapped (not diagnosed; resume to diagnose).`
    : session.doneSummary ||
      `${session.findings.length} finding(s) across ${session.inv.screens().length} screen(s).`;
  return { findings: session.findings, summary, turns, tokensUsed: runTokens, costUsd };
}
