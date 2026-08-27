// Post-Burp-import verification phase: the AI actively re-tests Burp active-scan High+ findings to confirm/refute them.
// Burp's scanner produces false positives (especially SSTI/XSS/desync/reflected classes), so for each imported High+
// the AI reproduces it with its own http_request (negative control + >=2 stable positives = evidence discipline) and
// judges by the effect. A refutation does NOT remove it from the report, but drops it to **info** and labels it a LIKELY
// FALSE POSITIVE (so a refuted medium/high stops masquerading at its Burp severity). Confirmations are marked [burp✓]
// (raised upward-only to the confirmed level), refutations [burp?].
//
// Self-contained: does not depend on the diagnosis stage's heavy PilotSession (driver/inventory…) — runs on just the
// http client and evidence store. Callable from runBurpScanOnRun / burp-import (either the REST or XML import path).

import { createSdkMcpServer, query, tool } from "@anthropic-ai/claude-agent-sdk";
import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { isInScope } from "@veritas/core";
import type { AssessmentStore, Finding, FindingVerdict, ScopePolicy, Severity } from "@veritas/core";
import { readEvidenceArtifact, classifyBurpName } from "@veritas/scanner";
import type { EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse } from "@veritas/scanner";
import type { PlaywrightDriver } from "@veritas/crawler";
import { resolveLlmConfig } from "@veritas/llm";
import { runOpenAiAgentLoop, type PilotToolDef } from "./agent-loop.js";

export interface VerifyBurpDeps {
  store: AssessmentStore;
  assessmentId: string;
  scope: ScopePolicy;
  /** Scope-gated http client (carries auth headers if needed). */
  http: FetchHttpClient;
  /** EvidenceStore bound to runs/<id>/artifacts (records the re-test req/resp). */
  evidence: EvidenceStore;
  /** artifacts directory for reading the original req/resp a Burp finding cites. */
  artifactsDir: string;
  /** Cookie header for reproducing authenticated findings (optional; without it, verification runs unauthenticated). */
  cookie?: string;
  /** Bearer JWT (optional). Apps like Juice Shop verify /profile via Bearer, so without it the re-test is rejected with
   *  401/"Blocked" and wrongly judged "could not reproduce" (the root cause of failing SSTI/XSS re-verification). Sent on
   *  Authorization together with the cookie. */
  bearer?: string;
  /** Live headless browser (optional). When present, XSS leads get an ACTUAL-EXECUTION DOM re-test (probe_dom_xss).
   *  Raw HTTP cannot observe client-side / DOM sinks (SPA / hash-route / innerHTML), which is exactly why HTTP-only
   *  re-verification mislabels DOM-XSS as false positives. Absent → HTTP-only (unchanged behaviour). */
  driver?: PlaywrightDriver;
  model?: string;
  maxTurnsPerFinding?: number;
  onText?: (t: string) => void;
  onTool?: (n: string, i: unknown) => void;
}

/** A re-verification outcome. `inconclusive` is the middle ground: the reported surface is real (the input DOES reflect,
 *  the endpoint exists) but exploitation could not be proven with the tools at hand — a manual/browser lead, NOT a false
 *  positive. It keeps the finding at its current severity (no bump, no drop-to-info). */
export type DeepDiveOutcome = "confirmed" | "inconclusive" | "refuted";

export interface VerifyBurpResult {
  checked: number;
  confirmed: number;
  inconclusive: number;
  refuted: number;
}

const HIGH_PLUS = new Set<Severity>(["high", "critical"]);
// onlyVeritasToolsHook is the real boundary. But unless we hide the built-ins the preset surfaces here, the model keeps
// hitting ToolSearch etc. and getting denied (wasting turns). Kept in sync with run.ts's DISALLOWED.
const DISALLOWED = [
  "Bash", "BashOutput", "KillShell", "Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "WebFetch", "WebSearch",
  "Task", "Agent", "ToolSearch", "TodoWrite", "Skill", "Monitor", "Workflow", "EnterPlanMode", "ExitPlanMode", "SendMessage",
  "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "TaskStop", "TaskOutput", "CronCreate", "CronList", "CronDelete",
];

const onlyVeritasToolsHook: HookCallback = async (input) => {
  const name = (input as { tool_name?: string }).tool_name ?? "";
  if (name.startsWith("mcp__veritas__")) return { continue: true };
  return {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: "deny",
      permissionDecisionReason: `burp-verify only permits veritas tools. '${name}' is denied.`,
    },
  };
};

const VERIFY_SYSTEM = `You are independently RE-VERIFYING a vulnerability that Burp Suite's automated active scanner reported. Automated scanners produce false positives, so you must REPRODUCE the issue with your own requests before confirming — never trust Burp's verdict alone.

Procedure:
1. Call burp_evidence to read Burp's original request/response.
2. Send a NEGATIVE CONTROL (the payload absent / a benign value) — it must NOT show the vulnerable behaviour.
3. Reproduce the attack at least TWICE — both must show the SAME behaviour (stable).

Judge by the EXPLOITABLE EFFECT — not by Burp's say-so, and NOT by mere input reflection:
- SSTI: an arithmetic payload (e.g. 7*7) must render its result (49); the control must not.
- XSS: the payload must ACTUALLY EXECUTE, or come back UNENCODED in an executable HTML context. Input merely being echoed back ("input returned in response" / "reflected") is NOT XSS on its own — most reflections are inert (HTML-escaped, or inside a JSON / attribute / plain-text context). For client-rendered / SPA / hash-route inputs the sink lives in the browser, so raw HTTP shows escaped-or-absent even when it executes: if probe_dom_xss is available, use it to drive a real browser and confirm the payload RAN; if it is not available, treat a bare reflection you cannot prove executes as INCONCLUSIVE (a DOM sink you can't reach over HTTP), never refuted.
- SQLi: a boolean / UNION / error difference vs the control that proves query control.
- Open redirect / SSRF / desync: the concrete side effect (Location to an attacker host, a fetched marker, a smuggled response).

Then call verdict EXACTLY ONCE, choosing one of THREE outcomes:
- confirmed: you reproduced the EXPLOITABLE effect (control clean + >=2 stable positives that PROVE impact — execution, breakout, injected result, cross-user data). Pass the evidenceIds you used.
- inconclusive: the reported surface is real (the input IS reflected, the endpoint exists) but you could NOT prove exploitation with the tools at hand (no execution proven, a client-side sink you can't reach, or it needs conditions you can't set up). The finding is KEPT AS A LEAD at its current severity for manual/browser review — this is NOT a false positive, so do NOT use refuted for it.
- refuted: the reported behaviour is ABSENT / not reproducible at all (the input does not even reflect, control == positive, no signal) — a genuine likely false positive.

Reproducing a bare reflection WITHOUT proving execution is INCONCLUSIVE, not confirmed. When you cannot prove exploitation, prefer inconclusive over both confirmed and refuted. Keep it to a handful of requests.`;

/** Extract the target endpoint from the "@ <url>" tail of a Burp finding's description. null if absent. */
export function endpointOf(f: Finding): string | null {
  const m = /@\s+(https?:\/\/\S+)\s*$/.exec(f.description.trim());
  return m?.[1] ?? null;
}

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

// Run a small bounded tool-loop for a burp re-verify / lead-selection stage. Default = the Claude Agent SDK (query());
// VERDICT_LLM_PROVIDER=openai routes the SAME tools through the OpenAI-compatible loop instead (OpenCodeGo etc.), with
// the allowlist as the locked toolbox. The tools' handlers write their result into a closure box; shouldStop reads it.
async function runVerifyToolLoop(
    deps: { onText?: (t: string) => void; onTool?: (n: string, i: unknown) => void; model?: string },
    p: { tools: unknown[]; allowed: string[]; system: string; goal: string; maxTurns: number; shouldStop: () => boolean; label: string },
): Promise<void> {
    const vcfg = resolveLlmConfig(process.env);
    if (vcfg.provider === "openai") {
        if (!vcfg.baseURL || !vcfg.model) throw new Error("VERDICT_LLM_PROVIDER=openai needs VERDICT_LLM_BASE_URL + VERDICT_LLM_MODEL for burp re-verify");
        await runOpenAiAgentLoop({
            baseURL: vcfg.baseURL,
            ...(vcfg.apiKey ? { apiKey: vcfg.apiKey } : {}),
            model: vcfg.model,
            system: p.system,
            goal: p.goal,
            tools: p.tools as unknown as PilotToolDef[],
            allowed: p.allowed,
            maxTurns: p.maxTurns,
            mode: (process.env.VERDICT_LLM_TOOL_MODE as "native" | "text" | "auto" | undefined) ?? "auto",
            onText: (t) => deps.onText?.(t),
            onToolUse: (n, i) => deps.onTool?.(n, i),
            shouldStop: p.shouldStop,
        });
        return;
    }
    const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: p.tools as never });
    const q = query({
        prompt: p.goal,
        options: {
            mcpServers: { veritas: server },
            allowedTools: p.allowed.map((n) => `mcp__veritas__${n}`),
            disallowedTools: DISALLOWED,
            permissionMode: "bypassPermissions",
            hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
            ...(deps.model ? { model: deps.model } : {}),
            systemPrompt: { type: "preset", preset: "claude_code", append: p.system },
            maxTurns: p.maxTurns,
        },
    });
    try {
        for await (const msg of q) {
            if (msg.type === "assistant") {
                for (const block of msg.message.content) {
                    if (block.type === "text" && block.text.trim()) deps.onText?.(block.text.trim());
                    else if (block.type === "tool_use") deps.onTool?.(block.name, block.input);
                }
            }
            if (p.shouldStop()) break;
        }
    } catch (e) {
        deps.onText?.(`⚠ ${p.label} ended early: ${String(e instanceof Error ? e.message : e).slice(0, 140)}`);
    }
    try {
        await q.return?.(undefined as never);
    } catch {
        /* generator already done */
    }
}

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

/**
 * The AI actively re-tests Burp-derived High+ findings to confirm/refute them. Idempotent (skips already-marked findings).
 * A refutation drops the finding to info + labels it a likely false positive. Marks confirm=[burp✓] / refute=[burp?] and attaches the AI's re-test evidence.
 */
export async function verifyBurpFindings(deps: VerifyBurpDeps): Promise<VerifyBurpResult> {
  const all = deps.store.loadAssessment(deps.assessmentId)?.findings ?? [];
  const targets = all.filter(
    (f) =>
      HIGH_PLUS.has(f.severity) &&
      f.source.kind === "validator" &&
      f.source.validatorName === "burp" &&
      !/\[burp[✓?~]\]/.test(f.title), // already-verified (✓ confirmed / ? refuted / ~ inconclusive) are skipped (idempotent)
  );
  const result: VerifyBurpResult = { checked: 0, confirmed: 0, inconclusive: 0, refuted: 0 };
  if (targets.length === 0) return result;

  const maxTurns = deps.maxTurnsPerFinding ?? 12;
  for (const f of targets) {
    result.checked += 1;
    const o = await deepDiveOne(deps, f, maxTurns);
    if (o === "confirmed") result.confirmed += 1;
    else if (o === "inconclusive") result.inconclusive += 1;
    else result.refuted += 1;
  }
  return result;
}

/**
 * Shared core that has the AI actively re-test a single Burp finding to confirm/refute it (used by both High+ verification
 * and sub-High deep-dive). Passing confirmSeverity **raises** severity to it on confirmation (e.g. a reflection imported as
 * info that turned out to be real XSS).
 */
async function deepDiveOne(
  deps: VerifyBurpDeps,
  f: Finding,
  maxTurns: number,
  opts: { confirmSeverity?: Severity } = {},
): Promise<DeepDiveOutcome> {
    const endpoint = endpointOf(f);
    // The result for this one finding, written by the verdict tool.
    // NB: it's mutated across the closure, so use a holder object (avoids TS flow-narrowing).
    const box: { outcome: DeepDiveOutcome | null; note: string; ev: string[] } = { outcome: null, note: "", ev: [] };

    const burpEvidence = tool(
      "burp_evidence",
      "Return Burp's original request/response for the finding under verification (so you can craft your own re-test).",
      {},
      async () => {
        const evId = f.evidenceIds[0];
        const art = evId ? readEvidenceArtifact(deps.artifactsDir, evId, 6000) : null;
        return txt(
          JSON.stringify({
            finding: f.title,
            endpoint,
            burpRequest: art?.request ?? "(no stored request)",
            burpResponse: art?.response ?? "(no stored response)",
          }),
        );
      },
    );

    const httpRequest = tool(
      "http_request",
      "Send a scoped raw HTTP request to reproduce (or refute) the finding. Records evidence; returns an evidenceId to cite in the verdict.",
      {
        method: z.string(),
        url: z.string(),
        headers: z.record(z.string()).optional(),
        body: z.string().optional(),
        note: z.string().optional(),
      },
      async ({ method, url, headers, body, note }) => {
        if (!isInScope(url, deps.scope)) return txt(`BLOCKED: ${url} is out of scope`);
        const req: HttpRequest = {
          method: method.toUpperCase(),
          url,
          // Send cookie + Bearer by default so authenticated findings (/profile JWT none, SSTI, etc.) can be reproduced
          // (the model's headers override if it sets them). Without this, Juice Shop returns 401/"Blocked illegal activity".
          headers: {
            ...(deps.cookie ? { cookie: deps.cookie } : {}),
            ...(deps.bearer ? { authorization: `Bearer ${deps.bearer}` } : {}),
            ...(headers ?? {}),
          },
          body: body ?? null,
        };
        let res: HttpResponse;
        try {
          res = await deps.http.send(req);
        } catch (e) {
          return txt(`ERROR: ${String(e).slice(0, 200)}`);
        }
        const ev = deps.evidence.record({
          screenId: "burp-verify",
          validator: "burp-verify",
          kind: "positive_replay",
          request: { ...req, headers: deps.http.effectiveHeaders(req.headers) },
          response: res,
          note: note ?? `verify ${f.id}: ${req.method} ${url}`,
        });
        return txt(
          JSON.stringify({
            evidenceId: ev.id,
            status: res.status,
            headers: pick(res.headers, ["content-type", "location", "set-cookie", "www-authenticate", "access-control-allow-origin"]),
            bodyLength: res.body.length,
            body: res.body.slice(0, 1800),
          }),
        );
      },
    );

    // Optional DOM-XSS probe — only when a live browser is attached. Raw HTTP cannot see client-side / SPA / hash-route
    // sinks execute, so without this an XSS lead that DOES fire in the browser gets wrongly refuted (the FP problem).
    const domXss = deps.driver
      ? tool(
          "probe_dom_xss",
          "Confirm DOM / client-side XSS by ACTUAL BROWSER EXECUTION — what raw HTTP cannot see (SPA / hash-route / innerHTML sinks execute only in the browser). Pass url with a {{XSS}} placeholder at the injection point, or url + param. Drives a real browser with an executing payload plus a benign control and reports whether it RAN, returning negativeControl + positiveReplays evidenceIds + effectMarker. Use it whenever an XSS lead's input reflects but raw HTTP does not show it executing.",
          { url: z.string(), param: z.string().optional() },
          async ({ url, param }) => {
            const drv = deps.driver;
            if (!drv) return txt("probe_dom_xss unavailable (no live browser).");
            const tok = `domX${Date.now().toString(36)}${Math.floor(Math.random() * 1e6).toString(36)}`;
            const payload = `"><img src=x onerror="window.__verdict_xss='${tok}';alert('${tok}')">`;
            const benign = `verdict${tok}safe`;
            const buildUrl = (val: string): string | null => {
              try {
                if (url.includes("{{XSS}}")) return url.replace(/\{\{XSS\}\}/g, encodeURIComponent(val));
                if (!param) return null;
                const hashAt = url.indexOf("#"); // hash-route support: the URL API won't touch inside the fragment, build it by hand
                if (hashAt >= 0) {
                  const b = url.slice(0, hashAt);
                  let hash = url.slice(hashAt);
                  const enc = `${encodeURIComponent(param)}=${encodeURIComponent(val)}`;
                  const re = new RegExp(`([?&]${param}=)[^&]*`);
                  if (hash.includes("?")) hash = re.test(hash) ? hash.replace(re, `$1${encodeURIComponent(val)}`) : `${hash}&${enc}`;
                  else hash = `${hash}?${enc}`;
                  return b + hash;
                }
                const uu = new URL(url);
                uu.searchParams.set(param, val);
                return uu.toString();
              } catch {
                return null;
              }
            };
            const run = async (val: string, kind: "negative_control" | "positive_replay", tag: string) => {
              const u = buildUrl(val);
              if (!u) return null;
              if (!isInScope(u, deps.scope)) throw new Error(`out of scope: ${u}`);
              const r = await drv.detectXssExecution(u, tok);
              const ev = deps.evidence.record({
                screenId: "burp-verify",
                validator: "burp-verify-dom-xss",
                kind,
                request: { method: "GET", url: u, headers: {}, body: null },
                // Encode the execution result into the body (carries tok when executed) so record_finding's marker gate can see it.
                response: { status: 200, finalUrl: u, durationMs: 0, headers: { "content-type": "text/html" }, body: r.executed ? `${r.signal} [${tok}]` : r.signal },
                note: `dom-xss ${tag}`,
              });
              return { evId: ev.id, executed: r.executed, signal: r.signal };
            };
            try {
              const ctrl = await run(benign, "negative_control", "control(benign)");
              const p1 = await run(payload, "positive_replay", "payload #1");
              const p2 = await run(payload, "positive_replay", "payload #2");
              if (!ctrl || !p1 || !p2) return txt("ERROR: could not build injection URL — pass url with a {{XSS}} placeholder, or url + param.");
              const confirmed = !ctrl.executed && p1.executed && p2.executed;
              return txt(
                JSON.stringify({
                  negativeControl: ctrl.evId,
                  positiveReplays: [p1.evId, p2.evId],
                  effectMarker: tok,
                  executed: { control: ctrl.executed, payload1: p1.executed, payload2: p2.executed },
                  verdict: confirmed
                    ? "DOM XSS CONFIRMED — the payload EXECUTED in the browser (control did not). Call verdict(confirmed) citing these evidenceIds."
                    : ctrl.executed
                      ? "inconclusive: the benign control also 'executed' — detection is unreliable here, do not confirm."
                      : "NOT executed in the browser: the sink escapes it or is not a live DOM sink. If the input still reflects, this is INCONCLUSIVE (a sink you couldn't reach), not a false positive.",
                }),
              );
            } catch (e) {
              return txt(`ERROR: ${String(e).slice(0, 180)}`);
            }
          },
        )
      : null;

    const verdict = tool(
      "verdict",
      "Record the re-verification verdict for this Burp finding EXACTLY ONCE. confirmed = you reproduced the EXPLOITABLE effect (control clean + >=2 stable positives that prove impact); inconclusive = the surface is real (input reflects / endpoint exists) but you could not prove exploitation (a manual/browser lead, NOT a false positive); refuted = you could not reproduce the reported behaviour at all (likely false positive).",
      {
        verdict: z.enum(["confirmed", "inconclusive", "refuted"]),
        note: z.string().describe("one-sentence justification grounded in the EFFECT you observed (e.g. 'control returned {{7*7}} literally, payload rendered 49 twice'; or 'input reflects but HTML-escaped and probe_dom_xss did not execute')"),
        evidenceIds: z.array(z.string()).optional().describe("the http_request / probe_dom_xss evidenceIds that justify the verdict"),
      },
      async ({ verdict: v, note, evidenceIds }) => {
        box.outcome = v;
        box.note = note;
        if (evidenceIds) box.ev.push(...evidenceIds);
        return txt(`recorded ${v} for ${f.id}.`);
      },
    );

    const domXssHint = domXss ? " For an XSS lead whose input reflects but does not clearly execute in the HTTP body, use probe_dom_xss (real browser) before deciding — do not refute a possible DOM sink." : "";
    const goal = `Re-verify Burp finding ${f.id}: [${f.severity}] ${f.title.replace(/^\[burp\]\s*/, "")}${endpoint ? ` at ${endpoint}` : ""}. Start with burp_evidence, reproduce it (control + >=2 positives), then call verdict.${domXssHint}`;
    await runVerifyToolLoop(deps, {
      tools: [burpEvidence, httpRequest, ...(domXss ? [domXss] : []), verdict],
      allowed: ["burp_evidence", "http_request", ...(domXss ? ["probe_dom_xss"] : []), "verdict"],
      system: VERIFY_SYSTEM,
      goal,
      maxTurns,
      shouldStop: () => !!box.outcome, // one verdict per finding
      label: `verify ${f.id}`,
    });

    // Ended without a verdict (maxTurns etc.) → INCONCLUSIVE, not refuted: running out of budget is not evidence of a
    // false positive, so it must not drop the finding to info. Keep it as a lead at its current severity.
    const finalOutcome: DeepDiveOutcome = box.outcome ?? "inconclusive";
    const note = box.note || (box.outcome ? "" : "automated re-test did not reach a verdict within the budget — kept as a lead");
    annotate(deps, f, finalOutcome, note, box.ev, finalOutcome === "confirmed" ? opts.confirmSeverity : undefined);
    return finalOutcome;
}

export interface TriageDeepDiveResult {
  /** total number of sub-High Burp leads (the count of the list shown to the model) */
  listed: number;
  /** number the model selected for deep-dive */
  selected: number;
  confirmed: number;
  inconclusive: number;
  refuted: number;
}

const SELECT_SYSTEM = `You are triaging a list of LOWER-severity issues Burp's scanner reported. Most are noise (hygiene, low-value disclosures), but some are ENTRY POINTS to real vulnerabilities the scanner under-rated:
- "Input returned in response (reflected/stored)" / "Cross-site scripting" → reflected/stored XSS, IF the input returns unescaped in an executable context.
- "External service interaction (DNS/HTTP)" → SSRF / OOB.
- "Cross-origin resource sharing: arbitrary origin trusted" → cross-site data theft, IF the response is credentialed and sensitive.
- "Cross-site request forgery", "Open redirection", "File upload", weak CSP, exposed API spec → their respective classes.
Each row carries a heuristic hint «lead/priority» — treat it as a suggestion, not a verdict; use your own judgement on the title and endpoint.
Pick ONLY the rows genuinely worth a deep active re-test — favour those that plausibly lead to a concrete, high-impact effect; skip pure hygiene and trivial disclosures. Then call select_leads(ids, reason) EXACTLY ONCE. Be selective: a handful, not all of them.`;

/**
 * New phase: "list titles → the model picks the promising ones → deep-dive".
 * Shows the model a list of the **sub-High Burp leads** that verifyBurpFindings doesn't touch (each row with a heuristic
 * hint), and actively re-tests (evidence discipline) only the ones it picks via deepDiveOne. On confirmation, raises severity
 * to the hint's level. It does NOT verify all of them — per the operator's policy, "only deep-dive the promising ones".
 */
export async function triageAndDeepDiveBurp(
  deps: VerifyBurpDeps,
  opts: { maxDeepDives?: number } = {},
): Promise<TriageDeepDiveResult> {
  const all = deps.store.loadAssessment(deps.assessmentId)?.findings ?? [];
  const leads = all.filter(
    (f) =>
      f.source.kind === "validator" &&
      f.source.validatorName === "burp" &&
      !HIGH_PLUS.has(f.severity) &&
      !/\[burp[✓?~]\]/.test(f.title), // already-verified (✓ / ? / ~) are skipped (idempotent)
  );
  const res: TriageDeepDiveResult = { listed: leads.length, selected: 0, confirmed: 0, inconclusive: 0, refuted: 0 };
  if (leads.length === 0) return res;

  const strip = (t: string): string => t.replace(/^\[burp\]\s*/, "").replace(/\s*\(\d+ URLs?\)\s*$/, "");
  const listing = leads
    .map((f) => {
      const c = classifyBurpName(strip(f.title));
      const ep = endpointOf(f);
      return `- ${f.id} [${f.severity}] ${strip(f.title)}${ep ? ` @ ${ep}` : ""}${c ? `  «hint: ${c.lead}/${c.priority}»` : ""}`;
    })
    .join("\n");

  // ── Selection phase (1 query) ── the model reviews the list and picks deep-dive targets.
  const picked: { ids: string[]; reason: string } = { ids: [], reason: "" };
  const selectLeads = tool(
    "select_leads",
    "Record which lead ids are worth a deep active re-test. Call EXACTLY ONCE.",
    {
      ids: z.array(z.string()).describe("the finding ids (e.g. b-012) to deep-dive"),
      reason: z.string().describe("one sentence: why these and not the rest"),
    },
    async ({ ids, reason }) => {
      picked.ids = ids;
      picked.reason = reason;
      return txt(`selected ${ids.length} of ${leads.length}`);
    },
  );
  await runVerifyToolLoop(deps, {
    tools: [selectLeads],
    allowed: ["select_leads"],
    system: SELECT_SYSTEM,
    goal: `${leads.length} lower-severity Burp issues (format: id [severity] title @ endpoint «heuristic hint»):\n${listing}\n\nReview the titles and pick the ones worth deep-diving, then call select_leads.`,
    maxTurns: 4,
    shouldStop: () => picked.ids.length > 0,
    label: "burp triage selection",
  });

  const cap = opts.maxDeepDives ?? 12;
  const chosen = leads.filter((f) => picked.ids.includes(f.id)).slice(0, cap);
  res.selected = chosen.length;
  if (chosen.length === 0) {
    deps.onText?.(`burp triage: model selected nothing to deep-dive of ${leads.length} lead(s)`);
    return res;
  }
  deps.store.appendEvent(deps.assessmentId, {
    type: "note",
    payload: { message: `🔬 burp triage: deep-diving ${chosen.length}/${leads.length} model-flagged lead(s) — ${picked.reason.slice(0, 160)}` },
  });

  const maxTurns = deps.maxTurnsPerFinding ?? 12;
  for (const f of chosen) {
    const c = classifyBurpName(strip(f.title));
    // A confirmed lead is raised to its vuln CLASS band max — NOT the entry-point hint priority. Reproducing an
    // "input returned in response" reflection therefore can never bump a finding to High (reflected-XSS caps at Medium).
    const confirmSeverity = confirmedLeadSeverity(c?.lead);
    const outcome = await deepDiveOne(deps, f, maxTurns, { confirmSeverity });
    if (outcome === "confirmed") res.confirmed += 1;
    else if (outcome === "inconclusive") res.inconclusive += 1;
    else res.refuted += 1;
  }
  return res;
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Class band MAX per Burp lead — mirrors the pilot's SEVERITY_BAND (tools.ts) for the classes burp-verify may raise a
 *  CONFIRMED lead to. Reflected / DOM XSS caps at Medium (reproducing an "input returned in response" reflection must NOT
 *  bump a finding to High); stored-XSS / SSRF cap at High. Anything not listed caps at Medium (a fuzzy confirmed lead is
 *  never auto-High). This is what turns the entry-point "notice this" hint priority into an honest severity ceiling. */
const LEAD_CONFIRM_SEVERITY: Record<string, Severity> = {
  "xss-reflected": "medium",
  "xss-dom": "medium",
  "xss-stored": "high",
  ssrf: "high",
  "open-redirect": "medium",
  csrf: "medium",
};

/** The severity a CONFIRMED sub-High Burp lead may be raised to = its vuln CLASS band max (above), NOT the entry-point
 *  hint priority. Ambiguous / unlisted classes cap at Medium. */
export function confirmedLeadSeverity(lead: string | undefined): Severity {
  return (lead && LEAD_CONFIRM_SEVERITY[lead]) || "medium";
}

/** The severity a Burp finding takes after AI re-verification:
 *  - confirmed → raised UPWARD-ONLY to the class-band severity (never lowers a higher current, never exceeds the band);
 *  - inconclusive → UNCHANGED (surface real but exploitation unproven — a manual/browser lead, not a false positive);
 *  - refuted → info (could not reproduce at all = likely false positive). */
export function reverifiedSeverity(outcome: DeepDiveOutcome, current: Severity, confirmSeverity?: Severity): Severity {
  if (outcome === "refuted") return "info";
  if (outcome === "inconclusive") return current;
  return confirmSeverity && SEV_RANK[confirmSeverity] > SEV_RANK[current] ? confirmSeverity : current;
}

/** The report verdict a Burp finding takes after re-verification. Only a reproduced-exploitable outcome is `confirmed`;
 *  `inconclusive` (surface real, unproven) and `refuted` (likely FP) become `suspected` so they leave the CONFIRMED total
 *  and the headlined findings section (findingVerdict() defaults undefined→"confirmed", so this must be set explicitly). */
export function reverifiedVerdict(outcome: DeepDiveOutcome): FindingVerdict {
  return outcome === "confirmed" ? "confirmed" : "suspected";
}

/** Attach the verification mark and note to a finding: confirmed=[burp✓] / inconclusive=[burp~] / refuted=[burp?].
 *  Confirmed: raise a sub-High lead upward-only to its class-band severity (correct an under-rated import — capped, never
 *  above the band). Inconclusive: keep it as a lead at its current severity — the automated re-test reproduced the reported
 *  surface but could not prove an exploitable effect (e.g. input reflects but did not execute; a client-side/DOM sink), so
 *  it is NOT a false positive. Refuted (could not reproduce at all): drop to **info** and label it a LIKELY FALSE POSITIVE
 *  so a refuted medium/high stops masquerading at its Burp severity. */
function annotate(
  deps: VerifyBurpDeps,
  f: Finding,
  outcome: DeepDiveOutcome,
  note: string,
  evidenceIds: string[],
  newSeverity?: Severity,
): void {
  const cur = deps.store.loadAssessment(deps.assessmentId)?.findings.find((x) => x.id === f.id) ?? f;
  const mark = outcome === "confirmed" ? "[burp✓]" : outcome === "inconclusive" ? "[burp~]" : "[burp?]";
  const title = cur.title.replace(/^\[burp\]/, mark);
  const bumped = reverifiedSeverity(outcome, cur.severity, newSeverity);
  const head =
    outcome === "confirmed"
      ? `✅ AI-verified by active re-test: ${note}${bumped !== cur.severity ? ` (severity raised ${cur.severity}→${bumped}: confirmed real, not info-only)` : ""}`
      : outcome === "inconclusive"
        ? `🔎 SURFACE REAL, EXPLOITATION UNCONFIRMED — automated re-test reproduced the reported behaviour but could not prove an exploitable effect (e.g. the input reflects but did not execute — likely a client-side/DOM sink or a context needing manual/browser verification). NOT a false positive; kept at its current severity as a lead: ${note}`
        : `⚠ LIKELY FALSE POSITIVE — AI active re-test could not reproduce it${cur.severity !== "info" ? ` (severity ${cur.severity}→info)` : ""}; manual confirmation advised: ${note}`;
  const ev = [...new Set([...cur.evidenceIds, ...evidenceIds])];
  // Set the verdict explicitly. Burp imports carry NO verdict field, and findingVerdict() defaults undefined→"confirmed"
  // (report-model.ts) — so without this an inconclusive/refuted re-verify would still be COUNTED as confirmed and headlined
  // in the report. Only a reproduced-exploitable outcome is confirmed; inconclusive (surface real, unproven) and refuted
  // (likely FP) drop to "suspected" so they leave the confirmed total and land in the leads/needs-review section.
  deps.store.upsertFinding(deps.assessmentId, { ...cur, title, verdict: reverifiedVerdict(outcome), severity: bumped, description: `${head}\n\n${cur.description}`, evidenceIds: ev });
  deps.store.appendEvent(deps.assessmentId, {
    type: "note",
    payload: { message: `${outcome === "confirmed" ? "✅" : outcome === "inconclusive" ? "🔎" : "⚠"} burp-verify ${f.id}: ${outcome} — ${note.slice(0, 200)}` },
  });
}
