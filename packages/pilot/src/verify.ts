// Post-Burp-import verification phase: the AI actively re-tests Burp active-scan High+ findings to confirm/refute them.
// Burp's scanner produces false positives (especially SSTI/XSS/desync/reflected classes), so for each imported High+
// the AI reproduces it with its own http_request (negative control + >=2 stable positives = evidence discipline) and
// judges by the effect. A refutation does NOT remove it from the report (severity kept + note only). Confirmations are
// marked [burp✓], refutations [burp?].
//
// Self-contained: does not depend on the diagnosis stage's heavy PilotSession (driver/inventory…) — runs on just the
// http client and evidence store. Callable from runBurpScanOnRun / burp-import (either the REST or XML import path).

import { createSdkMcpServer, query, tool } from "@anthropic-ai/claude-agent-sdk";
import type { HookCallback } from "@anthropic-ai/claude-agent-sdk";
import { z } from "zod";
import { isInScope } from "@veritas/core";
import type { AssessmentStore, Finding, ScopePolicy, Severity } from "@veritas/core";
import { readEvidenceArtifact, classifyBurpName } from "@veritas/scanner";
import type { EvidenceStore, FetchHttpClient, HttpRequest, HttpResponse } from "@veritas/scanner";

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
  model?: string;
  maxTurnsPerFinding?: number;
  onText?: (t: string) => void;
  onTool?: (n: string, i: unknown) => void;
}

export interface VerifyBurpResult {
  checked: number;
  confirmed: number;
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

const VERIFY_SYSTEM = `You are independently RE-VERIFYING a vulnerability that Burp Suite's automated active scanner reported. Automated scanners produce false positives, so you must REPRODUCE the issue with your own HTTP requests before confirming — never trust Burp's verdict alone.

Procedure:
1. Call burp_evidence to read Burp's original request/response.
2. Use http_request to send a NEGATIVE CONTROL (the payload absent / a benign value) — it must NOT show the vulnerable behaviour.
3. Use http_request to send the attack request at least TWICE — both must reproduce the SAME vulnerable behaviour (stable).
Judge by the EFFECT, not by Burp's say-so:
- SSTI: an arithmetic payload (e.g. 7*7) must render its result (49) in the response, and the control must not.
- Reflected/stored XSS: the exact injected markup must come back UNENCODED (executable), control encoded/absent.
- SQLi: a boolean/UNION/error difference vs the control that proves query control.
- Open redirect/SSRF/desync: the concrete side effect (Location to attacker host, fetched marker, smuggled response).
Then call verdict EXACTLY ONCE:
- confirmed: you reproduced it (control clean + >=2 stable positives). Pass the evidenceIds you used.
- refuted: you could NOT reproduce it (control == positive, behaviour absent, or unstable). The finding is KEPT for manual review; you are only flagging that automated re-test failed.
Be skeptical: when uncertain, choose refuted. Keep it to a handful of requests.`;

/** Extract the target endpoint from the "@ <url>" tail of a Burp finding's description. null if absent. */
export function endpointOf(f: Finding): string | null {
  const m = /@\s+(https?:\/\/\S+)\s*$/.exec(f.description.trim());
  return m?.[1] ?? null;
}

const txt = (s: string): { content: { type: "text"; text: string }[] } => ({ content: [{ type: "text", text: s }] });

function pick(h: Record<string, string>, keys: string[]): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of keys) if (h[k] !== undefined) o[k] = h[k];
  return o;
}

/**
 * The AI actively re-tests Burp-derived High+ findings to confirm/refute them. Idempotent (skips already-marked findings).
 * A refutation keeps severity unchanged (note only). Marks confirm=[burp✓] / refute=[burp?] and attaches the AI's re-test evidence.
 */
export async function verifyBurpFindings(deps: VerifyBurpDeps): Promise<VerifyBurpResult> {
  const all = deps.store.loadAssessment(deps.assessmentId)?.findings ?? [];
  const targets = all.filter(
    (f) =>
      HIGH_PLUS.has(f.severity) &&
      f.source.kind === "validator" &&
      f.source.validatorName === "burp" &&
      !/\[burp[✓?]\]/.test(f.title), // already-verified are skipped (idempotent)
  );
  const result: VerifyBurpResult = { checked: 0, confirmed: 0, refuted: 0 };
  if (targets.length === 0) return result;

  const maxTurns = deps.maxTurnsPerFinding ?? 12;
  for (const f of targets) {
    result.checked += 1;
    const o = await deepDiveOne(deps, f, maxTurns);
    if (o === "confirmed") result.confirmed += 1;
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
): Promise<"confirmed" | "refuted"> {
    const endpoint = endpointOf(f);
    // The result for this one finding, written by the verdict tool.
    // NB: it's mutated across the closure, so use a holder object (avoids TS flow-narrowing).
    const box: { outcome: "confirmed" | "refuted" | null; note: string; ev: string[] } = { outcome: null, note: "", ev: [] };

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

    const verdict = tool(
      "verdict",
      "Record the re-verification verdict for this Burp finding EXACTLY ONCE. confirmed = you reproduced it (control clean + >=2 stable positives); refuted = automated re-test could not reproduce it.",
      {
        verdict: z.enum(["confirmed", "refuted"]),
        note: z.string().describe("one-sentence justification grounded in the EFFECT you observed (e.g. 'control returned {{7*7}} literally, payload rendered 49 twice')"),
        evidenceIds: z.array(z.string()).optional().describe("the http_request evidenceIds that justify the verdict"),
      },
      async ({ verdict: v, note, evidenceIds }) => {
        box.outcome = v;
        box.note = note;
        if (evidenceIds) box.ev.push(...evidenceIds);
        return txt(`recorded ${v} for ${f.id}.`);
      },
    );

    const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: [burpEvidence, httpRequest, verdict] });
    const goal = `Re-verify Burp finding ${f.id}: [${f.severity}] ${f.title.replace(/^\[burp\]\s*/, "")}${endpoint ? ` at ${endpoint}` : ""}. Start with burp_evidence, reproduce it with http_request (control + >=2 positives), then call verdict.`;

    const q = query({
      prompt: goal,
      options: {
        mcpServers: { veritas: server },
        allowedTools: ["burp_evidence", "http_request", "verdict"].map((n) => `mcp__veritas__${n}`),
        disallowedTools: DISALLOWED,
        permissionMode: "bypassPermissions",
        hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
        ...(deps.model ? { model: deps.model } : {}),
        systemPrompt: { type: "preset", preset: "claude_code", append: VERIFY_SYSTEM },
        maxTurns,
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
        if (box.outcome) break; // stop as soon as a verdict is in (one verdict per finding)
      }
    } catch (e) {
      deps.onText?.(`⚠ verify ${f.id} ended early: ${String(e instanceof Error ? e.message : e).slice(0, 140)}`);
    }
    try {
      await q.return?.(undefined as never);
    } catch {
      /* generator already done */
    }

    // Ended without a verdict (maxTurns etc.) → treated as refuted (could not reproduce = note only).
    const finalOutcome: "confirmed" | "refuted" = box.outcome ?? "refuted";
    const note = box.note || (box.outcome ? "" : "no verdict reached within the re-test budget");
    annotate(deps, f, finalOutcome, note, box.ev, finalOutcome === "confirmed" ? opts.confirmSeverity : undefined);
    return finalOutcome;
}

export interface TriageDeepDiveResult {
  /** total number of sub-High Burp leads (the count of the list shown to the model) */
  listed: number;
  /** number the model selected for deep-dive */
  selected: number;
  confirmed: number;
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
      !/\[burp[✓?]\]/.test(f.title), // already-verified are skipped (idempotent)
  );
  const res: TriageDeepDiveResult = { listed: leads.length, selected: 0, confirmed: 0, refuted: 0 };
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
  const server = createSdkMcpServer({ name: "veritas", version: "1.0.0", tools: [selectLeads] });
  const q = query({
    prompt: `${leads.length} lower-severity Burp issues (format: id [severity] title @ endpoint «heuristic hint»):\n${listing}\n\nReview the titles and pick the ones worth deep-diving, then call select_leads.`,
    options: {
      mcpServers: { veritas: server },
      allowedTools: ["select_leads"].map((n) => `mcp__veritas__${n}`),
      disallowedTools: DISALLOWED,
      permissionMode: "bypassPermissions",
      hooks: { PreToolUse: [{ hooks: [onlyVeritasToolsHook] }] },
      ...(deps.model ? { model: deps.model } : {}),
      systemPrompt: { type: "preset", preset: "claude_code", append: SELECT_SYSTEM },
      maxTurns: 4,
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
      if (picked.ids.length) break;
    }
  } catch (e) {
    deps.onText?.(`⚠ burp triage selection ended early: ${String(e instanceof Error ? e.message : e).slice(0, 140)}`);
  }
  try {
    await q.return?.(undefined as never);
  } catch {
    /* generator already done */
  }

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
    const confirmSeverity: Severity | undefined = c?.priority === "high" ? "high" : c?.priority === "medium" ? "medium" : undefined;
    const outcome = await deepDiveOne(deps, f, maxTurns, confirmSeverity ? { confirmSeverity } : {});
    if (outcome === "confirmed") res.confirmed += 1;
    else res.refuted += 1;
  }
  return res;
}

const SEV_RANK: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/** Attach the verification mark and note to a finding. confirmed=[burp✓] / refuted=[burp?].
 *  When newSeverity is given, raise the severity of a confirmed sub-High lead **upward only** (info→high, etc.). */
function annotate(
  deps: VerifyBurpDeps,
  f: Finding,
  outcome: "confirmed" | "refuted",
  note: string,
  evidenceIds: string[],
  newSeverity?: Severity,
): void {
  const cur = deps.store.loadAssessment(deps.assessmentId)?.findings.find((x) => x.id === f.id) ?? f;
  const mark = outcome === "confirmed" ? "[burp✓]" : "[burp?]";
  const title = cur.title.replace(/^\[burp\]/, mark);
  // If confirmed and the hint severity is higher than the current one, raise it (correcting an under-rated info import). Never lowers.
  const bumped = outcome === "confirmed" && newSeverity && SEV_RANK[newSeverity] > SEV_RANK[cur.severity] ? newSeverity : cur.severity;
  const head =
    outcome === "confirmed"
      ? `✅ AI-verified by active re-test: ${note}${bumped !== cur.severity ? ` (severity raised ${cur.severity}→${bumped}: confirmed real, not info-only)` : ""}`
      : `⚠ AI re-test could not reproduce (severity kept, manual confirmation advised): ${note}`;
  const ev = [...new Set([...cur.evidenceIds, ...evidenceIds])];
  deps.store.upsertFinding(deps.assessmentId, { ...cur, title, severity: bumped, description: `${head}\n\n${cur.description}`, evidenceIds: ev });
  deps.store.appendEvent(deps.assessmentId, {
    type: "note",
    payload: { message: `${outcome === "confirmed" ? "✅" : "⚠"} burp-verify ${f.id}: ${outcome} — ${note.slice(0, 200)}` },
  });
}
