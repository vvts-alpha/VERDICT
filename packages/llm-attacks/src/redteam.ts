import type { AssessmentStore, Finding, Severity } from "@veritas/core";
import type { ChatAdapter } from "./adapter.js";
import type { CanaryLeakProbe, OracleVerdict } from "./oracle.js";
import { confirmCanaryLeak } from "./oracle.js";
import type { LlmCategory } from "./taxonomy.js";
import { OWASP_LLM_2025 } from "./taxonomy.js";

/** A named, categorized canary-leak probe carrying the metadata needed to file a Finding. */
export interface RedteamProbe extends CanaryLeakProbe {
  id: string;
  category: LlmCategory;
  title: string;
  severity: Severity;
}

export interface RedteamOptions {
  store: AssessmentStore;
  assessmentId: string;
  chatUrl: string;
  adapter: ChatAdapter;
  probes: RedteamProbe[];
  /** Progress callback fired after each probe is judged. */
  onProbe?: (probe: RedteamProbe, verdict: OracleVerdict) => void;
}

export interface RedteamResult {
  findings: Finding[];
  verdicts: Array<{ probe: RedteamProbe; verdict: OracleVerdict }>;
}

/** Confidence rank so a later confirmed can upgrade an earlier suspected (and never the reverse). */
const rank = (status: string | undefined): number => (status === "confirmed" ? 2 : status === "suspected" ? 1 : 0);

function buildFinding(id: string, probe: RedteamProbe, verdict: OracleVerdict, chatUrl: string): Finding {
  const owasp = OWASP_LLM_2025[probe.category];
  const status = verdict.status === "confirmed" ? "confirmed" : "suspected";
  return {
    id,
    screenId: null,
    title: `[${owasp.id} ${probe.category}] ${probe.title}`,
    severity: probe.severity,
    verdict: status,
    ...(status === "suspected" ? { anomaly: verdict.reason } : {}),
    source: { kind: "validator", validatorName: "llm-redteam" },
    description:
      `${probe.title}\n\n` +
      `OWASP ${owasp.id} — ${owasp.title} (${probe.category}).\n` +
      `An out-of-band canary (${verdict.canary}) planted in the assistant's protected context was ` +
      `surfaced through the chat. ${verdict.reason}.`,
    reproSteps:
      `Chat URL: ${chatUrl}\n` +
      `Negative control (benign): ${JSON.stringify(probe.controlPrompt)}\n` +
      `Attack prompt: ${JSON.stringify(probe.attackPrompt)}\n` +
      `Oracle: fresh conversation per turn; the control must not surface the canary and ` +
      `>=2 positive replays must surface it. Result: ${verdict.status}.`,
    evidenceIds: [],
    scopeBasis: `authorized target ${chatUrl}`,
  };
}

/**
 * Run each probe through the canary oracle and persist confirmed/suspected leaks as core Findings.
 * Refuted probes (the defense held) are returned in `verdicts` but never filed — that is defense-works
 * evidence, not a finding. Findings are deduped by (category, chatUrl), keeping the HIGHEST-confidence probe
 * per category: a later confirmed upgrades an earlier suspected in place (reusing the finding id), never a
 * downgrade. So probe ordering can never turn a real confirmed leak into a weaker suspected lead.
 */
export async function runLlmRedteam(opts: RedteamOptions): Promise<RedteamResult> {
  const verdicts: Array<{ probe: RedteamProbe; verdict: OracleVerdict }> = [];
  const byKey = new Map<string, Finding>();
  let counter = 0;

  for (const probe of opts.probes) {
    const verdict = await confirmCanaryLeak(opts.adapter, probe);
    verdicts.push({ probe, verdict });
    opts.onProbe?.(probe, verdict);
    if (verdict.status === "refuted") continue;

    const key = `${probe.category}::${opts.chatUrl}`;
    const existing = byKey.get(key);
    if (existing && rank(existing.verdict) >= rank(verdict.status)) continue; // keep the stronger; never downgrade

    const id = existing?.id ?? `llm-${String(++counter).padStart(3, "0")}`;
    const f = buildFinding(id, probe, verdict, opts.chatUrl);
    opts.store.upsertFinding(opts.assessmentId, f); // ON CONFLICT updates in place → safe suspected→confirmed upgrade
    byKey.set(key, f);
  }
  return { findings: [...byKey.values()], verdicts };
}
