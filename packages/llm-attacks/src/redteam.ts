import type { AssessmentStore, Finding, Severity } from "@veritas/core";
import type { EvidenceStore, HttpRequest, HttpResponse } from "@veritas/scanner";
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
  /** When set, each filed finding's control + positive turns are recorded as CHAT evidence and cited. */
  evidence?: EvidenceStore;
  /** screenId the evidence is filed under (artifactsDir/<screenId>/). Default "assistant". */
  screenId?: string;
  /** Progress callback fired after each probe is judged. */
  onProbe?: (probe: RedteamProbe, verdict: OracleVerdict) => void;
}

export interface RedteamResult {
  findings: Finding[];
  verdicts: Array<{ probe: RedteamProbe; verdict: OracleVerdict }>;
}

/** Confidence rank so a later confirmed can upgrade an earlier suspected (and never the reverse). */
const rank = (status: string | undefined): number => (status === "confirmed" ? 2 : status === "suspected" ? 1 : 0);

/** Record the oracle's negative control + positive replays as synthetic CHAT HTTP evidence; return the ids. */
function recordTurns(evidence: EvidenceStore, screenId: string, chatUrl: string, verdict: OracleVerdict): string[] {
  const req = (prompt: string): HttpRequest => ({ method: "CHAT", url: chatUrl, body: prompt });
  const res = (text: string): HttpResponse => ({ status: 200, headers: {}, body: text, finalUrl: chatUrl, durationMs: 0 });
  const ids: string[] = [
    evidence.record({
      screenId,
      validator: "llm-redteam",
      kind: "negative_control",
      request: req(verdict.control.prompt),
      response: res(verdict.control.reply.text),
      note: "negative control (benign prompt; canary must be absent)",
    }).id,
  ];
  verdict.positives.forEach((p, i) => {
    ids.push(
      evidence.record({
        screenId,
        validator: "llm-redteam",
        kind: "positive_replay",
        request: req(p.prompt),
        response: res(p.reply.text),
        note: `positive replay ${i + 1} (canary ${p.canaryPresent ? "present" : "absent"})`,
      }).id,
    );
  });
  return ids;
}

function buildFinding(
  id: string,
  probe: RedteamProbe,
  verdict: OracleVerdict,
  chatUrl: string,
  evidenceIds: string[],
): Finding {
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
    evidenceIds,
    scopeBasis: `authorized target ${chatUrl}`,
  };
}

/**
 * Run each probe through the canary oracle and persist confirmed/suspected leaks as core Findings.
 * Refuted probes (the defense held) are returned in `verdicts` but never filed. Findings are deduped by
 * (category, chatUrl), keeping the HIGHEST-confidence probe per category: a later confirmed upgrades an
 * earlier suspected in place (reusing the finding id), never a downgrade. When an EvidenceStore is provided,
 * the control + positive turns are recorded as CHAT HTTP evidence and cited on the finding.
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
    const evidenceIds = opts.evidence
      ? recordTurns(opts.evidence, opts.screenId ?? "assistant", opts.chatUrl, verdict)
      : [];
    const f = buildFinding(id, probe, verdict, opts.chatUrl, evidenceIds);
    opts.store.upsertFinding(opts.assessmentId, f); // ON CONFLICT updates in place → safe suspected→confirmed upgrade
    byKey.set(key, f);
  }
  return { findings: [...byKey.values()], verdicts };
}
