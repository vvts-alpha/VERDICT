// DESIGN §7.2 — 画面別ビジネスロジック評価(フレッシュコンテキスト)。
// 1 画面: 仮説生成(LLM) → 各仮説を検証(証拠規律) → store に Hypothesis/Finding を集約。

import type { AssessmentStore, Finding, Hypothesis, Screen } from "@veritas/core";
import { prioritizeScreens } from "@veritas/core";
import type { LlmClient } from "@veritas/llm";
import type { EvidenceStore, HttpClient } from "@veritas/scanner";
import { generateHypotheses, type HypothesizeOptions } from "./hypothesize.js";
import { verifyHypothesis, type VerifyOutcome } from "./verify.js";

export interface AssessScreenHooks {
  store?: AssessmentStore;
  assessmentId?: string;
  onHypothesis?: (hypothesis: Hypothesis, outcome: VerifyOutcome) => void;
}

export interface LogicResult {
  screenId: string;
  hypotheses: Hypothesis[];
  findings: Finding[];
  usedFallback: boolean;
}

function buildHypothesisFinding(screen: Screen, h: Hypothesis, outcome: VerifyOutcome): Finding {
  return {
    id: `hf-${h.id}`,
    screenId: screen.screenId,
    title: `[${h.class}] ${h.statement}`,
    severity: h.class === "idor" || h.class === "privilege_escalation" || h.class === "auth_bypass" ? "high" : "medium",
    source: { kind: "hypothesis", hypothesisId: h.id },
    description: `${h.statement} — ${outcome.reason}`,
    reproSteps: `${h.testPlan} (evidence: ${outcome.evidenceIds.join(", ")})`,
    evidenceIds: outcome.evidenceIds,
    scopeBasis: "same origin as a crawled in-scope screen",
  };
}

/** 1 画面のビジネスロジック評価。store 連携時は仮説の status 遷移と confirmed の Finding を記録。 */
export async function assessScreenLogic(
  screen: Screen,
  llm: LlmClient | null,
  http: HttpClient,
  evidence: EvidenceStore,
  hooks: AssessScreenHooks = {},
  opts: HypothesizeOptions = {},
): Promise<LogicResult> {
  const { store, assessmentId } = hooks;
  const seen = new Set<string>();
  const { hypotheses, usedFallback } = await generateHypotheses(screen, llm, opts);
  const findings: Finding[] = [];

  for (const h of hypotheses) {
    if (store && assessmentId) store.upsertHypothesis(assessmentId, { ...h, status: "testing" });
    const outcome = await verifyHypothesis(h, screen, http, evidence, seen);
    h.status = outcome.status;
    h.evidenceIds = outcome.evidenceIds;
    if (store && assessmentId) store.upsertHypothesis(assessmentId, h);

    if (outcome.status === "confirmed") {
      const finding = buildHypothesisFinding(screen, h, outcome);
      findings.push(finding);
      if (store && assessmentId) store.upsertFinding(assessmentId, finding);
    }
    hooks.onHypothesis?.(h, outcome);
  }

  if (store && assessmentId && (findings.length > 0 || hypotheses.length > 0)) {
    const current = store.loadAssessment(assessmentId)?.screenScans.find((s) => s.screenId === screen.screenId);
    // findings があれば finding、無ければ既存 status を尊重(generic scan の結果を上書きしない)
    if (findings.length > 0) {
      store.setScreenScanStatus(assessmentId, screen.screenId, "finding", {
        findingIds: findings.map((f) => f.id),
        hypothesisIds: hypotheses.map((h) => h.id),
      });
    } else if (current && current.status === "queued") {
      store.setScreenScanStatus(assessmentId, screen.screenId, "clean", {
        hypothesisIds: hypotheses.map((h) => h.id),
      });
    }
  }

  return { screenId: screen.screenId, hypotheses, findings, usedFallback };
}

export interface LogicInventoryResult {
  results: LogicResult[];
  hypotheses: number;
  confirmed: number;
}

/** object_ref/id param か idor-candidate ラベルを持つ画面にビジネスロジック評価を回す。 */
export async function assessLogicInventory(
  screens: Screen[],
  llm: LlmClient | null,
  http: HttpClient,
  evidence: EvidenceStore,
  hooks: AssessScreenHooks = {},
  opts: HypothesizeOptions & { maxScreens?: number } = {},
): Promise<LogicInventoryResult> {
  if (hooks.store && hooks.assessmentId) hooks.store.setPhase(hooks.assessmentId, "phase2_scan");
  const applicable = screens.filter(
    (s) =>
      s.labels.includes("idor-candidate") ||
      s.params.some((p) => p.guessedType === "object_ref" || p.guessedType === "id"),
  );
  // コスト抑制: 優先度上位 N 画面に限定して LLM 仮説生成を回す(§7.1)
  const maxScreens = opts.maxScreens ?? 25;
  const targets =
    applicable.length <= maxScreens
      ? applicable
      : prioritizeScreens({ screens: applicable, screenScans: [] }, { onlyScannable: false })
          .map((p) => applicable.find((s) => s.screenId === p.screenId))
          .filter((s): s is Screen => s !== undefined)
          .slice(0, maxScreens);
  const results: LogicResult[] = [];
  let hypothesisCount = 0;
  let confirmed = 0;
  for (const screen of targets) {
    const r = await assessScreenLogic(screen, llm, http, evidence, hooks, opts);
    results.push(r);
    hypothesisCount += r.hypotheses.length;
    confirmed += r.findings.length;
  }
  return { results, hypotheses: hypothesisCount, confirmed };
}
