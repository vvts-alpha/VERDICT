// DESIGN §7.3 / §7.6 — run the catalog per screen, turn confirmed outcomes into Findings, and aggregate them into the store.
// Only confirmed outcomes become Findings (they passed evidence discipline). The coverage-ledger status is also updated to finding/clean.

import type { AssessmentStore, Finding, Screen } from "@veritas/core";
import type { HttpClient } from "./http.js";
import type { EvidenceStore } from "./evidence.js";
import { CATALOG } from "./catalog.js";
import { makeTarget, runValidator, type ProbeOutcome } from "./validator.js";

export interface ScanScreenResult {
  screenId: string;
  outcomes: ProbeOutcome[];
  findings: Finding[];
}

function buildFinding(screen: Screen, o: ProbeOutcome): Finding {
  return {
    id: `vf-${screen.screenId}-${o.validator}-${o.probeId}`.replace(/[^a-zA-Z0-9_-]/g, "_"),
    screenId: screen.screenId,
    title: o.title,
    severity: o.severity,
    source: { kind: "validator", validatorName: o.validator },
    description: `${o.description} — ${o.reason}`,
    reproSteps: `validator '${o.validator}' probe '${o.probeId}': negative control + ${o.evidenceIds.length - 1} positive replays (evidence: ${o.evidenceIds.join(", ")})`,
    evidenceIds: o.evidenceIds,
    scopeBasis: "same origin as a crawled in-scope screen",
  };
}

export async function scanScreen(
  screen: Screen,
  http: HttpClient,
  evidence: EvidenceStore,
  seen: Set<string>,
): Promise<ScanScreenResult> {
  const target = makeTarget(screen);
  if (!target) return { screenId: screen.screenId, outcomes: [], findings: [] };
  const outcomes: ProbeOutcome[] = [];
  for (const validator of CATALOG) {
    if (!validator.applicable(target)) continue;
    outcomes.push(...(await runValidator(validator, target, http, evidence, seen)));
  }
  const findings = outcomes.filter((o) => o.status === "confirmed").map((o) => buildFinding(screen, o));
  return { screenId: screen.screenId, outcomes, findings };
}

export interface ScanInventoryHooks {
  store?: AssessmentStore;
  assessmentId?: string;
  onScreen?: (result: ScanScreenResult) => void;
}

export interface ScanInventoryResult {
  results: ScanScreenResult[];
  confirmed: number;
}

export async function scanInventory(
  screens: Screen[],
  http: HttpClient,
  evidence: EvidenceStore,
  hooks: ScanInventoryHooks = {},
): Promise<ScanInventoryResult> {
  if (hooks.store && hooks.assessmentId) hooks.store.setPhase(hooks.assessmentId, "phase2_scan");
  const seen = new Set<string>();
  const results: ScanScreenResult[] = [];
  let confirmed = 0;

  for (const screen of screens) {
    if (hooks.store && hooks.assessmentId) {
      hooks.store.setScreenScanStatus(hooks.assessmentId, screen.screenId, "scanning");
    }
    const result = await scanScreen(screen, http, evidence, seen);
    results.push(result);
    confirmed += result.findings.length;

    if (hooks.store && hooks.assessmentId) {
      for (const finding of result.findings) hooks.store.upsertFinding(hooks.assessmentId, finding);
      hooks.store.setScreenScanStatus(
        hooks.assessmentId,
        screen.screenId,
        result.findings.length > 0 ? "finding" : "clean",
        { findingIds: result.findings.map((f) => f.id) },
      );
    }
    hooks.onScreen?.(result);
  }

  return { results, confirmed };
}
