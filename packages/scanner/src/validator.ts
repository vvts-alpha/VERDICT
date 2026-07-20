// DESIGN §7.3 / §7.5 / §4.3 — the validator abstraction and the evidence-discipline runner.
// confirmed requires a negative control (normal response) + 2 positive replays (the ValidatorBase-equivalent invariant).

import type { Screen, Severity } from "@veritas/core";
import type { HttpClient, HttpRequest, HttpResponse } from "./http.js";
import type { EvidenceStore } from "./evidence.js";

export interface ScanTarget {
  screen: Screen;
  /** the concrete observed URL (probe base point) */
  baseUrl: string;
  /** scheme://host */
  origin: string;
}

/** Build a concrete target from observedUrls[0]. Returns null if there's no observed URL (nothing to probe). */
export function makeTarget(screen: Screen): ScanTarget | null {
  const base = screen.observedUrls[0];
  if (!base) return null;
  try {
    return { screen, baseUrl: base, origin: new URL(base).origin };
  } catch {
    return null;
  }
}

/** Fill {name} in the api urlTemplate with screen.params' example to form a concrete URL. Returns null if any can't be filled. */
export function concretizeApiUrl(origin: string, urlTemplate: string, screen: Screen): string | null {
  let path = urlTemplate;
  for (const placeholder of urlTemplate.match(/\{[^}]+\}/g) ?? []) {
    const name = placeholder.slice(1, -1);
    const param = screen.params.find((p) => p.name === name && p.example);
    if (!param) return null;
    path = path.replace(placeholder, encodeURIComponent(param.example));
  }
  try {
    return new URL(path, origin).toString();
  } catch {
    return null;
  }
}

export interface Probe {
  id: string;
  request: HttpRequest;
}

export interface ProbeEval {
  positive: boolean;
  reason: string;
  /** Optional per-outcome severity override (e.g. CORS is High WITH credentials, Low without) — falls back to Validator.severity. */
  severity?: Severity;
}

export interface Validator {
  name: string;
  severity: Severity;
  applicable(target: ScanTarget): boolean;
  /** one or more positive probes */
  probes(target: ScanTarget): Probe[];
  /** shared negative control (catch-all / 0-byte-200 guard) */
  negativeControl(target: ScanTarget): HttpRequest;
  evaluate(res: HttpResponse, target: ScanTarget, probe: Probe): ProbeEval;
  title(target: ScanTarget, probe: Probe): string;
  describe(target: ScanTarget, probe: Probe): string;
}

export type ProbeStatus = "negative" | "refuted" | "confirmed";

export interface ProbeOutcome {
  validator: string;
  probeId: string;
  status: ProbeStatus;
  reason: string;
  evidenceIds: string[];
  title: string;
  description: string;
  severity: Severity;
}

export interface RunOptions {
  /** how many positives are required (default 2 = "2 positive replays") */
  positiveReplays?: number;
}

/**
 * Evaluate all probes of one validator under evidence discipline.
 *  1. positive probe → if negative, no signal
 *  2. negative control also positive → treated as catch-all, refuted (0-byte/catch-all guard)
 *  3. reproduce the positive N times total (default 2) → if any breaks down, refuted
 *  4. if all hold, confirmed. Record the negative control + N positives in the EvidenceStore
 * seen prevents re-running the same probe URL within an assessment.
 */
export async function runValidator(
  v: Validator,
  target: ScanTarget,
  http: HttpClient,
  evidence: EvidenceStore,
  seen: Set<string>,
  opts: RunOptions = {},
): Promise<ProbeOutcome[]> {
  const replays = Math.max(1, opts.positiveReplays ?? 2);
  const negRequest = v.negativeControl(target);
  let negResponse: HttpResponse | null = null;
  const outcomes: ProbeOutcome[] = [];

  const finish = (probe: Probe, status: ProbeStatus, reason: string, evidenceIds: string[], severity?: Severity): ProbeOutcome => ({
    validator: v.name,
    probeId: probe.id,
    status,
    reason,
    evidenceIds,
    title: v.title(target, probe),
    description: v.describe(target, probe),
    severity: severity ?? v.severity, // per-outcome override (ProbeEval.severity) wins over the validator default
  });

  for (const probe of v.probes(target)) {
    const key = `${v.name} ${probe.request.method} ${probe.request.url}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const positives: HttpResponse[] = [];
    const first = await http.send(probe.request);
    const firstEval = v.evaluate(first, target, probe);
    if (!firstEval.positive) {
      outcomes.push(finish(probe, "negative", firstEval.reason, []));
      continue;
    }
    positives.push(first);

    if (!negResponse) negResponse = await http.send(negRequest);
    const negEval = v.evaluate(negResponse, target, probe);
    if (negEval.positive) {
      outcomes.push(finish(probe, "refuted", `negative control also positive (catch-all): ${negEval.reason}`, []));
      continue;
    }

    let stable = true;
    for (let i = 1; i < replays; i += 1) {
      const replay = await http.send(probe.request);
      if (!v.evaluate(replay, target, probe).positive) {
        stable = false;
        break;
      }
      positives.push(replay);
    }
    if (!stable) {
      outcomes.push(finish(probe, "refuted", "positive signal not stable across replays", []));
      continue;
    }

    const evidenceIds: string[] = [
      evidence.record({
        screenId: target.screen.screenId,
        validator: v.name,
        kind: "negative_control",
        request: negRequest,
        response: negResponse,
        note: negEval.reason,
      }).id,
    ];
    for (const response of positives) {
      evidenceIds.push(
        evidence.record({
          screenId: target.screen.screenId,
          validator: v.name,
          kind: "positive_replay",
          request: probe.request,
          response,
          note: firstEval.reason,
        }).id,
      );
    }
    outcomes.push(finish(probe, "confirmed", firstEval.reason, evidenceIds, firstEval.severity));
  }

  return outcomes;
}
