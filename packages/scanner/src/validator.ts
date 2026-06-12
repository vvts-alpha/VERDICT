// DESIGN §7.3 / §7.5 / §4.3 — validator 抽象 と 証拠規律ランナー。
// confirmed には negative control(正常応答)+ 2 positive replays を必須(ValidatorBase 相当の不変条件)。

import type { Screen, Severity } from "@veritas/core";
import type { HttpClient, HttpRequest, HttpResponse } from "./http.js";
import type { EvidenceStore } from "./evidence.js";

export interface ScanTarget {
  screen: Screen;
  /** 具体的な観測 URL(プローブの基点) */
  baseUrl: string;
  /** scheme://host */
  origin: string;
}

/** observedUrls[0] から具体ターゲットを作る。観測 URL が無ければ null(プローブ不能)。 */
export function makeTarget(screen: Screen): ScanTarget | null {
  const base = screen.observedUrls[0];
  if (!base) return null;
  try {
    return { screen, baseUrl: base, origin: new URL(base).origin };
  } catch {
    return null;
  }
}

/** api urlTemplate の {name} を screen.params の example で埋めて具体 URL に。埋まらなければ null。 */
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
}

export interface Validator {
  name: string;
  severity: Severity;
  applicable(target: ScanTarget): boolean;
  /** 1 つ以上の陽性プローブ */
  probes(target: ScanTarget): Probe[];
  /** 共有の negative control(catch-all / 0-byte 200 ガード) */
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
  /** 陽性を要求する回数(既定 2 = 「2 positive replays」) */
  positiveReplays?: number;
}

/**
 * 1 validator の全プローブを証拠規律で評価する。
 *  1. 陽性プローブ → 陰性なら no signal
 *  2. negative control も陽性 → catch-all とみなし refuted(0-byte/catch-all ガード)
 *  3. 陽性を計 N 回(既定 2)再現 → いずれか崩れたら refuted
 *  4. すべて満たせば confirmed。negative control + N 陽性を EvidenceStore に記録
 * seen は同一プローブ URL の重複実行をアセスメント内で防ぐ。
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

  const finish = (probe: Probe, status: ProbeStatus, reason: string, evidenceIds: string[]): ProbeOutcome => ({
    validator: v.name,
    probeId: probe.id,
    status,
    reason,
    evidenceIds,
    title: v.title(target, probe),
    description: v.describe(target, probe),
    severity: v.severity,
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
    outcomes.push(finish(probe, "confirmed", firstEval.reason, evidenceIds));
  }

  return outcomes;
}
