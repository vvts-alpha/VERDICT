// DESIGN §7.4/§7.5 — Hypothesis verification. IDOR reuses the scanner's evidence-discipline runner (neg control + 2 positive replays).
// IDOR: a neighbouring id returns substantive data and an invalid id 404s (not a catch-all) → confirms an object-level authorization-missing candidate.

import type { Hypothesis, Screen } from "@veritas/core";
import type { EvidenceStore, HttpClient, HttpResponse, Probe, ProbeEval, ScanTarget, Validator } from "@veritas/scanner";
import { makeTarget, runValidator, impactOracle } from "@veritas/scanner";

const MIN_BYTES = 16;

export interface VerifyOutcome {
  status: "confirmed" | "refuted" | "blocked";
  reason: string;
  evidenceIds: string[];
}

function fillUrl(origin: string, urlTemplate: string, screen: Screen, overrideName: string, overrideValue: string): string | null {
  let path = urlTemplate;
  for (const placeholder of urlTemplate.match(/\{[^}]+\}/g) ?? []) {
    const name = placeholder.slice(1, -1);
    const value = name === overrideName ? overrideValue : screen.params.find((p) => p.name === name)?.example;
    if (value == null) return null;
    path = path.replace(placeholder, encodeURIComponent(value));
  }
  try {
    return new URL(path, origin).toString();
  } catch {
    return null;
  }
}

/** Advance an id by one (numeric, or prefix+digits). Returns null if not possible. */
function incrementId(id: string): string | null {
  if (/^\d+$/.test(id)) return String(Number(id) + 1);
  const m = id.match(/^(.*?)(\d+)$/);
  if (m) return `${m[1]}${Number(m[2]) + 1}`;
  return null;
}

/** Construct an id that almost certainly doesn't exist (a large offset onto numeric / prefix+digits). */
function invalidId(id: string): string {
  if (/^\d+$/.test(id)) return String(Number(id) + 999_999_983);
  const m = id.match(/^(.*?)(\d+)$/);
  if (m) return `${m[1]}${Number(m[2]) + 999_983}`;
  return `${id}zzq000`;
}

interface IdorTarget {
  kind: "page" | "api";
  urlTemplate: string;
  paramName: string;
  exampleId: string;
}

/** Enumerate IDOR candidate targets: object_ref path params on post-login pages + authenticated GET APIs. */
function idorTargets(screen: Screen): IdorTarget[] {
  const targets: IdorTarget[] = [];
  // Page: post-login (= possibly a private object) with an object_ref/id path param
  if (screen.authState === "post-login") {
    for (const placeholder of screen.urlTemplate.match(/\{[^}]+\}/g) ?? []) {
      const name = placeholder.slice(1, -1);
      const param = screen.params.find((p) => p.name === name && p.in === "path");
      if (param?.example && (param.guessedType === "object_ref" || param.guessedType === "id")) {
        targets.push({ kind: "page", urlTemplate: screen.urlTemplate, paramName: name, exampleId: param.example });
      }
    }
  }
  // API: GET with an id (a candidate if enumerable, regardless of whether auth was observed)
  for (const api of screen.apis) {
    if (api.method.toUpperCase() !== "GET") continue;
    for (const placeholder of api.urlTemplate.match(/\{[^}]+\}/g) ?? []) {
      const name = placeholder.slice(1, -1);
      const param = screen.params.find((p) => p.name === name && p.example);
      if (param) targets.push({ kind: "api", urlTemplate: api.urlTemplate, paramName: name, exampleId: param.example });
    }
  }
  return targets;
}

function makeIdorValidator(screen: Screen, origin: string, t: IdorTarget): Validator | null {
  const other = incrementId(t.exampleId);
  if (!other) return null;
  const otherUrl = fillUrl(origin, t.urlTemplate, screen, t.paramName, other);
  const invalidUrl = fillUrl(origin, t.urlTemplate, screen, t.paramName, invalidId(t.exampleId));
  if (!otherUrl || !invalidUrl) return null;
  return {
    name: "idor",
    severity: "high",
    applicable: () => true,
    probes: (): Probe[] => [{ id: `${t.kind}:${t.urlTemplate}#${t.paramName}`, request: { method: "GET", url: otherUrl } }],
    negativeControl: () => ({ method: "GET", url: invalidUrl }),
    evaluate: (res: HttpResponse): ProbeEval => {
      if (res.status !== 200) return { positive: false, reason: `status ${res.status}` };
      if (res.body.trim().length < MIN_BYTES) return { positive: false, reason: "empty 200 (0-byte guard)" };
      // Require a CROSS-USER signal — the neighbour object distinctly carries the OTHER id's data and not our own — not
      // merely a 200. "neighbour id returns 200" only proves the id space is enumerable (or the endpoint is public); it
      // does NOT prove object-level authorization is missing. This is the deterministic analogue of probe_idor's oracle,
      // and it stops the false HIGH IDOR on public catalogs / self-owned objects.
      const cross = impactOracle(res.body, { requestedIdentity: other, sessionIdentity: t.exampleId }).some((i) => i.kind === "cross-user");
      if (!cross) return { positive: false, reason: `neighbour ${t.kind} id ${other} returned 200 but carries no cross-user data (enumerable, not a proven object-level-auth failure)` };
      return { positive: true, reason: `neighbouring ${t.kind} id ${other} returned its own object (cross-user data present, not ${t.exampleId}'s)` };
    },
    title: () => `IDOR: ${t.kind} cross-user object access on ${t.urlTemplate} (${t.paramName})`,
    describe: () =>
      `A neighbouring ${t.paramName} on ${t.kind} ${t.urlTemplate} returns ANOTHER id's object (cross-user data present, not the session's own) while an invalid id is denied — object-level authorization is missing`,
  };
}

async function verifyIdor(
  screen: Screen,
  http: HttpClient,
  evidence: EvidenceStore,
  seen: Set<string>,
): Promise<VerifyOutcome> {
  const target: ScanTarget | null = makeTarget(screen);
  if (!target) return { status: "blocked", reason: "no concrete observed URL to probe", evidenceIds: [] };
  const validators = idorTargets(screen)
    .map((t) => makeIdorValidator(screen, target.origin, t))
    .filter((v): v is Validator => v !== null);
  if (validators.length === 0) {
    return { status: "blocked", reason: "no enumerable object_ref id (post-login page or API id required)", evidenceIds: [] };
  }
  let lastReason = "no IDOR signal";
  for (const validator of validators) {
    const outcomes = await runValidator(validator, target, http, evidence, seen);
    const confirmed = outcomes.find((o) => o.status === "confirmed");
    if (confirmed) return { status: "confirmed", reason: confirmed.reason, evidenceIds: confirmed.evidenceIds };
    lastReason = outcomes.find((o) => o.status === "refuted")?.reason ?? outcomes[0]?.reason ?? lastReason;
  }
  return { status: "refuted", reason: lastReason, evidenceIds: [] };
}

/** Dispatch to a verifier based on the hypothesis class. Unsupported classes are blocked (future / manual). */
export async function verifyHypothesis(
  hypothesis: Hypothesis,
  screen: Screen,
  http: HttpClient,
  evidence: EvidenceStore,
  seen: Set<string>,
): Promise<VerifyOutcome> {
  switch (hypothesis.class) {
    case "idor":
      return verifyIdor(screen, http, evidence, seen);
    default:
      return {
        status: "blocked",
        reason: `no automated verifier for class '${hypothesis.class}' yet (needs operator / future milestone)`,
        evidenceIds: [],
      };
  }
}
