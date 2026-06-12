// DESIGN §7.4/§7.5 — 仮説の検証。IDOR は scanner の証拠規律ランナー(neg control + 2 positive replays)を再利用。
// IDOR: 隣接 id が実体を返し、無効 id は 404(catch-all でない)→ オブジェクトレベル認可欠如の候補を confirmed。

import type { Hypothesis, Screen } from "@veritas/core";
import type { EvidenceStore, HttpClient, HttpResponse, Probe, ProbeEval, ScanTarget, Validator } from "@veritas/scanner";
import { makeTarget, runValidator } from "@veritas/scanner";

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

/** id を 1 つ進める(数値 or 接頭辞+数字)。できなければ null。 */
function incrementId(id: string): string | null {
  if (/^\d+$/.test(id)) return String(Number(id) + 1);
  const m = id.match(/^(.*?)(\d+)$/);
  if (m) return `${m[1]}${Number(m[2]) + 1}`;
  return null;
}

/** まず存在しない id を作る(数値/接頭辞+数字に大きな値)。 */
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

/** IDOR を試す対象を列挙: post-login ページの object_ref path param + 認証付き GET API。 */
function idorTargets(screen: Screen): IdorTarget[] {
  const targets: IdorTarget[] = [];
  // ページ: 認証後(=私的オブジェクトの可能性)で object_ref/id の path param を持つ
  if (screen.authState === "post-login") {
    for (const placeholder of screen.urlTemplate.match(/\{[^}]+\}/g) ?? []) {
      const name = placeholder.slice(1, -1);
      const param = screen.params.find((p) => p.name === name && p.in === "path");
      if (param?.example && (param.guessedType === "object_ref" || param.guessedType === "id")) {
        targets.push({ kind: "page", urlTemplate: screen.urlTemplate, paramName: name, exampleId: param.example });
      }
    }
  }
  // API: GET で id を持つ(認証観測の有無に関わらず enumerable なら候補)
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
      return { positive: true, reason: `neighbouring ${t.kind} id returned 200 with ${res.body.length}B` };
    },
    title: () => `IDOR candidate: ${t.kind} object enumeration on ${t.urlTemplate} (${t.paramName})`,
    describe: () =>
      `A neighbouring ${t.paramName} on ${t.kind} ${t.urlTemplate} returns substantive data while an invalid id does not — object-level authorization may be missing`,
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

/** 仮説クラスに応じて検証器をディスパッチ。未対応クラスは blocked(将来 / 人手)。 */
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
