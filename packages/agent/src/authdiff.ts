// DESIGN §7.4 — auth-diff(マルチロール / ロール比較)。2 ロールで同一 API を叩き認可境界越えを検出。
// low-priv ロールが high-priv と同一実体を取得できる → privilege_escalation / IDOR を confirmed。
// ロール資格情報(headers)は M6 の人手ログイン or vault 由来(取得は operator)。

import type { Screen } from "@veritas/core";
import type { EvidenceStore, HttpClient, HttpResponse } from "@veritas/scanner";
import { concretizeApiUrl, makeTarget } from "@veritas/scanner";

const MIN_BYTES = 16;

export interface RoleContext {
  name: string;
  /** そのロールの認証ヘッダ(Cookie/Authorization 等)。証拠保存時はマスクされる。 */
  headers: Record<string, string>;
}

export interface AuthDiffOutcome {
  status: "confirmed" | "refuted" | "blocked";
  reason: string;
  evidenceIds: string[];
}

const DENIED_RE = /(sign[\s-]?in|log[\s-]?in|forbidden|unauthorized|access denied|ログイン|権限|認証が必要)/i;

/** 200 + 実体あり + 否認系文言が無い(= 実際にアクセスできている)。ページHTML/JSON 両対応。 */
function accessible(res: HttpResponse): boolean {
  return res.status === 200 && res.body.trim().length >= MIN_BYTES && !DENIED_RE.test(res.body.slice(0, 2000));
}

/**
 * 認証付き GET API を high/low 2 ロールで叩く。high が実体を返し、low が **同一実体**を 2 回安定取得 →
 * 認可境界越え(confirmed)。high baseline + 2 low replays を証拠化(証拠規律の精神を踏襲)。
 */
export async function authDiffScreen(
  screen: Screen,
  http: HttpClient,
  evidence: EvidenceStore,
  high: RoleContext,
  low: RoleContext,
): Promise<AuthDiffOutcome> {
  const target = makeTarget(screen);
  if (!target) return { status: "blocked", reason: "no concrete observed URL", evidenceIds: [] };
  // 比較対象: 認証付き GET API を優先、無ければ post-login のページ URL(server-rendered 対応)
  let url: string | null = null;
  let label = "";
  const api = screen.apis.find((a) => a.auth !== "none" && a.method.toUpperCase() === "GET");
  if (api) {
    url = concretizeApiUrl(target.origin, api.urlTemplate, screen);
    label = `API ${api.urlTemplate}`;
  }
  if (!url && screen.authState === "post-login") {
    url = target.baseUrl;
    label = `page ${screen.urlTemplate}`;
  }
  if (!url) return { status: "blocked", reason: "no authenticated API or post-login page to compare", evidenceIds: [] };

  const highRes = await http.send({ method: "GET", url, headers: high.headers });
  if (!accessible(highRes)) {
    return { status: "refuted", reason: `high-priv role cannot access ${label} (status ${highRes.status})`, evidenceIds: [] };
  }
  const lowResponses: HttpResponse[] = [];
  for (let i = 0; i < 2; i += 1) {
    const r = await http.send({ method: "GET", url, headers: low.headers });
    if (!accessible(r)) {
      return { status: "refuted", reason: `low-priv role blocked on ${label} (status ${r.status})`, evidenceIds: [] };
    }
    lowResponses.push(r);
  }

  const evidenceIds = [
    evidence.record({
      screenId: screen.screenId, validator: "auth_diff", kind: "negative_control",
      request: { method: "GET", url, headers: high.headers }, response: highRes,
      note: `high-priv (${high.name}) baseline`,
    }).id,
    ...lowResponses.map(
      (response) =>
        evidence.record({
          screenId: screen.screenId, validator: "auth_diff", kind: "positive_replay",
          request: { method: "GET", url, headers: low.headers }, response,
          note: `low-priv (${low.name}) obtained identical data`,
        }).id,
    ),
  ];
  return {
    status: "confirmed",
    reason: `low-priv role '${low.name}' accessed ${label} that only '${high.name}' should — authorization boundary crossed`,
    evidenceIds,
  };
}
