// DESIGN §7.4 — auth-diff (multi-role / role comparison). Hit the same API with 2 roles to detect an authorization-boundary crossing.
// A low-priv role can fetch the same entity as high-priv → confirms privilege_escalation / IDOR.
// Role credentials (headers) come from M6 manual login or a vault (obtained by the operator).

import type { Screen } from "@veritas/core";
import type { EvidenceStore, HttpClient, HttpResponse } from "@veritas/scanner";
import { concretizeApiUrl, makeTarget } from "@veritas/scanner";

const MIN_BYTES = 16;

export interface RoleContext {
  name: string;
  /** That role's auth headers (Cookie/Authorization, etc.). Masked when recorded as evidence. */
  headers: Record<string, string>;
}

export interface AuthDiffOutcome {
  status: "confirmed" | "refuted" | "blocked";
  reason: string;
  evidenceIds: string[];
}

const DENIED_RE = /(sign[\s-]?in|log[\s-]?in|forbidden|unauthorized|access denied|ログイン|権限|認証が必要)/i;

/** 200 + substantive body + no denial wording (= actually accessible). Handles both page HTML and JSON. */
function accessible(res: HttpResponse): boolean {
  return res.status === 200 && res.body.trim().length >= MIN_BYTES && !DENIED_RE.test(res.body.slice(0, 2000));
}

/**
 * Hit an authenticated GET API with 2 roles (high/low). If high returns the entity and low stably fetches the **same entity** twice →
 * an authorization-boundary crossing (confirmed). Records high baseline + 2 low replays as evidence (following the spirit of evidence discipline).
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
  // Comparison target: prefer an authenticated GET API; otherwise the post-login page URL (handles server-rendered)
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
