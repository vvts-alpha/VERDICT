// auth_required — クロールで認証付き(cookie/bearer)に観測された API が、未認証で実体を返すか。
// 0-byte 200 ガード(空 200 は到達とみなさない)= 過去の教訓を反映。

import type { HttpRequest, HttpResponse } from "../http.js";
import { concretizeApiUrl, type Probe, type ProbeEval, type Validator } from "../validator.js";

const MIN_BYTES = 16;

export const authRequired: Validator = {
  name: "auth_required",
  severity: "medium",
  applicable(target): boolean {
    return target.screen.apis.some((a) => a.auth !== "none");
  },
  probes(target): Probe[] {
    const probes: Probe[] = [];
    for (const api of target.screen.apis) {
      if (api.auth === "none") continue;
      if (api.method.toUpperCase() !== "GET") continue; // M4 は GET のみ(破壊的回避)
      const url = concretizeApiUrl(target.origin, api.urlTemplate, target.screen);
      if (!url) continue;
      probes.push({ id: `${api.method} ${api.urlTemplate}`, request: { method: "GET", url } }); // 認証ヘッダ無し
    }
    return probes;
  },
  negativeControl(target): HttpRequest {
    return {
      method: "GET",
      url: new URL(`/veritas-nonexistent-${Math.random().toString(36).slice(2, 10)}`, target.origin).toString(),
    };
  },
  evaluate(res: HttpResponse): ProbeEval {
    if (res.status !== 200) return { positive: false, reason: `status ${res.status} (auth enforced / redirect)` };
    if (res.body.trim().length < MIN_BYTES) return { positive: false, reason: "empty 200 (0-byte guard)" };
    return { positive: true, reason: `unauthenticated 200 with ${res.body.length}B body` };
  },
  title(_target, probe): string {
    return `Unauthenticated access to ${probe.id}`;
  },
  describe(_target, probe): string {
    return `${probe.id} returned substantive content without authentication (observed using auth during crawl)`;
  },
};
