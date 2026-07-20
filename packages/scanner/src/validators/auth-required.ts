// auth_required — whether an API observed using BEARER auth during the crawl returns real content when unauthenticated.
// 0-byte-200 guard (an empty 200 is not counted as reached) = reflects a past lesson.
//
// BEARER-ONLY by design: a Bearer token is set EXPLICITLY by the app's JS for calls that need it, so its absence being
// accepted is a real auth bypass. A COOKIE, by contrast, is auto-sent by the browser to EVERY same-origin request, so
// detectAuth (crawler/api.ts) labels every public GET as auth:"cookie" — probing those unauthenticated yields a 200 and
// a false "unauthenticated access" MEDIUM (this validator has no authed-vs-unauth comparison to tell public from bypassed).
// Cookie-based auth-bypass is instead covered by the pilot's verify_access, which compares the unauth and authed bodies.

import type { HttpRequest, HttpResponse } from "../http.js";
import { concretizeApiUrl, type Probe, type ProbeEval, type Validator } from "../validator.js";

const MIN_BYTES = 16;

export const authRequired: Validator = {
  name: "auth_required",
  severity: "medium",
  applicable(target): boolean {
    return target.screen.apis.some((a) => a.auth === "bearer");
  },
  probes(target): Probe[] {
    const probes: Probe[] = [];
    for (const api of target.screen.apis) {
      if (api.auth !== "bearer") continue; // cookie/none excluded (see file header) — Bearer is the only reliable auth signal
      if (api.method.toUpperCase() !== "GET") continue; // M4 is GET-only (avoid destructive requests)
      const url = concretizeApiUrl(target.origin, api.urlTemplate, target.screen);
      if (!url) continue;
      probes.push({ id: `${api.method} ${api.urlTemplate}`, request: { method: "GET", url, headers: { authorization: "" } } }); // explicitly no Bearer
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
    return `${probe.id} returned substantive content without a Bearer token (it used Bearer auth during the crawl) — the token is not enforced`;
  },
};
