// cors_misconfig — whether an arbitrary Origin is reflected into Access-Control-Allow-Origin.
// negative control = the same request without an Origin (it should not be reflected). Static `*`+credentials is also excluded as catch-all.

import type { HttpRequest, HttpResponse } from "../http.js";
import { concretizeApiUrl, type Probe, type ProbeEval, type ScanTarget, type Validator } from "../validator.js";

const EVIL_ORIGIN = "https://veritas-evil.example";

function firstGetApiUrl(target: ScanTarget): string | null {
  const api = target.screen.apis.find((a) => a.method.toUpperCase() === "GET");
  return api ? concretizeApiUrl(target.origin, api.urlTemplate, target.screen) : null;
}

export const corsMisconfig: Validator = {
  name: "cors_misconfig",
  severity: "medium",
  applicable(target): boolean {
    return target.screen.apis.some((a) => a.method.toUpperCase() === "GET");
  },
  probes(target): Probe[] {
    const probes: Probe[] = [];
    for (const api of target.screen.apis) {
      if (api.method.toUpperCase() !== "GET") continue;
      const url = concretizeApiUrl(target.origin, api.urlTemplate, target.screen);
      if (!url) continue;
      probes.push({ id: `${api.method} ${api.urlTemplate}`, request: { method: "GET", url, headers: { origin: EVIL_ORIGIN } } });
    }
    return probes;
  },
  negativeControl(target): HttpRequest {
    return { method: "GET", url: firstGetApiUrl(target) ?? target.baseUrl };
  },
  evaluate(res: HttpResponse): ProbeEval {
    const acao = res.headers["access-control-allow-origin"];
    const acac = res.headers["access-control-allow-credentials"];
    if (acao === EVIL_ORIGIN) {
      return { positive: true, reason: `ACAO reflects arbitrary origin${acac === "true" ? " with credentials" : ""}` };
    }
    if (acao === "*" && acac === "true") {
      return { positive: true, reason: "ACAO '*' with credentials" };
    }
    return { positive: false, reason: `ACAO=${acao ?? "none"}` };
  },
  title(_target, probe): string {
    return `CORS misconfiguration on ${probe.id}`;
  },
  describe(_target, probe): string {
    return `${probe.id} reflects an arbitrary Origin in Access-Control-Allow-Origin`;
  },
};
