// exposed_file — 機微ファイルの公開露出(.git/config 等)。origin 直下のパスをプローブ。

import type { HttpRequest, HttpResponse } from "../http.js";
import type { Probe, ProbeEval, Validator } from "../validator.js";

const MIN_BYTES = 8;

interface Signature {
  id: string;
  path: string;
  test: (body: string) => boolean;
}

const SIGNATURES: Signature[] = [
  { id: "git-config", path: "/.git/config", test: (b) => /\[core\]|repositoryformatversion/i.test(b) },
  { id: "git-head", path: "/.git/HEAD", test: (b) => /^ref:\s/m.test(b) },
  { id: "dotenv", path: "/.env", test: (b) => /^\s*[A-Z][A-Z0-9_]*\s*=/m.test(b) },
];

function get(url: string): HttpRequest {
  return { method: "GET", url };
}

export const exposedFile: Validator = {
  name: "exposed_file",
  severity: "high",
  applicable: () => true,
  probes(target): Probe[] {
    return SIGNATURES.map((s) => ({ id: s.id, request: get(new URL(s.path, target.origin).toString()) }));
  },
  negativeControl(target): HttpRequest {
    return get(new URL(`/veritas-nonexistent-${Math.random().toString(36).slice(2, 10)}`, target.origin).toString());
  },
  evaluate(res: HttpResponse, _target, probe): ProbeEval {
    const sig = SIGNATURES.find((s) => s.id === probe.id);
    if (!sig) return { positive: false, reason: "unknown probe" };
    if (res.status !== 200) return { positive: false, reason: `status ${res.status}` };
    if (res.body.trim().length < MIN_BYTES) return { positive: false, reason: "empty/short 200 (0-byte guard)" };
    if (!sig.test(res.body)) return { positive: false, reason: "signature mismatch" };
    return { positive: true, reason: `200 with ${sig.id} signature (${res.body.length}B)` };
  },
  title(_target, probe): string {
    return `Exposed sensitive file: ${SIGNATURES.find((s) => s.id === probe.id)?.path ?? probe.id}`;
  },
  describe(target, probe): string {
    return `${SIGNATURES.find((s) => s.id === probe.id)?.path ?? probe.id} is publicly readable at ${target.origin}`;
  },
};
