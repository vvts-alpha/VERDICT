import type { EvidenceRecord } from "./evidence.js";

/** Validate the actual C0/P1/C1/P2/C2 experiment, never a claim embedded in an HTTP body. */
export function checkTimingEvidence(control: EvidenceRecord, positives: EvidenceRecord[], records: readonly EvidenceRecord[]): boolean {
  const proof = control.timingProof;
  if (!proof || ![3000, 5000].includes(proof.delayMs) || positives.length !== 2) return false;
  if (positives.some((p, i) => p.id !== proof.positiveIds[i])) return false;
  const byId = new Map(records.map((r) => [r.id, r]));
  const c0 = byId.get(proof.controlIds[0]);
  const c1 = byId.get(proof.controlIds[1]);
  if (!c0 || !c1) return false;
  const ordered = [c0, positives[0]!, c1, positives[1]!, control];
  if (new Set(ordered.map((r) => r.id)).size !== 5) return false;
  if (ordered.some((r, i) => r.kind !== (i % 2 ? "positive_replay" : "negative_control") ||
    r.screenId !== control.screenId || r.validator !== control.validator ||
    r.response.status < 200 || r.response.status >= 300 || r.response.truncated ||
    !Number.isFinite(r.response.durationMs) || r.response.durationMs < 0 ||
    (i > 0 && records.indexOf(r) <= records.indexOf(ordered[i - 1]!)))) return false;
  const requestKey = (r: EvidenceRecord): string => JSON.stringify([r.request.method, r.request.url, r.request.headers, r.request.body]);
  if (requestKey(c0) !== requestKey(c1) || requestKey(c0) !== requestKey(control) ||
    requestKey(positives[0]!) !== requestKey(positives[1]!) || requestKey(c0) === requestKey(positives[0]!)) return false;
  const cs = [c0, c1, control].map((r) => r.response.durationMs);
  const ps = positives.map((r) => r.response.durationMs);
  const jitter = Math.min(1000, proof.delayMs * 0.2);
  return Math.max(...cs) - Math.min(...cs) <= jitter && Math.max(...ps) - Math.min(...ps) <= jitter &&
    Math.min(...ps) - Math.max(...cs) >= proof.delayMs * 0.8 &&
    Math.max(...ps) - Math.min(...cs) <= proof.delayMs * 1.4;
}
