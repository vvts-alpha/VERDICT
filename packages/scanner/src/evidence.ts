// DESIGN §4.3 — EvidenceStore。req/resp 対を artifacts/<screen_id>/<evidence_id>/ に保存。
// 認証ヘッダ(Authorization/Cookie 等)は値をマスクして保存(§6.2 の原則)。

import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { HttpRequest, HttpResponse } from "./http.js";

export type EvidenceKind = "negative_control" | "positive_replay";

export interface EvidenceInput {
  screenId: string;
  validator: string;
  kind: EvidenceKind;
  request: HttpRequest;
  response: HttpResponse;
  note: string;
}

export interface EvidenceRecord extends EvidenceInput {
  id: string;
  recordedAt: string;
}

const SENSITIVE = new Set(["authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"]);

function maskHeaders(headers: Record<string, string> = {}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    out[k] = SENSITIVE.has(k.toLowerCase()) ? "<redacted>" : v;
  }
  return out;
}

let seq = 0;
function nextEvidenceId(): string {
  seq += 1;
  return `ev-${Date.now().toString(36)}-${seq.toString(36)}`;
}

export class EvidenceStore {
  readonly records: EvidenceRecord[] = [];

  constructor(private readonly artifactsDir: string) {}

  record(input: EvidenceInput): EvidenceRecord {
    const id = nextEvidenceId();
    const rec: EvidenceRecord = { ...input, id, recordedAt: new Date().toISOString() };
    const dir = join(this.artifactsDir, input.screenId, id);
    mkdirSync(dir, { recursive: true });

    const safeRequest = { ...input.request, headers: maskHeaders(input.request.headers) };
    const safeResponse = {
      status: input.response.status,
      finalUrl: input.response.finalUrl,
      durationMs: input.response.durationMs,
      headers: maskHeaders(input.response.headers),
    };
    writeFileSync(join(dir, "request.json"), JSON.stringify(safeRequest, null, 2));
    writeFileSync(join(dir, "response.json"), JSON.stringify(safeResponse, null, 2));
    writeFileSync(join(dir, "response.body.txt"), input.response.body);
    writeFileSync(
      join(dir, "meta.json"),
      JSON.stringify(
        { id, screenId: input.screenId, validator: input.validator, kind: input.kind, note: input.note, recordedAt: rec.recordedAt },
        null,
        2,
      ),
    );

    this.records.push(rec);
    return rec;
  }
}
