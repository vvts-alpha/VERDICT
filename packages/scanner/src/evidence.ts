// DESIGN §4.3 — EvidenceStore. Saves each req/resp pair under artifacts/<screen_id>/<evidence_id>/.
// Auth headers (Authorization/Cookie etc.) are saved with their values masked (§6.2 principle).

import { mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import type { HttpRequest, HttpResponse } from "./http.js";

export interface EvidenceArtifact {
  /** The whole raw HTTP request (sensitive headers already redacted). */
  request: string | null;
  /** The whole raw HTTP response (headers + body, already redacted; truncated at maxResponseBytes). */
  response: string | null;
  /** Whether the response was truncated for exceeding maxResponseBytes. */
  truncated: boolean;
}

/**
 * Search artifacts/<screenId>/<evidenceId>/ and read the raw HTTP request/response (for embedding in the report).
 * evidenceId is unique, so we search across screens. Returns null if not found.
 */
export function readEvidenceArtifact(artifactsDir: string, evidenceId: string, maxResponseBytes = 16384): EvidenceArtifact | null {
  if (!existsSync(artifactsDir)) return null;
  let dir: string | null = null;
  for (const ent of readdirSync(artifactsDir, { withFileTypes: true })) {
    if (!ent.isDirectory()) continue;
    const cand = join(artifactsDir, ent.name, evidenceId);
    if (existsSync(cand) && statSync(cand).isDirectory()) {
      dir = cand;
      break;
    }
  }
  if (!dir) return null;
  const read = (f: string): string | null => {
    try {
      return readFileSync(join(dir as string, f), "utf8");
    } catch {
      return null;
    }
  };
  const request = read("request.http.txt");
  let response = read("response.http.txt");
  let truncated = false;
  if (response && response.length > maxResponseBytes) {
    response = response.slice(0, maxResponseBytes);
    truncated = true;
  }
  return { request, response, truncated };
}

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

/** {method,url,headers,body} → raw HTTP request (the whole request; reproducible / copy-pasteable). */
function rawHttpRequest(req: { method: string; url: string; headers?: Record<string, string>; body?: string | null }): string {
  let host = "";
  let target = req.url;
  try {
    const u = new URL(req.url);
    host = u.host;
    target = `${u.pathname}${u.search}` || "/";
  } catch {
    /* leave relative/malformed URLs as-is */
  }
  const lines = [`${req.method} ${target} HTTP/1.1`];
  if (host) lines.push(`Host: ${host}`);
  for (const [k, v] of Object.entries(req.headers ?? {})) lines.push(`${k}: ${v}`);
  return `${lines.join("\n")}\n\n${req.body ?? ""}`;
}

/** status+headers+body → raw HTTP response. */
function rawHttpResponse(res: { status: number; headers?: Record<string, string>; body: string }): string {
  const lines = [`HTTP/1.1 ${res.status}`];
  for (const [k, v] of Object.entries(res.headers ?? {})) lines.push(`${k}: ${v}`);
  return `${lines.join("\n")}\n\n${res.body ?? ""}`;
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
    // Also save the whole request / whole response as raw HTTP (headers masked; for reproduction / copy-paste).
    writeFileSync(join(dir, "request.http.txt"), rawHttpRequest(safeRequest));
    writeFileSync(join(dir, "response.http.txt"), rawHttpResponse({ status: safeResponse.status, headers: safeResponse.headers, body: input.response.body }));
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
