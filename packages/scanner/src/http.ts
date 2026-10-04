// DESIGN §9 — policy-gated raw HTTP (for validation). The real impl is FetchHttpClient; tests use FakeHttpClient.

import { DEFAULT_BROWSER_UA } from "@veritas/core";

/** multipart/form-data upload spec. undici's FormData generates boundary + CRLF + Content-Type **correctly**
 *  (fixes the problem where an LLM hand-writing the raw wire drops CRLF/boundary and gets rejected by python-multipart etc.). Takes priority over body. */
export interface MultipartSpec {
  fields?: Record<string, string>;
  files: Array<{ name: string; filename: string; contentType?: string; base64: string }>;
}

export interface HttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | null;
  /** When set, body is ignored and the request is sent as multipart/form-data (for file-upload attacks = XXE-SVG / webshell / pickle). */
  multipart?: MultipartSpec;
  /** Bounded read override for asset analysis; ordinary probes use the client default. */
  maxBodyBytes?: number;
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  durationMs: number;
  /** The body is a prefix only. Never use its length/absence as complete-response evidence. */
  truncated?: boolean;
  bodyBytes?: number;
}

export interface HttpClient {
  send(req: HttpRequest): Promise<HttpResponse>;
}

export interface FetchHttpClientOptions {
  /** Scope gate (out-of-scope requests are refused) */
  allow?: (url: string) => boolean;
  timeoutMs?: number;
  maxBodyBytes?: number;
  /** Minimum interval between requests (conservative rate; WAF lesson) */
  minDelayMs?: number;
  userAgent?: string;
  /** Default headers added to every request (auth-session cookie, etc.). */
  headers?: Record<string, string>;
  /** Upstream HTTP proxy (e.g. Burp http://127.0.0.1:8080). Only when set are all requests routed through it.
   *  If unset, behaviour is unchanged (none of the proxy code runs = byte-identical). */
  proxy?: string;
  /** Called after scope/rate checks, immediately before each attempted network request. May refuse it. */
  beforeSend?: (req: HttpRequest) => void;
}

/** Merge header maps case-insensitively, last-wins by lowercased name (keeping the last casing seen for a name). A
 *  caller's "User-Agent" thus replaces a default "user-agent" instead of producing two keys undici comma-combines. */
export function foldHeaders(...maps: Array<Record<string, string> | undefined>): Record<string, string> {
  const byLc = new Map<string, { key: string; value: string }>();
  for (const m of maps) {
    if (!m) continue;
    for (const [k, v] of Object.entries(m)) byLc.set(k.toLowerCase(), { key: k, value: v });
  }
  const out: Record<string, string> = {};
  for (const { key, value } of byLc.values()) out[key] = value;
  return out;
}

export class FetchHttpClient implements HttpClient {
  private lastSentAt = 0;
  private dispatcher: unknown | null = null;
  private dispatcherInit = false;
  /** Live rate override (ms). When set, takes precedence over opts.minDelayMs — lets a running scan be re-throttled. */
  private rateOverrideMs?: number;

  constructor(private readonly opts: FetchHttpClientOptions = {}) {}

  /** Change the inter-request delay (rate) on a live client. Read per-send, so it applies to the next request. */
  setRate(minDelayMs: number): void {
    this.rateOverrideMs = Math.max(0, minDelayMs);
  }

  /** Lazily create an undici ProxyAgent only when a proxy is set (skip TLS verification for Burp's intercepting CA). Non-fatal on failure. */
  private async getDispatcher(): Promise<unknown | undefined> {
    if (!this.opts.proxy) return undefined;
    if (!this.dispatcherInit) {
      this.dispatcherInit = true;
      try {
        const { ProxyAgent } = await import("undici");
        this.dispatcher = new ProxyAgent({ uri: this.opts.proxy, requestTls: { rejectUnauthorized: false } });
      } catch {
        this.dispatcher = null;
      }
    }
    return this.dispatcher ?? undefined;
  }

  /** The headers actually sent (default user-agent + opts.headers + per-call). Used to record the "whole request" in evidence. */
  effectiveHeaders(reqHeaders?: Record<string, string>): Record<string, string> {
    return foldHeaders({ "user-agent": this.opts.userAgent ?? DEFAULT_BROWSER_UA }, this.opts.headers, reqHeaders);
  }

  async send(req: HttpRequest): Promise<HttpResponse> {
    if (this.opts.allow && !this.opts.allow(req.url)) {
      throw new Error(`out-of-scope request blocked: ${req.url}`);
    }
    const minDelay = this.rateOverrideMs ?? this.opts.minDelayMs ?? 0;
    if (minDelay > 0) {
      const wait = this.lastSentAt + minDelay - Date.now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }

    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs ?? 15_000);
    try {
      const dispatcher = await this.getDispatcher();
      // Fold case-insensitively so a caller's e.g. "User-Agent" REPLACES the default "user-agent" rather than colliding
      // into two keys that undici would comma-combine (which silently neutered header-injection probes + garbled evidence).
      const reqHeaders: Record<string, string> = foldHeaders({ "user-agent": this.opts.userAgent ?? DEFAULT_BROWSER_UA }, this.opts.headers, req.headers);
      let bodyInit: unknown = req.body ?? undefined;
      if (req.multipart) {
        // Generate correct multipart via undici's FormData (boundary/CRLF/Content-Type are automatic). Don't let the caller's
        // content-type override it (undici decides the boundary).
        const fd = new FormData();
        for (const [k, v] of Object.entries(req.multipart.fields ?? {})) fd.append(k, v);
        for (const f of req.multipart.files) {
          const bytes = Buffer.from(f.base64, "base64");
          fd.append(f.name, new Blob([bytes], { type: f.contentType || "application/octet-stream" }), f.filename);
        }
        bodyInit = fd;
        for (const k of Object.keys(reqHeaders)) if (k.toLowerCase() === "content-type") delete reqHeaders[k];
      }
      const init: Record<string, unknown> = {
        method: req.method,
        headers: reqHeaders,
        body: bodyInit,
        redirect: "manual", // don't mistake an auth redirect for "reached"
        signal: controller.signal,
      };
      if (dispatcher) init.dispatcher = dispatcher; // via Burp (only when a proxy is set)
      const max = req.maxBodyBytes ?? this.opts.maxBodyBytes ?? 64 * 1024;
      if (!Number.isSafeInteger(max) || max < 1) throw new Error("maxBodyBytes must be a positive integer");
      this.opts.beforeSend?.(req);
      const res = await fetch(req.url, init as unknown as RequestInit);
      const chunks: Uint8Array[] = [];
      let bodyBytes = 0;
      let truncated = false;
      const reader = res.body?.getReader();
      if (reader) {
        try {
          while (bodyBytes < max) {
            const { value, done } = await reader.read();
            if (done) break;
            const kept = value.subarray(0, max - bodyBytes);
            chunks.push(kept.slice());
            bodyBytes += kept.byteLength;
            if (bodyBytes === max) {
              // Do not wait for another chunk: a server may leave a capped response open forever.
              const length = res.headers.get("content-length");
              truncated = value.byteLength > kept.byteLength || !!res.headers.get("content-encoding") || length === null || Number(length) !== bodyBytes;
              await reader.cancel();
            }
          }
        } finally {
          reader.releaseLock();
        }
      }
      const body = Buffer.concat(chunks, bodyBytes).toString("utf8");
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key] = value;
      });
      this.lastSentAt = Date.now();
      return { status: res.status, headers, body, bodyBytes, truncated, finalUrl: res.url || req.url, durationMs: Date.now() - started };
    } finally {
      clearTimeout(timer);
    }
  }
}

export type FakeResponder = (req: HttpRequest) => (Partial<HttpResponse> & { status: number });

/** For deterministic tests. The responder returns status/body/headers based on req. */
export class FakeHttpClient implements HttpClient {
  readonly sent: HttpRequest[] = [];
  constructor(private readonly responder: FakeResponder) {}

  async send(req: HttpRequest): Promise<HttpResponse> {
    this.sent.push(req);
    const r = this.responder(req);
    return {
      status: r.status,
      headers: r.headers ?? {},
      body: r.body ?? "",
      finalUrl: r.finalUrl ?? req.url,
      durationMs: r.durationMs ?? 1,
      ...(r.truncated !== undefined ? { truncated: r.truncated } : {}),
      ...(r.bodyBytes !== undefined ? { bodyBytes: r.bodyBytes } : {}),
    };
  }
}
