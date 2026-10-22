// DESIGN §9 — policy-gated raw HTTP (for validation). The real impl is FetchHttpClient; tests use FakeHttpClient.

import { createHash } from "node:crypto";

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
  /** Set false to NOT merge the client's constructor-supplied default headers (site-wide Basic auth, operator custom
   *  headers carrying cookies/API keys, ...) into THIS request. Anonymous and alternate-identity replays must not
   *  silently inherit the baseline session — an unauth check that inherits the session's Authorization/Cookie would
   *  still be authed, and a role replay would carry both identities. Only `headers` plus the default user-agent go
   *  on the wire; scope, proxy, rate and budget handling are unchanged. Note: an AMBIENT identity that isn't a header
   *  (IP allowlist, mTLS, NTLM) cannot be excluded this way — treat such results as inconclusive for "public". */
  inheritDefaultHeaders?: boolean;
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
  /** Per-session-material write mutex — parallel workers may read concurrently, but state-changing requests
   *  under the SAME account (own session or a cross-role replay with identical material) are chained so a
   *  mutation can't interleave with another mutation on that account. Keyed by a digest of auth headers. */
  private writeQueues = new Map<string, Promise<unknown>>();

  constructor(private readonly opts: FetchHttpClientOptions = {}) {}

  /** State-changing-looking request: non-GET methods, plus GETs on paths that mutate (change-password,
   *  register, checkout, … — the same shapes the mutation ledger detects). OPTIONS/HEAD stay reads. */
  private looksMutating(req: HttpRequest): boolean {
    const m = (req.method || "GET").toUpperCase();
    if (!["GET", "HEAD", "OPTIONS"].includes(m)) return true;
    try {
      return /change[-_]?password|reset[-_]?password|register|signup|update|delete|checkout|order|comment|review|upload|logout/i.test(new URL(req.url).pathname);
    } catch {
      return false;
    }
  }

  /** Digest of the auth material on the wire — same cookie/bearer ⇒ same key ⇒ serialized writes. */
  private sessionKey(headers: Record<string, string>): string {
    const canon = Object.entries(headers)
      .filter(([k, v]) => v && /^(cookie|authorization|proxy-authorization|x-)/i.test(k) || (v && /token|auth|session|api[-_]?key/i.test(k)))
      .map(([k, v]) => `${k.toLowerCase()}:${v}`)
      .sort()
      .join("\n");
    return createHash("sha256").update(canon || "anon").digest("hex").slice(0, 16);
  }

  /** Chain fn through the write queue for this session key. */
  private enqueueWrite<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.writeQueues.get(key) ?? Promise.resolve();
    const next = prev.catch(() => undefined).then(fn);
    this.writeQueues.set(key, next);
    return next.finally(() => {
      if (this.writeQueues.get(key) === next) this.writeQueues.delete(key);
    }) as Promise<T>;
  }

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

  /** The headers actually sent for a given request (default user-agent + opts.headers + per-call, unless the request
   *  opted out of inherited defaults). Used to record the "whole request" in evidence — pass the same request flags
   *  so evidence matches the wire exactly. */
  effectiveHeaders(reqHeaders?: Record<string, string>, inheritDefaultHeaders = true): Record<string, string> {
    return foldHeaders(
      { "user-agent": this.opts.userAgent ?? DEFAULT_BROWSER_UA },
      inheritDefaultHeaders ? this.opts.headers : undefined,
      reqHeaders,
    );
  }

  async send(req: HttpRequest): Promise<HttpResponse> {
    if (this.opts.allow && !this.opts.allow(req.url)) {
      throw new Error(`out-of-scope request blocked: ${req.url}`);
    }
    const minDelay = this.rateOverrideMs ?? this.opts.minDelayMs ?? 0;
    // Reserve the send slot synchronously (read+write without an await in between) — under parallel workers
    // multiple sends race on lastSentAt; reserving keeps ≥minDelay between send STARTS globally.
    let slotWait = 0;
    if (minDelay > 0) {
      const now = Date.now();
      const sendAt = Math.max(this.lastSentAt + minDelay, now);
      this.lastSentAt = sendAt;
      slotWait = sendAt - now;
    }

    const dispatcher = await this.getDispatcher();
    // Fold case-insensitively so a caller's e.g. "User-Agent" REPLACES the default "user-agent" rather than colliding
    // into two keys that undici would comma-combine (which silently neutered header-injection probes + garbled evidence).
    const reqHeaders: Record<string, string> = this.effectiveHeaders(req.headers, req.inheritDefaultHeaders !== false);
    // Serializes state-changing sends per session-material so parallel workers can't interleave mutations on one account.
    const dispatch = async (): Promise<HttpResponse> => {
      if (slotWait > 0) await new Promise((r) => setTimeout(r, slotWait));
      const started = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs ?? 15_000);
      try {
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
    };
    // Mutating sends chain through the per-session write queue; reads go straight through.
    return this.looksMutating(req) ? await this.enqueueWrite(this.sessionKey(reqHeaders), dispatch) : await dispatch();
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
