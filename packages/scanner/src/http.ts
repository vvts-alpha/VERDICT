// DESIGN §9 — policy-gated raw HTTP (for validation). The real impl is FetchHttpClient; tests use FakeHttpClient.

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
}

export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  finalUrl: string;
  durationMs: number;
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
}

export class FetchHttpClient implements HttpClient {
  private lastSentAt = 0;
  private dispatcher: unknown | null = null;
  private dispatcherInit = false;

  constructor(private readonly opts: FetchHttpClientOptions = {}) {}

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
    return {
      "user-agent": this.opts.userAgent ?? "verdict-scanner/0.1",
      ...(this.opts.headers ?? {}),
      ...(reqHeaders ?? {}),
    };
  }

  async send(req: HttpRequest): Promise<HttpResponse> {
    if (this.opts.allow && !this.opts.allow(req.url)) {
      throw new Error(`out-of-scope request blocked: ${req.url}`);
    }
    const minDelay = this.opts.minDelayMs ?? 0;
    if (minDelay > 0) {
      const wait = this.lastSentAt + minDelay - Date.now();
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
    }

    const started = Date.now();
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.opts.timeoutMs ?? 15_000);
    try {
      const dispatcher = await this.getDispatcher();
      const reqHeaders: Record<string, string> = {
        "user-agent": this.opts.userAgent ?? "verdict-scanner/0.1",
        ...(this.opts.headers ?? {}),
        ...(req.headers ?? {}),
      };
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
      const res = await fetch(req.url, init as unknown as RequestInit);
      const max = this.opts.maxBodyBytes ?? 64 * 1024;
      const body = Buffer.from(await res.arrayBuffer()).subarray(0, max).toString("utf8");
      const headers: Record<string, string> = {};
      res.headers.forEach((value, key) => {
        headers[key] = value;
      });
      this.lastSentAt = Date.now();
      return { status: res.status, headers, body, finalUrl: res.url || req.url, durationMs: Date.now() - started };
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
    };
  }
}
