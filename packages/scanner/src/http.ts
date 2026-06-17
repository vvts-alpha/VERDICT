// DESIGN §9 — policy gated な生 HTTP(検証用)。実体は FetchHttpClient、テストは FakeHttpClient。

export interface HttpRequest {
  method: string;
  url: string;
  headers?: Record<string, string>;
  body?: string | null;
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
  /** スコープゲート(out-of-scope は送信拒否) */
  allow?: (url: string) => boolean;
  timeoutMs?: number;
  maxBodyBytes?: number;
  /** リクエスト間の最小間隔(保守的レート。WAF 教訓) */
  minDelayMs?: number;
  userAgent?: string;
  /** 全リクエストに付与する既定ヘッダ(認証セッションの cookie 等)。 */
  headers?: Record<string, string>;
  /** 上流 HTTP プロキシ(例 Burp http://127.0.0.1:8080)。指定時のみ全リクエストを経由。
   *  未指定なら従来通り(プロキシ周りのコードは一切走らない=挙動不変)。 */
  proxy?: string;
}

export class FetchHttpClient implements HttpClient {
  private lastSentAt = 0;
  private dispatcher: unknown | null = null;
  private dispatcherInit = false;

  constructor(private readonly opts: FetchHttpClientOptions = {}) {}

  /** proxy 指定時のみ undici ProxyAgent を遅延生成(Burp の傍受 CA は検証スキップ)。失敗しても致命的でない。 */
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

  /** 実際に送信されるヘッダ(既定 user-agent + opts.headers + 呼び出し時)。証拠に「リクエスト全体」を残す用。 */
  effectiveHeaders(reqHeaders?: Record<string, string>): Record<string, string> {
    return {
      "user-agent": this.opts.userAgent ?? "amraam-scanner/0.1",
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
      const init: Record<string, unknown> = {
        method: req.method,
        headers: {
          "user-agent": this.opts.userAgent ?? "amraam-scanner/0.1",
          ...(this.opts.headers ?? {}),
          ...(req.headers ?? {}),
        },
        body: req.body ?? undefined,
        redirect: "manual", // 認証リダイレクトを「到達」と誤認しない
        signal: controller.signal,
      };
      if (dispatcher) init.dispatcher = dispatcher; // Burp 経由(proxy 指定時のみ)
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

/** 決定論テスト用。responder が req に応じて status/body/headers を返す。 */
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
