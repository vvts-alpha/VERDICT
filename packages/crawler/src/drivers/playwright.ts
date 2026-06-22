// DESIGN §6.1 / §6.2 — 本番 driver。Playwright launchPersistentContext + XHR/fetch 傍受 +
// SPA 仮想ルート採取。playwright-core は遅延 import(import しただけでは browser を要求しない)。
//
// in-page で実行されるコールバックは (globalThis as any) 経由で DOM へ触れる
// → DOM lib を引かず Node 型と衝突させない。

import type { BrowserContext, CDPSession, Page } from "playwright-core";
import type { CapturedExchange, Driver, FormObservation, Observation } from "../types.js";
import { detectStuck } from "../auth.js";

export interface AutoLoginOptions {
  loginUrl: string;
  username?: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
}

/** セッション解析用の Cookie(フラグ付き)。 */
export interface CookieInfo {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  path: string;
  domain: string;
}

/** smartLogin が使う現在ページのスナップショット。 */
export interface PageSnapshot {
  url: string;
  title: string;
  domSkeleton: string;
  visibleText: string;
  links: string[];
  forms: FormObservation[];
  virtualRoutes: string[];
}

export interface PlaywrightDriverOptions {
  /** 認証状態を宿す永続プロファイル(DESIGN §6.3 / §10) */
  userDataDir: string;
  headless?: boolean;
  /** browser バイナリを明示(playwright install 済みなら不要) */
  executablePath?: string;
  channel?: string;
  /** 追加 launch 引数(コンテナ実行では ["--no-sandbox"] が必要なことが多い) */
  args?: string[];
  /** 上流 HTTP プロキシ(例 Burp http://127.0.0.1:8080)。指定時のみブラウザ通信を経由 + TLS 検証無視。
   *  未指定なら従来通り(挙動不変)。 */
  proxy?: string;
  /** サイト全体を覆う HTTP Basic/Digest 認証の資格情報(operator 提供)。指定すると Playwright が
   *  401 WWW-Authenticate を毎ナビ/リダイレクトで自動応答する(Basic/Digest 両対応・CORS 影響なし)。 */
  httpCredentials?: { username: string; password: string };
  navTimeoutMs?: number;
  settleMs?: number;
  maxBodySample?: number;
  /** x-amraam マーカーを付ける URL の **追加** 絞り込み(任意)。マーカーは常に「同一オリジン(+遷移)」
   *  だけに付く(クロスオリジンには絶対付けない = 第三者 CDN/解析/別ドメイン API を CORS preflight で壊さない)。
   *  この述語を渡すと、その同一オリジン要求の中でさらに true のものだけに限定できる(既定=全許可)。
   *  ※ スコープ(評価対象)とは別概念: スコープは別ドメイン/API を含めて広げてよい。 */
  markerAllow?: (url: string) => boolean;
}

/** ブラウザ由来トラフィックを識別するためのマーカーヘッダ(同一オリジンには無害、クロスオリジンは preflight 化)。 */
const MARKER_HEADER = "x-amraam";
const MARKER_VALUE = "assessment";

interface SettledOptions {
  navTimeoutMs: number;
  settleMs: number;
  maxBodySample: number;
}

// --- in-page で実行される関数(serialize されて browser 上で動く) ---

const INIT_SCRIPT = (): void => {
  const g = globalThis as any;
  g.__veritasRoutes = g.__veritasRoutes || [];
  const rec = (u: unknown): void => {
    try {
      g.__veritasRoutes.push(new g.URL(String(u), g.location.href).toString());
    } catch {
      /* ignore */
    }
  };
  const h = g.history;
  if (h && !h.__veritasWrapped) {
    h.__veritasWrapped = true;
    const wrap =
      (orig: any) =>
      function (this: any, ...args: any[]): any {
        const r = orig.apply(this, args);
        if (args[2] != null) rec(args[2]);
        return r;
      };
    h.pushState = wrap(h.pushState);
    h.replaceState = wrap(h.replaceState);
    g.addEventListener("hashchange", () => rec(g.location.href));
  }
};

const PAGE_EXTRACT_FN = (): {
  title: string;
  skeleton: string;
  visibleText: string;
  links: string[];
  forms: { action: string | null; method: string; fields: { name: string; type: string }[] }[];
  virtualRoutes: string[];
  scripts: string[];
} => {
  const g = globalThis as any;
  const doc = g.document;
  const result = {
    title: "",
    skeleton: "empty",
    visibleText: "",
    links: [] as string[],
    forms: [] as { action: string | null; method: string; fields: { name: string; type: string }[] }[],
    virtualRoutes: (g.__veritasRoutes || []) as string[],
    scripts: [] as string[],
  };
  if (!doc) return result;
  result.title = doc.title || "";
  const body = doc.body;
  result.visibleText = (body && body.innerText ? String(body.innerText) : "").slice(0, 4000);
  result.links = Array.from(doc.querySelectorAll("a[href]"))
    .map((a: any) => a.getAttribute("href"))
    .filter((h: any): h is string => typeof h === "string" && h.length > 0);
  result.forms = Array.from(doc.querySelectorAll("form")).map((f: any) => ({
    action: f.getAttribute("action"),
    method: String(f.getAttribute("method") || "get").toLowerCase(),
    fields: Array.from(f.querySelectorAll("input,select,textarea"))
      .map((el: any) => ({
        name: el.getAttribute("name") || "",
        type: String(el.getAttribute("type") || el.tagName || "").toLowerCase(),
      }))
      .filter((x: { name: string }) => x.name.length > 0),
  }));
  result.scripts = Array.from(doc.querySelectorAll("script"))
    .map((s: any) => String(s.textContent || "").slice(0, 20000))
    .filter((t: string) => t.length > 0)
    .slice(0, 30);
  const walk = (el: any, depth: number): string => {
    if (!el || !el.tagName) return "";
    const tag = String(el.tagName).toLowerCase();
    if (depth > 12) return tag;
    const kids = Array.from(el.children || [])
      .slice(0, 40)
      .map((c: any) => walk(c, depth + 1))
      .filter(Boolean);
    return kids.length ? `${tag}>(${kids.join(",")})` : tag;
  };
  result.skeleton = body ? walk(body, 0) : "empty";
  return result;
};

export class PlaywrightDriver implements Driver {
  private buffer: CapturedExchange[] = [];

  private constructor(
    private readonly context: BrowserContext,
    private readonly page: Page,
    private readonly opts: SettledOptions,
  ) {}

  static async launch(options: PlaywrightDriverOptions): Promise<PlaywrightDriver> {
    const { chromium } = await import("playwright-core");
    const context = await chromium.launchPersistentContext(options.userDataDir, {
      headless: options.headless ?? true,
      // 注意: extraHTTPHeaders で全付与すると、カスタムヘッダがクロスオリジン要求を CORS preflight 化して
      // 第三者 CDN/解析/別サブドメイン API を壊す。マーカーは下のルーティングで「同一オリジンのみ」に付ける。
      ...(options.executablePath ? { executablePath: options.executablePath } : {}),
      ...(options.channel ? { channel: options.channel } : {}),
      ...(options.args ? { args: options.args } : {}),
      ...(options.proxy ? { proxy: { server: options.proxy }, ignoreHTTPSErrors: true } : {}), // Burp 経由(指定時のみ)
      ...(options.httpCredentials ? { httpCredentials: options.httpCredentials } : {}), // サイト全体の Basic/Digest(指定時のみ)
    });
    const page = context.pages()[0] ?? (await context.newPage());
    const driver = new PlaywrightDriver(context, page, {
      navTimeoutMs: options.navTimeoutMs ?? 20_000,
      settleMs: options.settleMs ?? 800,
      maxBodySample: options.maxBodySample ?? 4096,
    });
    await context.addInitScript(INIT_SCRIPT);
    // x-amraam マーカーは **同一オリジン(+ドキュメント遷移)** のリクエストにだけ付ける。クロスオリジンには
    // 一切付けない(= スコープに別ドメイン/API を含めても、ブラウザが第三者を CORS preflight で壊さない)。
    // スコープとマーカーは別概念: スコープ=何を評価してよいか(別ドメイン・API 込みで広げてOK)、
    // マーカー=識別ヘッダで、同一オリジンなら preflight 不要なので常に無害。markerAllow で更に絞れる(既定=全許可)。
    const markerAllow = options.markerAllow ?? ((): boolean => true);
    await context.route("**/*", async (route) => {
      try {
        const req = route.request();
        let sameOrigin = false;
        if (req.isNavigationRequest()) {
          sameOrigin = true; // ドキュメント遷移は CORS preflight 対象外 → 付けても安全
        } else {
          try {
            const frameUrl = req.frame()?.url() ?? "";
            sameOrigin = frameUrl !== "" && new URL(req.url()).origin === new URL(frameUrl).origin;
          } catch {
            sameOrigin = false;
          }
        }
        if (sameOrigin && markerAllow(req.url())) {
          await route.continue({ headers: { ...req.headers(), [MARKER_HEADER]: MARKER_VALUE } });
        } else {
          await route.continue();
        }
      } catch {
        try {
          await route.continue();
        } catch {
          /* route already handled/closed */
        }
      }
    });
    driver.attachCapture();
    return driver;
  }

  private attachCapture(): void {
    this.context.on("response", async (response) => {
      try {
        const request = response.request();
        const rt = request.resourceType();
        if (rt !== "xhr" && rt !== "fetch") return;
        const headers = await request.allHeaders();
        const contentType = await response.headerValue("content-type");
        let responseBodySample: string | null = null;
        if (contentType?.includes("json")) {
          try {
            responseBodySample = (await response.text()).slice(0, this.opts.maxBodySample);
          } catch {
            /* opaque/streamed body */
          }
        }
        const postData = request.postData();
        this.buffer.push({
          method: request.method(),
          url: request.url(),
          resourceType: rt,
          hasAuthorizationHeader: Object.keys(headers).some((h) => h.toLowerCase() === "authorization"),
          hasCookieHeader: Object.keys(headers).some((h) => h.toLowerCase() === "cookie"),
          requestBody: postData ? postData.slice(0, this.opts.maxBodySample) : null,
          status: response.status(),
          responseBodySample,
          responseContentType: contentType,
        });
      } catch {
        /* ignore capture errors */
      }
    });
  }

  async visit(url: string): Promise<Observation> {
    this.buffer = [];
    let status = 0;
    try {
      const resp = await this.page.goto(url, {
        waitUntil: "domcontentloaded",
        timeout: this.opts.navTimeoutMs,
      });
      status = resp?.status() ?? 0;
    } catch {
      /* navigation error → 取れた範囲で返す */
    }
    try {
      await this.page.waitForLoadState("networkidle", { timeout: 5_000 });
    } catch {
      /* networkidle に達しない SPA はタイムアウト無視 */
    }
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));

    const finalUrl = this.page.url();
    let data: ReturnType<typeof PAGE_EXTRACT_FN> = {
      title: "",
      skeleton: "empty",
      visibleText: "",
      links: [],
      forms: [],
      virtualRoutes: [],
      scripts: [],
    };
    try {
      data = await this.page.evaluate(PAGE_EXTRACT_FN);
    } catch {
      /* about:blank 等 */
    }

    return {
      requestedUrl: url,
      finalUrl,
      status,
      title: data.title,
      domSkeleton: data.skeleton,
      visibleText: data.visibleText,
      forms: data.forms,
      links: data.links,
      virtualRoutes: data.virtualRoutes,
      apiCalls: this.buffer.slice(),
      scripts: data.scripts,
    };
  }

  /**
   * 生ブラウザで人間にログインさせる(headed)。Cookie 注入はせず、
   * 認証状態は永続 userDataDir に宿る(DESIGN §6.3)。waitMs の間に人手でログイン完了させる。
   */
  async interactiveLogin(loginUrl: string, waitMs: number): Promise<void> {
    try {
      await this.page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
    } catch {
      /* ログイン URL に到達できなくても待つ */
    }
    await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
  }

  /**
   * 資格情報でログインフォームを自動入力・送信(DESIGN §6.3 ステップ1)。Cookie 注入ではなく
   * 実フォームへの入力。CAPTCHA/MFA/失敗を検出したら ok:false(呼び出し側が人手ログインへ切替)。
   */
  async autoLogin(o: AutoLoginOptions): Promise<{ ok: boolean; reason: string }> {
    try {
      await this.page.goto(o.loginUrl, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
    } catch {
      return { ok: false, reason: `cannot reach login url ${o.loginUrl}` };
    }
    const passSel = o.passwordSelector ?? 'input[type="password"]';
    const userSel =
      o.usernameSelector ??
      'input[type="email"], input[name*="user" i], input[name*="email" i], input[name="login"], input[id*="user" i]';
    try {
      if (o.username) await this.page.fill(userSel, o.username, { timeout: 4000 }).catch(() => {});
      await this.page.fill(passSel, o.password, { timeout: 4000 });
    } catch {
      return { ok: false, reason: "login form not found (no password field)" };
    }
    if (o.submitSelector) {
      await this.page.click(o.submitSelector, { timeout: 4000 }).catch(() => {});
    } else {
      const clicked = await this.page
        .click('button[type="submit"], input[type="submit"]', { timeout: 3000 })
        .then(() => true)
        .catch(() => false);
      if (!clicked) await this.page.press(passSel, "Enter").catch(() => {});
    }
    await this.page.waitForLoadState("networkidle", { timeout: 8000 }).catch(() => {});
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));

    const finalUrl = this.page.url();
    const data = await this.page.evaluate(PAGE_EXTRACT_FN).catch(() => null);
    if (data) {
      const stuck = detectStuck({
        requestedUrl: o.loginUrl,
        finalUrl,
        status: 200,
        title: data.title,
        domSkeleton: data.skeleton,
        visibleText: data.visibleText,
        forms: data.forms,
        links: data.links,
        virtualRoutes: data.virtualRoutes,
        apiCalls: [],
      });
      if (stuck) return { ok: false, reason: `stuck: ${stuck.detail}` };
      if (data.forms.some((f) => f.fields.some((x) => x.type === "password"))) {
        return { ok: false, reason: "still on a login form (bad credentials or extra step)" };
      }
    }
    return { ok: true, reason: `logged in (now at ${finalUrl})` };
  }

  // --- LLM ログイン(smartLogin)用の粒度の細かいブラウザ操作 ---

  async gotoUrl(url: string): Promise<void> {
    try {
      await this.page.goto(url, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
    } catch {
      /* 到達できなくても続行 */
    }
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));
  }

  async snapshot(): Promise<PageSnapshot> {
    await this.page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
    const data = await this.page.evaluate(PAGE_EXTRACT_FN).catch(() => null);
    return {
      url: this.page.url(),
      title: data?.title ?? "",
      domSkeleton: data?.skeleton ?? "",
      visibleText: data?.visibleText ?? "",
      links: data?.links ?? [],
      forms: data?.forms ?? [],
      virtualRoutes: data?.virtualRoutes ?? [],
    };
  }

  async fill(selector: string, value: string): Promise<boolean> {
    return this.page
      .fill(selector, value, { timeout: 4000 })
      .then(() => true)
      .catch(() => false);
  }

  async clickFirst(selectors: string[]): Promise<boolean> {
    for (const selector of selectors) {
      const ok = await this.page
        .click(selector, { timeout: 2500 })
        .then(() => true)
        .catch(() => false);
      if (ok) return true;
    }
    return false;
  }

  async pressEnter(selector: string): Promise<void> {
    await this.page.press(selector, "Enter").catch(() => {});
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));
  }

  /** ログイン後のセッション Cookie を Cookie ヘッダ文字列に(auth-diff のロール用)。 */
  async sessionCookieHeader(): Promise<string> {
    const cookies = await this.context.cookies().catch(() => []);
    return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  }

  /** 現在ページのスクリーンショットを path に保存(WebUI 表示用)。親ディレクトリは自動作成。
   *  真っ白スクショ対策: 撮る前に描画が落ち着くのを待つ(networkidle → フォント ready → 小休止)。
   *  settleMs で追加の固定待ちを調整可(既定 700ms)。 */
  async saveScreenshot(path: string, settleMs = 700): Promise<boolean> {
    try {
      await this.page.waitForLoadState("networkidle", { timeout: 4_000 }).catch(() => {});
      // フォント読み込み完了を待つ(text が消えた真っ白フレームを防ぐ)。直列化のため boolean に畳む。
      // in-page コールバックは (globalThis as any) 経由で DOM へ(crawler tsconfig は dom lib 無し)。
      await this.page
        .evaluate(() => {
          const g = globalThis as any;
          return g.document?.fonts?.ready?.then(() => true) ?? true;
        })
        .catch(() => {});
      if (settleMs > 0) await this.page.waitForTimeout(settleMs);
      await this.page.screenshot({ path, fullPage: false, timeout: 5_000 });
      return true;
    } catch {
      return false;
    }
  }

  /** 認証 Cookie をフラグ付きで取得(セッション解析用: HttpOnly/Secure/SameSite/予測可能性)。 */
  async cookies(): Promise<CookieInfo[]> {
    const cs = await this.context.cookies().catch(() => []);
    return cs.map((c) => ({
      name: c.name,
      value: c.value,
      httpOnly: Boolean(c.httpOnly),
      secure: Boolean(c.secure),
      sameSite: String(c.sameSite ?? "None"),
      path: c.path,
      domain: c.domain,
    }));
  }

  /** 永続コンテキストの Cookie を消す(別ロールでログインし直す前に)。 */
  async clearSession(): Promise<void> {
    await this.context.clearCookies().catch(() => {});
  }

  /** operator が事前取得した Cookie をコンテキストに注入(Cookie ファイル認証用)。 */
  async addCookies(
    cookies: Array<{ name: string; value: string; domain?: string; path?: string; url?: string; httpOnly?: boolean; secure?: boolean }>,
  ): Promise<void> {
    if (cookies.length === 0) return;
    await this.context.addCookies(cookies as Parameters<BrowserContext["addCookies"]>[0]).catch(() => {});
  }

  /** 現在ページの URL(ログイン後の着地点 = 認証済み再クロールの起点に使う)。 */
  currentUrl(): string {
    return this.page.url();
  }

  /** ライブ遠隔ログイン(attended×LiveHands)用に現在ページの CDP セッションを返す
   *  (Page.startScreencast + Input.dispatch*)。認証状態は永続 userDataDir に宿る。 */
  async cdpSession(): Promise<CDPSession> {
    return this.context.newCDPSession(this.page);
  }

  /** 傍受バッファを取り出してクリア(操作で発火した API を回収する。能動探索用)。 */
  drainApiCalls(): CapturedExchange[] {
    const out = this.buffer.slice();
    this.buffer = [];
    return out;
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}
