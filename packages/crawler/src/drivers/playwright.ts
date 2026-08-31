// DESIGN §6.1 / §6.2 — production driver. Playwright launchPersistentContext + XHR/fetch interception +
// SPA virtual-route capture. playwright-core is lazily imported (importing it alone doesn't require a browser).
//
// Callbacks that run in-page touch the DOM via (globalThis as any)
// → so we don't pull in the DOM lib and clash with Node types.

import type { BrowserContext, CDPSession, Dialog, Page } from "playwright-core";
import type { CapturedExchange, Driver, FormObservation, Observation } from "../types.js";
import { detectStuck } from "../auth.js";
import { DEFAULT_BROWSER_UA } from "@veritas/core";

export interface AutoLoginOptions {
  loginUrl: string;
  username?: string;
  password: string;
  usernameSelector?: string;
  passwordSelector?: string;
  submitSelector?: string;
}

/** Cookie (with flags) for session analysis. */
export interface CookieInfo {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
  path: string;
  domain: string;
}

/** Snapshot of the current page used by smartLogin. */
export interface PageSnapshot {
  url: string;
  title: string;
  domSkeleton: string;
  visibleText: string;
  links: string[];
  clickables?: { text: string; selector: string }[];
  forms: FormObservation[];
  virtualRoutes: string[];
}

export interface PlaywrightDriverOptions {
  /** Persistent profile that holds auth state (DESIGN §6.3 / §10) */
  userDataDir: string;
  headless?: boolean;
  /** Browser User-Agent. Defaults to a realistic desktop Chrome UA (drops Playwright's "HeadlessChrome" tell that some WAFs / bot filters block). */
  userAgent?: string;
  /** Explicit browser binary (unnecessary if playwright install has been run) */
  executablePath?: string;
  channel?: string;
  /** Extra launch args (container runs often need ["--no-sandbox"]) */
  args?: string[];
  /** Upstream HTTP proxy (e.g. Burp http://127.0.0.1:8080). Only when set does browser traffic route through it + skip TLS verification.
   *  If unset, behaves as before (byte-identical). */
  proxy?: string;
  /** Site-wide HTTP Basic/Digest credentials (operator-provided). When set, Playwright auto-responds to
   *  401 WWW-Authenticate on every navigation/redirect (handles both Basic/Digest, no CORS impact). */
  httpCredentials?: { username: string; password: string };
  /** Operator-provided custom headers (WAF bypass, engagement-mandated headers, etc.). Like the marker, added only to
   *  "same-origin (+ document navigation)" requests (never cross-origin = don't break third parties via a CORS
   *  preflight). The raw-http path (FetchHttpClient) adds them separately. */
  extraHeaders?: Record<string, string>;
  navTimeoutMs?: number;
  settleMs?: number;
  maxBodySample?: number;
  /** **Additional** filter (optional) on which URLs get the x-verdict marker. The marker is always added only to
   *  "same-origin (+ navigation)" (never cross-origin = don't break third-party CDN/analytics/other-domain APIs via a CORS preflight).
   *  Passing this predicate further restricts it to same-origin requests where it returns true (default = allow all).
   *  Note: distinct from scope (what may be assessed): scope may broaden to include other domains/APIs. */
  markerAllow?: (url: string) => boolean;
}

/** Marker header to identify browser-origin traffic (harmless same-origin, triggers a preflight cross-origin). */
const MARKER_HEADER = "x-verdict";
const MARKER_VALUE = "assessment";

interface SettledOptions {
  navTimeoutMs: number;
  settleMs: number;
  maxBodySample: number;
}

// --- functions that run in-page (serialized and executed in the browser) ---

// Reduce the automation fingerprint (runs before page scripts). Lets an anti-bot CAPTCHA (Cloudflare Turnstile / Arkose /
// PerimeterX) be SOLVED BY A HUMAN in attended mode instead of permanently rejecting the browser as automated. This is
// NOT auto-solving — it only makes the browser look normal so the operator's handoff can pass. Defensive (only overrides
// when needed, try/catch each) and MINIMAL — it does NOT touch WebGL / plugins / canvas (which could break app JS or the
// recon extraction). navigator.webdriver is also cleared at the Chrome level by --disable-blink-features=AutomationControlled.
const STEALTH_INIT = (): void => {
  const nav = (globalThis as any).navigator;
  const win = globalThis as any;
  try {
    if (nav && nav.webdriver) Object.defineProperty(nav, "webdriver", { get: () => undefined, configurable: true });
  } catch {
    /* ignore */
  }
  try {
    if (win && !win.chrome) win.chrome = { runtime: {} };
  } catch {
    /* ignore */
  }
  try {
    if (nav && (!nav.languages || nav.languages.length === 0)) Object.defineProperty(nav, "languages", { get: () => ["en-US", "en"], configurable: true });
  } catch {
    /* ignore */
  }
  try {
    // A classic headless tell: Notification.permission says 'denied' while permissions.query returns 'prompt'. Make them agree.
    const perms = nav && nav.permissions;
    const N = (globalThis as any).Notification;
    if (perms && perms.query && N) {
      const orig = perms.query.bind(perms);
      perms.query = (p: any): any => (p && p.name === "notifications" ? Promise.resolve({ state: N.permission }) : orig(p));
    }
  } catch {
    /* ignore */
  }
};

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
  clickables: { text: string; selector: string }[];
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
    clickables: [] as { text: string; selector: string }[],
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
  // Non-anchor clickable controls (button-based navigation the a[href] crawl misses). Give each a label + a selector
  // usable with browser_click. Cap to keep responses small; dedup by selector.
  const cssEsc = (v: string): string => (g.CSS && g.CSS.escape ? g.CSS.escape(v) : v.replace(/[^\w-]/g, "\\$&"));
  const seenSel = new Set<string>();
  for (const el of Array.from(doc.querySelectorAll("button, input[type=submit], input[type=button], [role=button], [onclick]")) as any[]) {
    if (result.clickables.length >= 30) break;
    const tag = String(el.tagName || "").toLowerCase();
    const text = String(el.innerText || el.value || el.getAttribute("aria-label") || el.getAttribute("title") || "").replace(/\s+/g, " ").trim().slice(0, 60);
    const id = el.getAttribute("id");
    const name = el.getAttribute("name");
    let selector: string;
    if (id) selector = "#" + cssEsc(id);
    else if (name) selector = tag + '[name="' + name.replace(/"/g, '\\"') + '"]';
    else if (text && text.length <= 40) selector = tag + ':has-text("' + text.replace(/"/g, '\\"') + '")';
    else selector = tag;
    if (seenSel.has(selector)) continue;
    seenSel.add(selector);
    result.clickables.push({ text, selector });
  }
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
      userAgent: options.userAgent ?? DEFAULT_BROWSER_UA, // avoid the default "HeadlessChrome" UA that bot/WAF filters reject
      // Note: adding everything via extraHTTPHeaders would make custom headers turn cross-origin requests into CORS preflights
      // and break third-party CDN/analytics/other-subdomain APIs. The marker is added "same-origin only" via the routing below.
      // Drop the automation fingerprint so an anti-bot CAPTCHA can be human-solved in attended mode (see STEALTH_INIT).
      // Additive: full CDP control + all recon (route capture / XHR intercept / DOM extract) are unaffected.
      args: ["--disable-blink-features=AutomationControlled", ...(options.args ?? [])],
      ignoreDefaultArgs: ["--enable-automation"], // removes the "controlled by automated software" flag + infobar (a tell)
      ...(options.executablePath ? { executablePath: options.executablePath } : {}),
      ...(options.channel ? { channel: options.channel } : {}),
      ...(options.proxy ? { proxy: { server: options.proxy }, ignoreHTTPSErrors: true } : {}), // via Burp (only when set)
      ...(options.httpCredentials ? { httpCredentials: options.httpCredentials } : {}), // site-wide Basic/Digest (only when set)
    });
    const page = context.pages()[0] ?? (await context.newPage());
    const driver = new PlaywrightDriver(context, page, {
      navTimeoutMs: options.navTimeoutMs ?? 20_000,
      settleMs: options.settleMs ?? 800,
      maxBodySample: options.maxBodySample ?? 4096,
    });
    await context.addInitScript(STEALTH_INIT); // fingerprint-reduction first, then the route-capture hooks
    await context.addInitScript(INIT_SCRIPT);
    // The x-verdict marker is added only to **same-origin (+ document navigation)** requests. Never to cross-origin
    // at all (= even if scope includes other domains/APIs, the browser won't break third parties via a CORS preflight).
    // Scope and marker are distinct: scope = what may be assessed (fine to broaden across domains/APIs),
    // marker = an identifying header, harmless same-origin since it needs no preflight. markerAllow narrows it further (default = allow all).
    const markerAllow = options.markerAllow ?? ((): boolean => true);
    const extraHeaders = options.extraHeaders;
    const hasExtra = !!extraHeaders && Object.keys(extraHeaders).length > 0;
    await context.route("**/*", async (route) => {
      try {
        const req = route.request();
        let sameOrigin = false;
        if (req.isNavigationRequest()) {
          sameOrigin = true; // document navigation isn't subject to a CORS preflight → safe to add
        } else {
          try {
            const frameUrl = req.frame()?.url() ?? "";
            sameOrigin = frameUrl !== "" && new URL(req.url()).origin === new URL(frameUrl).origin;
          } catch {
            sameOrigin = false;
          }
        }
        if (sameOrigin && (hasExtra || markerAllow(req.url()))) {
          // same-origin only: add the operator's custom headers + the x-verdict marker (doesn't trigger a CORS preflight).
          const headers: Record<string, string> = { ...req.headers() };
          if (hasExtra) Object.assign(headers, extraHeaders);
          if (markerAllow(req.url())) headers[MARKER_HEADER] = MARKER_VALUE;
          await route.continue({ headers });
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

  /**
   * networkidle / a fixed settle alone misses SPAs that render via delayed XHR
   * (snapshot before render completes → empty skeleton / missing links·APIs = flaky "works sometimes, not others").
   * So observe body content volume (visible-text length + element count) at a fixed interval and, **once it stops
   * changing for 2 consecutive samples**, treat rendering as settled and return (capped at maxMs). Static pages
   * exit in ~0.4s; only lazily-rendered pages wait as long as needed — an adaptive wait. Because it defers the
   * snapshot, XHRs that resolve in the meantime also land in this.buffer, reducing missed firedApis at the same time.
   *   In-page callbacks reach the DOM via (globalThis as any) (the crawler tsconfig has no dom lib).
   */
  private async waitForDomStable(maxMs = 4_000, intervalMs = 200): Promise<void> {
    const sig = (): Promise<number> =>
      this.page
        .evaluate(() => {
          const g = globalThis as any;
          const b = g.document && g.document.body;
          if (!b) return 0;
          return (b.innerText ? String(b.innerText).length : 0) + b.getElementsByTagName("*").length;
        })
        .catch(() => -1); // sentinel: can't evaluate (mid-navigation etc.) → give up waiting for stability
    const start = Date.now();
    let last = -1;
    let stable = 0;
    while (Date.now() - start < maxMs) {
      const cur = await sig();
      if (cur < 0) return; // page can't be evaluated → defer to the caller's fixed settle
      if (cur > 0 && cur === last) {
        if (++stable >= 2) return; // unchanged for 2 in a row → treat rendering as settled
      } else {
        stable = 0;
        last = cur;
      }
      await this.page.waitForTimeout(intervalMs);
    }
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
      /* navigation error → return what we managed to capture */
    }
    try {
      await this.page.waitForLoadState("networkidle", { timeout: 5_000 });
    } catch {
      /* SPAs that never reach networkidle: ignore the timeout → wait for render via the DOM-stable wait below */
    }
    await this.waitForDomStable(); // guard against missing delayed-XHR rendering (adaptive wait until rendering stops)
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));

    const finalUrl = this.page.url();
    let data: ReturnType<typeof PAGE_EXTRACT_FN> = {
      title: "",
      skeleton: "empty",
      visibleText: "",
      links: [],
      clickables: [],
      forms: [],
      virtualRoutes: [],
      scripts: [],
    };
    try {
      data = await this.page.evaluate(PAGE_EXTRACT_FN);
    } catch {
      /* about:blank etc. */
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
      clickables: data.clickables,
      virtualRoutes: data.virtualRoutes,
      apiCalls: this.buffer.slice(),
      scripts: data.scripts,
    };
  }

  /**
   * Let a human log in via a real browser (headed). No cookie injection;
   * auth state lives in the persistent userDataDir (DESIGN §6.3). The human completes login during waitMs.
   */
  async interactiveLogin(loginUrl: string, waitMs: number): Promise<void> {
    try {
      await this.page.goto(loginUrl, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
    } catch {
      /* wait even if the login URL can't be reached */
    }
    await new Promise<void>((resolve) => setTimeout(resolve, waitMs));
  }

  /**
   * Auto-fill and submit the login form with credentials (DESIGN §6.3 step 1). Real form input,
   * not cookie injection. On CAPTCHA/MFA/failure, return ok:false (the caller switches to human login).
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

  // --- fine-grained browser operations for LLM login (smartLogin) ---

  async gotoUrl(url: string): Promise<void> {
    try {
      await this.page.goto(url, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
    } catch {
      /* continue even if unreachable */
    }
    await this.waitForDomStable(); // like visit(), an adaptive wait until rendering settles
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));
  }

  /**
   * Browser XSS *execution* detection. Navigate to `url` (with the payload embedded) and observe whether the payload actually ran.
   * For **DOM-based / innerHTML-sink XSS** that probe_xss (which inspects the HTTP response reflection) fundamentally can't catch
   * (e.g. Juice Shop's search `#/search?q=…` renders q into innerHTML → never appears in the server response, executes in the browser).
   * Detection signals: the payload either (1) sets `window.__verdict_xss = marker` (an `<img onerror>`/`<svg onload>` etc. fired)
   * or (2) surfaces the marker via `alert/confirm/prompt`. Either one confirms execution.
   */
  async detectXssExecution(url: string, marker: string): Promise<{ executed: boolean; signal: string }> {
    let dialog = "";
    const onDialog = (d: Dialog) => {
      dialog = d.message();
      void d.dismiss().catch(() => {});
    };
    this.page.on("dialog", onDialog);
    try {
      try {
        await this.page.goto(url, { waitUntil: "domcontentloaded", timeout: this.opts.navTimeoutMs });
      } catch {
        /* SPA hash routes may not count as navigation completion → continue and wait for render */
      }
      // wait for the SPA to evaluate the route and reflect q into innerHTML → img.onerror / svg.onload fires.
      await new Promise<void>((resolve) => setTimeout(resolve, Math.max(this.opts.settleMs, 900)));
      const g = await this.page
        .evaluate(() => String((globalThis as { __verdict_xss?: unknown }).__verdict_xss ?? ""))
        .catch(() => "");
      const viaGlobal = g.includes(marker);
      const viaDialog = dialog.includes(marker);
      const executed = viaGlobal || viaDialog;
      return {
        executed,
        signal: executed
          ? viaGlobal
            ? `XSS EXECUTED — sink fired (onerror/onload set window.__verdict_xss=${g})`
            : `XSS EXECUTED — dialog(alert/confirm/prompt): ${dialog}`
          : "no execution — payload was not run by the browser (escaped / not a live sink)",
      };
    } finally {
      this.page.off("dialog", onDialog);
    }
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
      clickables: data?.clickables ?? [],
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

  /** Upload a file (<input type=file>) via setInputFiles and submit. base64 also supports binary. */
  async uploadFile(
    selector: string,
    filename: string,
    base64: string,
    contentType?: string,
    submitSelector?: string,
  ): Promise<{ ok: boolean; note: string }> {
    try {
      await this.page.setInputFiles(selector, {
        name: filename,
        mimeType: contentType || "application/octet-stream",
        buffer: Buffer.from(base64, "base64"),
      });
    } catch (e) {
      return { ok: false, note: `setInputFiles failed on ${selector}: ${String(e).slice(0, 120)}` };
    }
    // submit: use the given selector, else try a submit button.
    const submitted = submitSelector
      ? await this.page.click(submitSelector, { timeout: 4000 }).then(() => true).catch(() => false)
      : await this.page.click('button[type="submit"], input[type="submit"], button', { timeout: 3000 }).then(() => true).catch(() => false);
    await this.page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
    await this.waitForDomStable();
    return { ok: true, note: `uploaded ${filename} via ${selector}${submitted ? " + submitted" : " (no submit button clicked — pass submitSelector if needed)"}` };
  }

  /** Stage a file into an <input type=file> via setInputFiles WITHOUT submitting (chat file-upload seedMode). */
  async stageFile(
    selector: string,
    filename: string,
    base64: string,
    contentType?: string,
  ): Promise<{ ok: boolean; note: string }> {
    try {
      await this.page.setInputFiles(selector, {
        name: filename,
        mimeType: contentType || "application/octet-stream",
        buffer: Buffer.from(base64, "base64"),
      });
    } catch (e) {
      return { ok: false, note: `setInputFiles failed on ${selector}: ${String(e).slice(0, 120)}` };
    }
    await this.page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => {});
    await this.waitForDomStable();
    return { ok: true, note: `staged ${filename} via ${selector}` };
  }

  /** UNCAPPED innerText of the chat transcript / reply container (bypasses snapshot()'s 4000-char cap).
   *  With no selector it walks a priority list of common chat-log containers, falling back to full body text. */
  async transcriptText(selector?: string): Promise<string> {
    await this.waitForDomStable().catch(() => {});
    const sels = selector
      ? [selector]
      : [
          '[role="log"]',
          '[data-testid*="transcript" i], [data-testid*="messages" i], [data-testid*="conversation" i]',
          "main",
          '[class*="transcript" i], [class*="messages" i], [class*="conversation" i], [class*="chat-log" i], [class*="chat" i]',
          "[aria-live]",
        ];
    return this.page
      .evaluate((list: string[]) => {
        const g = globalThis as any;
        const doc = g.document;
        if (!doc) return "";
        for (const sel of list) {
          const el = doc.querySelector(sel);
          if (el && el.innerText && String(el.innerText).trim().length > 0) return String(el.innerText);
        }
        const b = doc.body;
        return b && b.innerText ? String(b.innerText) : "";
      }, sels)
      .catch(() => "");
  }

  /** Resolve a live frame by URL ("" = top document). */
  private frameByUrl(frameUrl: string) {
    return this.page.frames().find((f) => f.url() === frameUrl) ?? null;
  }

  /** fill() scoped to a frame ("" = top document → the existing top-level fill, unchanged). */
  async fillFrame(frameUrl: string, selector: string, value: string): Promise<boolean> {
    if (!frameUrl) return this.fill(selector, value);
    const fr = this.frameByUrl(frameUrl);
    if (!fr) return false;
    return fr
      .fill(selector, value, { timeout: 4000 })
      .then(() => true)
      .catch(() => false);
  }

  /** clickFirst() scoped to a frame ("" = top document). */
  async clickFrame(frameUrl: string, selectors: string[]): Promise<boolean> {
    if (!frameUrl) return this.clickFirst(selectors);
    const fr = this.frameByUrl(frameUrl);
    if (!fr) return false;
    for (const selector of selectors) {
      const ok = await fr
        .click(selector, { timeout: 2500 })
        .then(() => true)
        .catch(() => false);
      if (ok) return true;
    }
    return false;
  }

  /** pressEnter() scoped to a frame ("" = top document). */
  async pressEnterFrame(frameUrl: string, selector: string): Promise<void> {
    if (!frameUrl) return this.pressEnter(selector);
    const fr = this.frameByUrl(frameUrl);
    await fr?.press(selector, "Enter").catch(() => {});
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));
  }

  /** UNCAPPED transcript/reply-container text scoped to a frame ("" = top document → transcriptText). */
  async transcriptTextFrame(frameUrl: string, selector?: string): Promise<string> {
    if (!frameUrl) return this.transcriptText(selector);
    const fr = this.frameByUrl(frameUrl);
    if (!fr) return "";
    const sels = selector
      ? [selector]
      : [
          '[role="log"]',
          '[data-testid*="transcript" i], [data-testid*="messages" i], [data-testid*="conversation" i]',
          "main",
          '[class*="transcript" i], [class*="messages" i], [class*="conversation" i], [class*="chat-log" i], [class*="chat" i]',
          "[aria-live]",
        ];
    return fr
      .evaluate((list: string[]) => {
        const g = globalThis as any;
        const doc = g.document;
        if (!doc) return "";
        for (const sel of list) {
          const el = doc.querySelector(sel);
          if (el && el.innerText && String(el.innerText).trim().length > 0) return String(el.innerText);
        }
        const b = doc.body;
        return b && b.innerText ? String(b.innerText) : "";
      }, sels)
      .catch(() => "");
  }

  /** Scan every frame for a calibration marker the operator sent into the target composer. Returns the URL of
   *  the frame whose transcript now shows it ("" = top document), or null — this is how attended calibration
   *  locates the right frame + composer even when the assistant is an embedded (iframe) widget. */
  async findMarker(marker: string): Promise<{ frame: string } | null> {
    for (const fr of this.page.frames()) {
      const has = await fr
        .evaluate((m: string) => {
          const b = (globalThis as any).document?.body;
          return b && b.innerText ? String(b.innerText).includes(m) : false;
        }, marker)
        .catch(() => false);
      if (has) return { frame: fr === this.page.mainFrame() ? "" : fr.url() };
    }
    return null;
  }

  async pressEnter(selector: string): Promise<void> {
    await this.page.press(selector, "Enter").catch(() => {});
    await new Promise<void>((resolve) => setTimeout(resolve, this.opts.settleMs));
  }

  /** Session cookies after login → a Cookie header string (for auth-diff roles). */
  async sessionCookieHeader(): Promise<string> {
    const cookies = await this.context.cookies().catch(() => []);
    return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
  }

  /** Recover the Bearer JWT the SPA holds browser-side (scans the common local/sessionStorage keys).
   *  Juice Shop and the like authenticate XHR/API via `Authorization: Bearer <localStorage.token>` rather than a cookie,
   *  so without picking this up and putting it on http_request/probe_logic, every write API would 401. Returns the raw token string. */
  async bearerToken(): Promise<string | null> {
    const raw = await this.page
      .evaluate(() => {
        const g = globalThis as any;
        const stores = [g.localStorage, g.sessionStorage].filter(Boolean);
        const keys = ["token", "access_token", "accessToken", "authToken", "auth_token", "jwt", "id_token", "idToken", "bearer"];
        for (const st of stores) {
          for (const k of keys) {
            const v = st.getItem?.(k);
            if (typeof v === "string" && v.length > 20) return v;
          }
          // also handles the case where the value is JSON wrapping {token:...}/{accessToken:...}.
          for (let i = 0; i < (st.length ?? 0); i++) {
            const k = st.key?.(i);
            const v = k ? st.getItem(k) : null;
            if (typeof v === "string" && v.startsWith("{")) {
              try {
                const o = JSON.parse(v);
                for (const kk of keys) if (typeof o?.[kk] === "string" && o[kk].length > 20) return o[kk];
              } catch {
                /* not json */
              }
            }
          }
        }
        return null;
      })
      .catch(() => null);
    if (!raw) return null;
    // may be stored as "Bearer xxx", so normalize to the bare token. Also lightly check it looks like a JWT (two '.').
    const tok = raw.replace(/^Bearer\s+/i, "").trim();
    return tok.length > 20 ? tok : null;
  }

  /** Save a screenshot of the current page to path (for WebUI display). Parent directory is created automatically.
   *  Blank-screenshot guard: wait for rendering to settle before capturing (networkidle → fonts ready → brief pause).
   *  settleMs tunes the extra fixed wait (default 700ms). */
  async saveScreenshot(path: string, settleMs = 700): Promise<boolean> {
    try {
      await this.page.waitForLoadState("networkidle", { timeout: 4_000 }).catch(() => {});
      // wait for fonts to finish loading (prevents a blank frame with the text gone). Fold to a boolean for serialization.
      // in-page callbacks reach the DOM via (globalThis as any) (the crawler tsconfig has no dom lib).
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

  /** Get auth cookies with flags (for session analysis: HttpOnly/Secure/SameSite/predictability). */
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

  /** Clear the persistent context's cookies (before re-logging-in as a different role). */
  async clearSession(): Promise<void> {
    await this.context.clearCookies().catch(() => {});
  }

  /** Inject cookies the operator pre-captured into the context (for cookie-file auth). */
  async addCookies(
    cookies: Array<{ name: string; value: string; domain?: string; path?: string; url?: string; httpOnly?: boolean; secure?: boolean }>,
  ): Promise<void> {
    if (cookies.length === 0) return;
    await this.context.addCookies(cookies as Parameters<BrowserContext["addCookies"]>[0]).catch(() => {});
  }

  /** Restore Playwright storageState `origins` (SPA Bearer in localStorage). Init-script covers later navigations;
   *  if the current page already matches an origin, set immediately too. */
  async restoreLocalStorage(
    origins: Array<{ origin: string; localStorage: Array<{ name: string; value: string }> }>,
  ): Promise<void> {
    if (origins.length === 0) return;
    await this.context.addInitScript((entries: Array<{ origin: string; localStorage: Array<{ name: string; value: string }> }>) => {
      const g = globalThis as any;
      const origin = g.location?.origin;
      if (!origin) return;
      const match = entries.find((o) => o.origin === origin);
      if (!match) return;
      const st = g.localStorage;
      if (!st) return;
      for (const item of match.localStorage) {
        try {
          st.setItem(item.name, item.value);
        } catch {
          /* quota / private mode */
        }
      }
    }, origins);
    let currentOrigin = "";
    try {
      currentOrigin = new URL(this.page.url()).origin;
    } catch {
      /* about:blank */
    }
    const here = origins.find((o) => o.origin === currentOrigin);
    if (!here) return;
    await this.page
      .evaluate((items: Array<{ name: string; value: string }>) => {
        const st = (globalThis as any).localStorage;
        if (!st) return;
        for (const item of items) {
          try {
            st.setItem(item.name, item.value);
          } catch {
            /* quota / private mode */
          }
        }
      }, here.localStorage)
      .catch(() => {});
  }

  /** The current page URL (the post-login landing point = start of the authenticated re-crawl). */
  currentUrl(): string {
    return this.page.url();
  }

  /** Return the current page's CDP session for live remote login (attended×LiveHands)
   *  (Page.startScreencast + Input.dispatch*). Auth state lives in the persistent userDataDir. */
  async cdpSession(): Promise<CDPSession> {
    return this.context.newCDPSession(this.page);
  }

  /** Take and clear the intercept buffer (collect APIs fired by an interaction; for active exploration). */
  drainApiCalls(): CapturedExchange[] {
    const out = this.buffer.slice();
    this.buffer = [];
    return out;
  }

  /**
   * Active input sweep: fill the current page's forms/input fields with benign values and submit, returning the
   * **new routes + fired XHR/fetch URLs** that come out (for the "touch every input" survey).
   * - aggressive=false submits only GET/search forms (never POST = writes no data). true also submits POST.
   * - logout / out-of-scope are rejected by allow() (self-destruction guard). DELETE/PUT/PATCH forms are always skipped.
   * - each form submission may navigate the page, so navigate back to origin every time to restore state.
   */
  async exerciseInputs(opts: { aggressive: boolean; allow: (url: string) => boolean; cap?: number }): Promise<{ exercised: number; discovered: string[] }> {
    const origin = this.page.url();
    const MARK = "verdict-probe";
    const cap = opts.cap ?? 12;
    const discovered = new Set<string>();
    let exercised = 0;
    this.drainApiCalls(); // clear the buffer before starting

    const collect = (before: string): void => {
      const after = this.page.url();
      if (after !== before && opts.allow(after)) discovered.add(after);
      for (const ex of this.drainApiCalls()) {
        if ((ex.resourceType === "xhr" || ex.resourceType === "fetch") && opts.allow(ex.url)) discovered.add(ex.url);
      }
    };

    // (1) forms
    const forms = await this.page.$$("form").catch(() => []);
    for (const form of forms) {
      if (exercised >= cap) break;
      try {
        const method = ((await form.getAttribute("method")) || "get").toLowerCase();
        const action = (await form.getAttribute("action")) || origin;
        let actionUrl = origin;
        try {
          actionUrl = new URL(action, origin).toString();
        } catch {
          /* relative/garbage → treat as origin */
        }
        if (!opts.allow(actionUrl)) continue;
        if (method === "delete" || method === "put" || method === "patch") continue;
        if (method === "post" && !opts.aggressive) continue;
        let filled = false;
        for (const el of await form.$$("input, textarea, select")) {
          const tag = await el.evaluate((n: { tagName: string }) => n.tagName.toLowerCase()).catch(() => "");
          if (tag === "select") {
            await el.selectOption({ index: 1 }).then(() => { filled = true; }).catch(() => {});
            continue;
          }
          const type = ((await el.getAttribute("type")) || "text").toLowerCase();
          if (["password", "file", "hidden", "checkbox", "radio", "submit", "button", "image", "reset"].includes(type)) continue;
          await el.fill(MARK).then(() => { filled = true; }).catch(() => {});
        }
        if (!filled) continue;
        const before = this.page.url();
        const btn = await form.$("button[type=submit], input[type=submit], button");
        if (btn) await btn.click({ timeout: 3000 }).catch(() => {});
        else await form.evaluate((f: { requestSubmit?: () => void; submit: () => void }) => { if (f.requestSubmit) f.requestSubmit(); else f.submit(); }).catch(() => {});
        await this.page.waitForLoadState("networkidle", { timeout: 4000 }).catch(() => {});
        exercised += 1;
        collect(before);
        await this.gotoUrl(origin); // restore
      } catch {
        /* on to the next form */
      }
    }

    // (2) standalone search/text inputs outside a form (SPA search boxes etc. often have no <form>)
    const loose = await this.page.$$("input[type=search], input[type=text]").catch(() => []);
    for (const el of loose) {
      if (exercised >= cap) break;
      try {
        if (await el.evaluate((n: { closest: (s: string) => unknown }) => !!n.closest("form")).catch(() => true)) continue; // inside a form: already handled in (1)
        await el.fill(MARK).catch(() => {});
        const before = this.page.url();
        await el.press("Enter").catch(() => {});
        await this.page.waitForLoadState("networkidle", { timeout: 4000 }).catch(() => {});
        exercised += 1;
        collect(before);
        await this.gotoUrl(origin);
      } catch {
        /* on to the next input */
      }
    }
    return { exercised, discovered: [...discovered] };
  }

  async close(): Promise<void> {
    await this.context.close();
  }
}
