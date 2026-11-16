// smartLogin: structural login-widget detection + LLM-guided discovery. No browser/real LLM needed (Fake).

import { test } from "node:test";
import assert from "node:assert/strict";

import { FakeLlmClient } from "@veritas/llm";
import { heuristicFields, smartLogin } from "./index.js";
import type { LoginDriver } from "./index.js";
import type { PageSnapshot } from "./drivers/playwright.js";
import type { FormObservation, InputObservation } from "./index.js";

function snap(url: string, over: Partial<PageSnapshot> = {}): PageSnapshot {
  return { url, title: "", domSkeleton: "html>(body)", visibleText: "", links: [], forms: [], virtualRoutes: [], ...over };
}
function loginForm(): FormObservation {
  return { action: "/login", method: "post", fields: [{ name: "username", type: "text" }, { name: "password", type: "password" }] };
}
const inp = (over: Partial<InputObservation>): InputObservation => ({
  selector: "", name: "", id: "", type: "text", label: "", autocomplete: "", ...over,
});

interface FakePages {
  [url: string]: (submitted: boolean) => PageSnapshot;
}

/** URL/click-keyed fake browser: gotoUrl switches page; clickFirst(selector) can remap to another page.
 *  onClick is per-page: selectors unmapped on the CURRENT page count as a successful submit. */
class FakeLoginDriver implements LoginDriver {
  url = "";
  submitted = false;
  readonly filled: Record<string, string> = {};
  readonly clicks: string[] = [];
  constructor(
    private readonly pages: FakePages,
    private readonly onClick: Record<string, Record<string, string>> = {},
  ) {}
  async gotoUrl(u: string): Promise<void> {
    this.url = u;
  }
  async snapshot(): Promise<PageSnapshot> {
    return (this.pages[this.url] ?? (() => snap(this.url)))(this.submitted);
  }
  async fill(selector: string, value: string): Promise<boolean> {
    this.filled[selector] = value;
    return true;
  }
  async clickFirst(selectors: string[]): Promise<boolean> {
    const pageMap = this.onClick[this.url] ?? {};
    for (const s of selectors) {
      this.clicks.push(s);
      if (pageMap[s]) {
        this.url = pageMap[s]!;
        return true;
      }
    }
    this.submitted = true; // no selector remapped → the click "worked" (submit path)
    return true;
  }
  async pressEnter(): Promise<void> {
    this.submitted = true;
  }
}

test("heuristicFields maps username + password from a form", () => {
  assert.deepEqual(
    heuristicFields({ action: null, method: "post", fields: [{ name: "email", type: "text" }, { name: "password", type: "password" }] }),
    { username: "email", password: "password" },
  );
});

test("smartLogin logs in when the login page is reached via an LLM-picked link", async () => {
  const driver = new FakeLoginDriver({
    "https://t.test/": () => snap("https://t.test/", { links: ["/about", "/login"] }),
    "https://t.test/login": (s) => (s ? snap("https://t.test/", { visibleText: "Welcome to your dashboard" }) : snap("https://t.test/login", { forms: [loginForm()] })),
  });
  const llm = new FakeLlmClient(['{"action":"goto","url":"/login"}']);
  const r = await smartLogin(driver, llm, { username: "alice", password: "pw" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, true);
  assert.equal(r.loginUrl, "https://t.test/login");
  assert.equal(driver.filled['[name="password"]'], "pw");
  assert.equal(driver.filled['[name="username"]'], "alice");
});

test("smartLogin reaches a hash-routed SPA login (no <form> needed, id-only inputs)", async () => {
  // Juice Shop shape: /#/login, a <form> exists but its inputs have NO name — only ids.
  const driver = new FakeLoginDriver({
    "http://shop.test/": () => snap("http://shop.test/", { links: ["#/register"], visibleText: "OWASP Juice Shop" }),
    "http://shop.test/#/login": (s) =>
      s
        ? snap("http://shop.test/#/", { visibleText: "Your Basket" })
        : snap("http://shop.test/#/login", {
            forms: [{ action: null, method: "get", fields: [] }], // nameless fields filtered out at capture
            inputs: [
              inp({ selector: "#email", id: "email", type: "email", label: "Text field for the login email" }),
              inp({ selector: "#password", id: "password", type: "password", label: "Text field for the login password" }),
            ],
            clickables: [{ text: "Log in", selector: "#loginButton" }],
          }),
  });
  const llm = new FakeLlmClient(['{"action":"goto","url":"#/login"}']);
  const r = await smartLogin(driver, llm, { username: "a@b.c", password: "pw" }, { targetUrl: "http://shop.test/" });
  assert.equal(r.ok, true, r.reason);
  assert.equal(driver.filled["#email"], "a@b.c");
  assert.equal(driver.filled["#password"], "pw");
});

test("smartLogin clicks through a revealed menu to reach the login page", async () => {
  // Login lives behind a lazy menu: no link in the DOM until the menu is opened.
  const driver = new FakeLoginDriver(
    {
      "https://t.test/": () => snap("https://t.test/", { clickables: [{ text: "Account", selector: "#account-btn" }] }),
      "https://t.test/menu": () => snap("https://t.test/", { clickables: [{ text: "Account", selector: "#account-btn" }, { text: "Sign in", selector: "#login-item" }] }),
      "https://t.test/#/login": (s) =>
        s
          ? snap("https://t.test/#/", { visibleText: "home" })
          : snap("https://t.test/#/login", {
              inputs: [inp({ selector: "#u", id: "u", type: "email" }), inp({ selector: "#p", id: "p", type: "password" })],
            }),
    },
    { "https://t.test/": { "#account-btn": "https://t.test/menu" }, "https://t.test/menu": { "#login-item": "https://t.test/#/login" } },
  );
  const llm = new FakeLlmClient(['{"action":"click","selector":"#account-btn"}', '{"action":"click","selector":"#login-item"}']);
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, true, r.reason);
  assert.deepEqual(driver.clicks.slice(0, 2), ["#account-btn", "#login-item"]);
});

test("smartLogin drives a username-first (multi-step) flow via fill_user", async () => {
  // Step 1 has only an identifier input; the model calls fill_user → the fake's submit-click navigates to step 2.
  const driver = new FakeLoginDriver(
    {
      "https://idp.test/": () =>
        snap("https://idp.test/", {
          inputs: [inp({ selector: "#ident", id: "ident", type: "text", label: "Email or username" })],
          clickables: [{ text: "Next", selector: "#next" }],
        }),
      "https://idp.test/step2": (s) =>
        s
          ? snap("https://idp.test/done", { visibleText: "signed in" })
          : snap("https://idp.test/step2", { inputs: [inp({ selector: "#pw", id: "pw", type: "password" })] }),
    },
    { "https://idp.test/": { 'button[type="submit"]': "https://idp.test/step2" } },
  );
  const llm = new FakeLlmClient(['{"action":"fill_user","selector":"#ident"}']);
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://idp.test/" });
  assert.equal(r.ok, true, r.reason);
  assert.equal(driver.filled["#ident"], "a");
  assert.equal(driver.filled["#pw"], "b");
});

test("smartLogin reports unreachable when the page never loads", async () => {
  const driver = new FakeLoginDriver({
    "http://dead.test/": () => snap("about:blank", { domSkeleton: "empty" }),
    "about:blank": () => snap("about:blank", { domSkeleton: "empty" }),
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, { targetUrl: "http://dead.test/" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /cannot reach/);
});

test("smartLogin returns needsHuman on MFA", async () => {
  const driver = new FakeLoginDriver({
    "https://t.test/": () => snap("https://t.test/", { links: ["/login"] }),
    "https://t.test/login": (s) =>
      s
        ? snap("https://t.test/login", { visibleText: "Enter the verification code from your authenticator app" })
        : snap("https://t.test/login", { forms: [loginForm()] }),
  });
  const llm = new FakeLlmClient(['{"action":"goto","url":"/login"}']);
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.equal(r.needsHuman, true);
});

test("smartLogin reports bad credentials when still on the login form", async () => {
  const driver = new FakeLoginDriver({
    "https://t.test/": () => snap("https://t.test/", { links: ["/login"] }),
    "https://t.test/login": () => snap("https://t.test/login", { forms: [loginForm()] }), // form persists after submit
  });
  const llm = new FakeLlmClient(['{"action":"goto","url":"/login"}']);
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.equal(r.needsHuman, false);
  assert.match(r.reason, /still on a login form/);
});

test("smartLogin fails honestly when the LLM finds no route", async () => {
  const driver = new FakeLoginDriver({
    "https://t.test/": () => snap("https://t.test/", { links: ["/about"], visibleText: "marketing page" }),
  });
  const llm = new FakeLlmClient(['{"action":"stop"}']);
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no login form found/);
});

test("smartLogin tolerates unparseable LLM output", async () => {
  const driver = new FakeLoginDriver({
    "https://t.test/": () => snap("https://t.test/", { links: ["/about"] }),
  });
  const llm = new FakeLlmClient("total garbage, not json");
  const r = await smartLogin(driver, llm, { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.match(r.reason, /no login form found/);
});

test("smartLogin uses the Phase1 auth-screen url first", async () => {
  let visitedLoginScreen = false;
  const driver = new FakeLoginDriver({
    "https://t.test/account/sign_in": (s) => {
      visitedLoginScreen = true;
      return s ? snap("https://t.test/", { visibleText: "home" }) : snap("https://t.test/account/sign_in", { forms: [loginForm()] });
    },
    "https://t.test/": () => snap("https://t.test/", { links: [] }),
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, {
    targetUrl: "https://t.test/",
    loginScreenUrl: "https://t.test/account/sign_in",
  });
  assert.equal(r.ok, true);
  assert.equal(visitedLoginScreen, true);
});
