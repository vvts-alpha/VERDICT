// smartLogin: auto-discovery of the login screen/fields + success/failure decision. No browser/LLM needed (Fake).

import { test } from "node:test";
import assert from "node:assert/strict";

import { FakeLlmClient } from "@veritas/llm";
import { heuristicFields, smartLogin } from "./index.js";
import type { LoginDriver } from "./index.js";
import type { PageSnapshot } from "./drivers/playwright.js";
import type { FormObservation } from "./index.js";

function snap(url: string, over: Partial<PageSnapshot> = {}): PageSnapshot {
  return { url, title: "", domSkeleton: "", visibleText: "", links: [], forms: [], virtualRoutes: [], ...over };
}
function loginForm(): FormObservation {
  return { action: "/login", method: "post", fields: [{ name: "username", type: "text" }, { name: "password", type: "password" }] };
}

class FakeLoginDriver implements LoginDriver {
  url = "";
  submitted = false;
  readonly filled: Record<string, string> = {};
  constructor(private readonly resolve: (url: string, submitted: boolean) => PageSnapshot) {}
  async gotoUrl(u: string): Promise<void> {
    this.url = u;
  }
  async snapshot(): Promise<PageSnapshot> {
    return this.resolve(this.url, this.submitted);
  }
  async fill(selector: string, value: string): Promise<boolean> {
    this.filled[selector] = value;
    return true;
  }
  async clickFirst(): Promise<boolean> {
    this.submitted = true;
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

test("smartLogin discovers login via an in-page link and logs in", async () => {
  const driver = new FakeLoginDriver((url, submitted) => {
    if (url === "https://t.test/") return snap(url, { links: ["/about", "/login"] });
    if (url === "https://t.test/login") return submitted ? snap(url, { visibleText: "Welcome to your dashboard" }) : snap(url, { forms: [loginForm()] });
    return snap(url);
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "alice", password: "pw" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, true);
  assert.equal(r.loginUrl, "https://t.test/login");
  assert.equal(driver.filled['[name="password"]'], "pw");
  assert.equal(driver.filled['[name="username"]'], "alice");
});

test("smartLogin discovers login via a common path when no link exists", async () => {
  const driver = new FakeLoginDriver((url, submitted) => {
    if (url === "https://t.test/") return snap(url, { links: ["/about"] });
    if (url === "https://t.test/login") return submitted ? snap(url, { visibleText: "dashboard" }) : snap(url, { forms: [loginForm()] });
    return snap(url);
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, true);
  assert.equal(r.loginUrl, "https://t.test/login");
});

test("smartLogin returns needsHuman on MFA", async () => {
  const driver = new FakeLoginDriver((url, submitted) => {
    if (url === "https://t.test/") return snap(url, { links: ["/login"] });
    if (url === "https://t.test/login")
      return submitted
        ? snap(url, { visibleText: "Enter the verification code from your authenticator app" })
        : snap(url, { forms: [loginForm()] });
    return snap(url);
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.equal(r.needsHuman, true);
});

test("smartLogin reports bad credentials when still on the login form", async () => {
  const driver = new FakeLoginDriver((url) => {
    if (url === "https://t.test/") return snap(url, { links: ["/login"] });
    return snap(url, { forms: [loginForm()] }); // login form persists even after submit
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, { targetUrl: "https://t.test/" });
  assert.equal(r.ok, false);
  assert.equal(r.needsHuman, false);
  assert.match(r.reason, /still on a login form/);
});

test("smartLogin uses the Phase1 auth-screen url first", async () => {
  let visitedLoginScreen = false;
  const driver = new FakeLoginDriver((url, submitted) => {
    if (url === "https://t.test/account/sign_in") {
      visitedLoginScreen = true;
      return submitted ? snap(url, { visibleText: "home" }) : snap(url, { forms: [loginForm()] });
    }
    return snap(url, { links: [] });
  });
  const r = await smartLogin(driver, new FakeLlmClient("{}"), { username: "a", password: "b" }, {
    targetUrl: "https://t.test/",
    loginScreenUrl: "https://t.test/account/sign_in",
  });
  assert.equal(r.ok, true);
  assert.equal(visitedLoginScreen, true);
});
