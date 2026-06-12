import assert from "node:assert/strict";
import { test } from "node:test";
import { FakeLlmClient } from "@veritas/llm";
import { exploreScreen } from "./explore.js";
import type { ExploreDriver } from "./explore.js";
import type { CapturedExchange } from "./types.js";
import type { PageSnapshot } from "./drivers/playwright.js";

const snapWith = (forms: PageSnapshot["forms"]): PageSnapshot => ({
  url: "https://shop.test/catalog",
  title: "",
  domSkeleton: "",
  visibleText: "",
  links: [],
  forms,
  virtualRoutes: [],
});

const api = (url: string): CapturedExchange => ({
  method: "GET",
  url,
  resourceType: "fetch",
  hasAuthorizationHeader: false,
  hasCookieHeader: false,
  requestBody: null,
  status: 200,
  responseBodySample: "[]",
  responseContentType: "application/json",
});

class FakeExploreDriver implements ExploreDriver {
  url = "https://shop.test/catalog";
  filled: Record<string, string> = {};
  clicked = 0;
  private pending: CapturedExchange[] = [];
  constructor(
    private readonly snap: PageSnapshot,
    private readonly onSubmit: () => { apis: CapturedExchange[]; navTo?: string },
  ) {}
  async gotoUrl(u: string): Promise<void> { this.url = u; }
  async snapshot(): Promise<PageSnapshot> { return this.snap; }
  async fill(selector: string, value: string): Promise<boolean> {
    const m = selector.match(/name="([^"]+)"/);
    if (m?.[1]) this.filled[m[1]] = value;
    return true;
  }
  async clickFirst(): Promise<boolean> {
    this.clicked += 1;
    const r = this.onSubmit();
    this.pending.push(...r.apis);
    if (r.navTo) this.url = r.navTo;
    return true;
  }
  async pressEnter(): Promise<void> {}
  drainApiCalls(): CapturedExchange[] { const o = this.pending.slice(); this.pending = []; return o; }
  currentUrl(): string { return this.url; }
}

test("exploreScreen submits an LLM-planned form and captures the fired API + new URL", async () => {
  const snap = snapWith([{ action: "/search", method: "get", fields: [{ name: "q", type: "text" }] }]);
  const driver = new FakeExploreDriver(snap, () => ({
    apis: [api("https://shop.test/api/search?q=shoe")],
    navTo: "https://shop.test/search?q=shoe",
  }));
  const llm = new FakeLlmClient(JSON.stringify({ actions: [{ formIndex: 0, values: { q: "shoe" } }] }));

  const res = await exploreScreen(driver, llm);

  assert.equal(driver.filled["q"], "shoe", "used the LLM-chosen value");
  assert.equal(driver.clicked, 1);
  assert.equal(res.firedApis.length, 1);
  assert.equal(res.firedApis[0]?.url, "https://shop.test/api/search?q=shoe");
  assert.deepEqual(res.newUrls, ["https://shop.test/search?q=shoe"]);
});

test("exploreScreen falls back to submitting forms with test values on bad LLM output", async () => {
  const snap = snapWith([{ action: "/filter", method: "get", fields: [{ name: "category", type: "text" }] }]);
  const driver = new FakeExploreDriver(snap, () => ({ apis: [] }));
  const res = await exploreScreen(driver, new FakeLlmClient("not json at all"));

  assert.equal(driver.filled["category"], "veritas-test", "filled a synthetic test value");
  assert.equal(driver.clicked, 1);
  assert.deepEqual(res.actions, ["submit form#0 get /filter"]);
});

test("exploreScreen no-ops on a page without forms", async () => {
  const driver = new FakeExploreDriver(snapWith([]), () => ({ apis: [api("x")] }));
  const res = await exploreScreen(driver, new FakeLlmClient("{}"));
  assert.equal(driver.clicked, 0);
  assert.equal(res.firedApis.length, 0);
});
