// e2e: BFS-crawl FakeDriver's mock site → dedup → serialize screens/APIs to JSON, and verify
// they auto-enroll in the store's coverage ledger — all without a browser (≈ the M1 completion criteria).

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { FakeDriver, buildInventory, crawl, readScreenInventory, writeScreenInventory } from "./index.js";
import type { FakeSite } from "./index.js";
import { AssessmentStore, coverage, deriveScopeFromSingleUrl, prioritizeScreens } from "@veritas/core";

const SITE: FakeSite = {
  "https://shop.test/": {
    title: "Shop Home",
    domSkeleton: "html>(body>(nav,main))",
    visibleText: "Welcome",
    links: ["/products", "/login"],
  },
  "https://shop.test/products": {
    title: "Products",
    domSkeleton: "html>(body>(ul))",
    links: ["/products/1", "/products/2"],
  },
  "https://shop.test/products/1": {
    title: "Product 1",
    domSkeleton: "html>(body>(article))",
    apiCalls: [
      {
        method: "GET",
        url: "https://shop.test/api/products/1",
        resourceType: "xhr",
        hasAuthorizationHeader: false,
        hasCookieHeader: true,
        requestBody: null,
        status: 200,
        responseBodySample: '{"id":1,"name":"x","price":9.99}',
        responseContentType: "application/json",
      },
    ],
  },
  "https://shop.test/products/2": {
    title: "Product 2",
    domSkeleton: "html>(body>(article))",
    apiCalls: [
      {
        method: "GET",
        url: "https://shop.test/api/products/2",
        resourceType: "xhr",
        hasAuthorizationHeader: false,
        hasCookieHeader: true,
        requestBody: null,
        status: 200,
        responseBodySample: '{"id":2,"name":"y","price":1.5}',
        responseContentType: "application/json",
      },
    ],
  },
  "https://shop.test/login": {
    title: "Login",
    domSkeleton: "html>(body>(form))",
    visibleText: "Enter username and password",
    forms: [
      {
        action: "/login",
        method: "post",
        fields: [
          { name: "username", type: "text" },
          { name: "password", type: "password" },
        ],
      },
    ],
  },
};

test("crawl dedups screens, extracts APIs, and writes screen_inventory.json", async () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-crawl-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    const scope = deriveScopeFromSingleUrl("https://shop.test/");
    store.createAssessment({
      id: "a-test",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 3 },
      scope,
    });

    const result = await crawl(
      { startUrl: "https://shop.test/", scope, followLinks: true, maxDepth: 3 },
      new FakeDriver(SITE),
      { store, assessmentId: "a-test" },
    );

    // 5 pages visited → dedup to 4 screens (home / products / product detail / login)
    assert.equal(result.stats.visited, 5);
    assert.equal(result.stats.screens, 4);

    const detail = result.screens.find((s) => s.urlTemplate === "/products/{id}");
    assert.ok(detail, "product detail screen exists");
    assert.equal(detail.screenType, "detail");
    assert.deepEqual(detail.observedUrls, ["https://shop.test/products/1", "https://shop.test/products/2"]);
    assert.deepEqual(
      detail.apis.map((a) => `${a.method} ${a.urlTemplate}`),
      ["GET /api/products/{id}"],
      "the two product APIs dedup to one template",
    );
    assert.ok(detail.labels.includes("idor-candidate"));

    const login = result.screens.find((s) => s.urlTemplate === "/login");
    assert.equal(login?.screenType, "auth");

    // store integration: phase + all screens auto-enrolled in the coverage ledger
    const state = store.loadAssessment("a-test");
    assert.ok(state);
    assert.equal(state.phase, "phase1_recon");
    assert.equal(state.screens.length, 4);
    assert.equal(state.screenScans.length, 4);
    const cov = coverage(state);
    assert.equal(cov.total, 4);
    assert.equal(cov.byStatus.queued, 4);
    assert.equal(cov.complete, false);

    // priority: login(auth,65) > detail(idor,45) > home(dashboard,12) > products(other,0)
    const tmplById = new Map(state.screens.map((s) => [s.screenId, s.urlTemplate]));
    assert.deepEqual(
      prioritizeScreens(state).map((p) => tmplById.get(p.screenId)),
      ["/login", "/products/{id}", "/", "/products"],
    );

    // screen_inventory.json round-trip
    const invPath = join(dir, "screen_inventory.json");
    writeScreenInventory(invPath, buildInventory(result.startUrl, result.screens));
    const reloaded = readScreenInventory(invPath);
    assert.equal(reloaded.version, 1);
    assert.equal(reloaded.screens.length, 4);
    assert.ok(reloaded.screens.some((s) => s.urlTemplate === "/products/{id}"));

    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("scope gate keeps the crawl on the start origin", async () => {
  const site: FakeSite = {
    "https://in.test/": { domSkeleton: "html>(body>(a))", links: ["https://out.test/secret", "/ok"] },
    "https://in.test/ok": { domSkeleton: "html>(body>(p))" },
  };
  const scope = deriveScopeFromSingleUrl("https://in.test/");
  const result = await crawl(
    { startUrl: "https://in.test/", scope, followLinks: true, maxDepth: 3 },
    new FakeDriver(site),
  );
  assert.equal(result.stats.visited, 2, "out-of-scope link is not followed");
  assert.ok(result.screens.every((s) => !s.observedUrls.some((u) => u.includes("out.test"))));
});
