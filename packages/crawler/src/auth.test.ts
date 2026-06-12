// 詰まり検出 + クロール中のハンドオフ起票(non-blocking)+ pause 停止。

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { FakeDriver, crawl, detectStuck } from "./index.js";
import type { FakeSite, Observation } from "./index.js";

function obs(over: Partial<Observation>): Observation {
  return {
    requestedUrl: "https://x/", finalUrl: over.finalUrl ?? "https://x/", status: over.status ?? 200,
    title: "", domSkeleton: over.domSkeleton ?? "html>(body)", visibleText: over.visibleText ?? "",
    forms: [], links: [], virtualRoutes: [], apiCalls: [],
  };
}

test("detectStuck flags captcha / challenge / mfa / 429, else null", () => {
  assert.equal(detectStuck(obs({ visibleText: "Please verify you are human" }))?.reason, "captcha");
  assert.equal(detectStuck(obs({ finalUrl: "https://x/account/challenge?x=1" }))?.reason, "captcha");
  assert.equal(detectStuck(obs({ visibleText: "Enter the verification code from your authenticator app" }))?.reason, "auth");
  assert.equal(detectStuck(obs({ status: 429 }))?.reason, "rate_limit");
  assert.equal(detectStuck(obs({ visibleText: "Welcome to the shop" })), null);
});

test("crawl raises a HumanHandoff on a captcha wall and keeps exploring (non-blocking)", async () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-auth-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    const scope = deriveScopeFromSingleUrl("https://shop.test/");
    store.createAssessment({
      id: "a-1",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 3 },
      scope,
    });
    const site: FakeSite = {
      "https://shop.test/": { domSkeleton: "html>(body>(nav))", links: ["/login", "/about"] },
      "https://shop.test/login": { domSkeleton: "html>(body>(form))", visibleText: "Sign in — I'm not a robot" },
      "https://shop.test/about": { domSkeleton: "html>(body>(article))", visibleText: "About us" },
    };
    const result = await crawl(
      { startUrl: "https://shop.test/", scope, followLinks: true, maxDepth: 3 },
      new FakeDriver(site),
      { store, assessmentId: "a-1" },
    );

    assert.equal(result.stats.handoffs, 1, "captcha login raised one handoff");
    assert.equal(result.stats.screens, 3, "home + login + about still mapped (non-blocking)");

    const state = store.loadAssessment("a-1");
    assert.ok(state);
    const ho = state.handoffs.find((h) => h.status === "pending");
    assert.ok(ho);
    assert.equal(ho.reason, "captcha");
    assert.equal(ho.url, "https://shop.test/login");
    assert.ok(state.events.some((e) => e.type === "handoff_requested"));
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("crawl stops early when paused", async () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-auth-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    const scope = deriveScopeFromSingleUrl("https://shop.test/");
    store.createAssessment({
      id: "a-2",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 3 },
      scope,
    });
    store.setPaused("a-2", true, "operator paused");
    const result = await crawl(
      { startUrl: "https://shop.test/", scope, followLinks: true, maxDepth: 3 },
      new FakeDriver({ "https://shop.test/": { links: ["/a"] } }),
      { store, assessmentId: "a-2" },
    );
    assert.equal(result.stats.stopReason, "paused");
    assert.equal(result.stats.visited, 0);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
