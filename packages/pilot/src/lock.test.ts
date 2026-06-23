// URL リスト固定(lockToSeeds)の frontier 抑止: ロック時は発見リンクを一切積まない。
// 非ロック時は従来どおり in-scope・非logout・未訪問・非ignore のリンクだけ積む。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { frontierLinks, stripHash } from "./tools.js";
import { deriveScopeFromUrls } from "@veritas/core";

const scope = deriveScopeFromUrls(["https://app.example.com/"], "etld");

function sess(over: Partial<Parameters<typeof frontierLinks>[1]> = {}) {
  return {
    scope,
    lockToSeeds: false,
    visited: new Set<string>(),
    ignorePaths: [] as string[],
    targetUrl: "https://app.example.com/",
    ...over,
  };
}

const obs = {
  finalUrl: "https://app.example.com/dash",
  links: [
    "https://app.example.com/users",
    "https://api.example.com/v1/orders", // sibling subdomain — in scope under etld
    "https://example.org/other", // out of scope
    "/logout", // session-destroying → never enqueued
    "https://app.example.com/dash", // self (will be marked visited)
  ],
};

test("non-locked: enqueues in-scope, non-logout, unvisited links (incl sibling API host)", () => {
  const s = sess({ visited: new Set(["https://app.example.com/dash"]) });
  const got = new Set(frontierLinks(obs, s));
  assert.ok(got.has("https://app.example.com/users"));
  assert.ok(got.has("https://api.example.com/v1/orders")); // etld → API subdomain crawlable
  assert.ok(!got.has("https://example.org/other")); // out of scope
  assert.ok(![...got].some((u) => u.includes("/logout"))); // logout never enqueued
  assert.ok(!got.has("https://app.example.com/dash")); // already visited
});

test("locked: enqueues nothing — survey maps only the seeds, no lateral crawl", () => {
  const s = sess({ lockToSeeds: true });
  assert.deepEqual(frontierLinks(obs, s), []);
});

test("locked stays empty even with brand-new in-scope links", () => {
  const s = sess({ lockToSeeds: true });
  const fresh = { finalUrl: "https://app.example.com/a", links: ["https://app.example.com/b", "https://app.example.com/c"] };
  assert.deepEqual(frontierLinks(fresh, s), []);
});

// ── SPA hash ルーティング ──
test("stripHash keeps SPA routes (#/.., #!/..) but drops plain fragments", () => {
  assert.equal(stripHash("https://x/#/search"), "https://x/#/search"); // route kept
  assert.equal(stripHash("https://x/#!/login"), "https://x/#!/login"); // hashbang route kept
  assert.equal(stripHash("https://x/page#section"), "https://x/page"); // in-page anchor dropped
  assert.equal(stripHash("https://x/page#"), "https://x/page"); // empty fragment dropped
  assert.equal(stripHash("https://x/#/"), "https://x/"); // empty route → base
  assert.equal(stripHash("https://x/dash"), "https://x/dash"); // no hash untouched
});

test("frontier enqueues distinct hash routes (links + captured virtualRoutes)", () => {
  const s = sess();
  const spa = {
    finalUrl: "https://app.example.com/#/",
    links: ["#/search", "#/login", "#top"], // hash-route links + an in-page anchor
    virtualRoutes: ["https://app.example.com/#/basket", "https://app.example.com/#/administration"],
  };
  const got = new Set(frontierLinks(spa, s));
  assert.ok(got.has("https://app.example.com/#/search")); // route link kept distinct
  assert.ok(got.has("https://app.example.com/#/login"));
  assert.ok(got.has("https://app.example.com/#/basket")); // from virtualRoutes
  assert.ok(got.has("https://app.example.com/#/administration"));
  assert.ok(![...got].some((u) => u.includes("#top"))); // plain fragment collapses to base (already visited target? no) — at least not a #top entry
});
