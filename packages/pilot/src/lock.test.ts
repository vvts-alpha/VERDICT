// URL リスト固定(lockToSeeds)の frontier 抑止: ロック時は発見リンクを一切積まない。
// 非ロック時は従来どおり in-scope・非logout・未訪問・非ignore のリンクだけ積む。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { frontierLinks } from "./tools.js";
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
