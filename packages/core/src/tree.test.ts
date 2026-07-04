import { test } from "node:test";
import assert from "node:assert/strict";

import { buildSiteTree, buildStateView } from "./index.js";
import { AssessmentStore, deriveScopeFromSingleUrl } from "./index.js";
import type { Screen } from "./index.js";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

function screen(
  id: string,
  urlTemplate: string,
  screenType: Screen["screenType"] = "other",
  observedUrls: string[] = [],
): Screen {
  return {
    screenId: id,
    urlTemplate,
    observedUrls,
    authState: "unauth",
    screenType,
    description: "",
    params: [],
    apis: [],
    screenshot: "",
    domSkeletonHash: id,
    labels: [],
  };
}

test("buildSiteTree folds urlTemplates into a hierarchy with scan badges", () => {
  const screens = [
    screen("s-0001", "/", "dashboard"),
    screen("s-0002", "/products", "listing"),
    screen("s-0003", "/products/{id}", "detail"),
    screen("s-0004", "/login", "auth"),
  ];
  const scans = [
    { screenId: "s-0003", status: "finding" as const, attempts: 0, hypothesisIds: [], findingIds: ["f-1"], lastError: null, updatedAt: "" },
  ];
  const tree = buildSiteTree(screens, scans);

  // top-level: "/", "login", "products" (sorted by segment name)
  assert.deepEqual(tree.map((n) => n.segment), ["/", "login", "products"]);

  const products = tree.find((n) => n.segment === "products");
  assert.equal(products?.path, "/products");
  assert.equal(products?.screenId, "s-0002");
  assert.equal(products?.children.length, 1);

  const detail = products?.children[0];
  assert.equal(detail?.segment, "{id}");
  assert.equal(detail?.path, "/products/{id}");
  assert.equal(detail?.screenType, "detail");
  assert.equal(detail?.scanStatus, "finding", "badge comes from the coverage ledger");
});

test("buildSiteTree groups by domain when screens span ≥2 hosts", () => {
  const screens = [
    screen("s-0001", "/", "dashboard", ["https://app.example.com/"]),
    screen("s-0002", "/login", "auth", ["https://app.example.com/login"]),
    screen("s-0003", "/v1/users/{id}", "detail", ["https://api.example.com/v1/users/42"]),
    screen("s-0004", "/login", "auth", ["https://api.example.com/login"]), // same-named path on a different domain doesn't merge
  ];
  const tree = buildSiteTree(screens, []);

  // Top = domain (sorted)
  assert.deepEqual(
    tree.map((n) => n.segment),
    ["api.example.com", "app.example.com"],
  );

  const app = tree.find((n) => n.segment === "app.example.com");
  assert.equal(app?.screenId, "s-0001", "the root (/) screen attaches directly to the domain node");
  assert.deepEqual(app?.children.map((c) => c.segment), ["login"]);

  const api = tree.find((n) => n.segment === "api.example.com");
  // The same-named /login exists independently under each domain (path uniqued by host)
  assert.equal(api?.children.find((c) => c.segment === "login")?.path, "api.example.com/login");
  assert.equal(app?.children.find((c) => c.segment === "login")?.path, "app.example.com/login");
});

test("buildSiteTree stays a flat path forest for a single host", () => {
  const screens = [
    screen("s-0001", "/", "dashboard", ["https://app.example.com/"]),
    screen("s-0002", "/products", "listing", ["https://app.example.com/products"]),
  ];
  const tree = buildSiteTree(screens, []);
  assert.deepEqual(tree.map((n) => n.segment), ["/", "products"], "a single domain doesn't add a domain level");
});

test("buildSiteTree branches SPA hash routes recovered from observedUrls", () => {
  // Same pathname `/app` but different hash routes → URL can't separate them, but we want them branched
  const screens = [
    screen("s-0001", "/app", "dashboard", ["https://app.example.com/app#/"]),
    screen("s-0002", "/app", "listing", ["https://app.example.com/app#/admin/users"]),
    screen("s-0003", "/app", "detail", ["https://app.example.com/app#/admin/users/42"]),
  ];
  const tree = buildSiteTree(screens, []);
  const app = tree.find((n) => n.segment === "app");
  assert.ok(app, "the /app node exists");
  const admin = app!.children.find((n) => n.segment === "#admin");
  assert.ok(admin, "the hash route #admin becomes a branch");
  const users = admin!.children.find((n) => n.segment === "users");
  assert.ok(users, "#admin/users");
  assert.equal(users!.screenId, "s-0002");
  // Id-like hash segments collapse to {id}
  assert.ok(users!.children.some((n) => n.segment === "{id}" && n.screenId === "s-0003"), "#admin/users/{id}");
});

test("buildSiteTree branches URL-stable (pure-state) SPA screens via skeleton tag", () => {
  // No hash and identical pathname (a state-driven SPA whose URL never changes). Branch by DOM-skeleton hash.
  const screens = [
    screen("s-0001", "/console", "dashboard", ["https://app.example.com/console"]),
    screen("s-0002", "/console", "listing", ["https://app.example.com/console"]),
  ];
  const tree = buildSiteTree(screens, []);
  const console_ = tree.find((n) => n.segment === "console");
  assert.ok(console_, "the /console node exists");
  assert.equal(console_!.screenId, null, "a collided parent carries no screen");
  assert.equal(console_!.children.length, 2, "the two state views branch by ~tag");
  const tags = console_!.children.map((n) => n.segment).sort();
  assert.deepEqual(tags, ["~s-0001", "~s-0002"], "uniqued by a short id derived from domSkeletonHash");
  assert.deepEqual(
    console_!.children.map((n) => n.screenId).sort(),
    ["s-0001", "s-0002"],
  );
});

test("buildStateView projects AssessmentState for the UI", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-view-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-1",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    store.upsertScreen("a-1", screen("s-0001", "/orders/{id}", "detail"));
    const view = buildStateView(store.loadAssessment("a-1")!);
    assert.equal(view.phase, "init");
    assert.equal(view.coverage.total, 1);
    assert.equal(view.tree.length, 1);
    assert.equal(view.tree[0]?.segment, "orders");
    assert.ok(view.lastSeq >= 1);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
