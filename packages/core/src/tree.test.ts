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

  // top-level: "/", "login", "products"(セグメント名でソート)
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
    screen("s-0004", "/login", "auth", ["https://api.example.com/login"]), // 別ドメインの同名パスは混ざらない
  ];
  const tree = buildSiteTree(screens, []);

  // トップ = ドメイン(ソート順)
  assert.deepEqual(
    tree.map((n) => n.segment),
    ["api.example.com", "app.example.com"],
  );

  const app = tree.find((n) => n.segment === "app.example.com");
  assert.equal(app?.screenId, "s-0001", "ルート(/)画面はドメインノードに直付け");
  assert.deepEqual(app?.children.map((c) => c.segment), ["login"]);

  const api = tree.find((n) => n.segment === "api.example.com");
  // 同名 /login が別ドメイン配下に独立して存在(path はホストで一意化)
  assert.equal(api?.children.find((c) => c.segment === "login")?.path, "api.example.com/login");
  assert.equal(app?.children.find((c) => c.segment === "login")?.path, "app.example.com/login");
});

test("buildSiteTree stays a flat path forest for a single host", () => {
  const screens = [
    screen("s-0001", "/", "dashboard", ["https://app.example.com/"]),
    screen("s-0002", "/products", "listing", ["https://app.example.com/products"]),
  ];
  const tree = buildSiteTree(screens, []);
  assert.deepEqual(tree.map((n) => n.segment), ["/", "products"], "単一ドメインはドメイン段を足さない");
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
