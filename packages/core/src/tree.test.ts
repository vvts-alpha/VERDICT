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

test("buildSiteTree branches SPA hash routes recovered from observedUrls", () => {
  // 同一 pathname `/app` だが hash route が違う → URL では分離できないが枝分かれさせたい
  const screens = [
    screen("s-0001", "/app", "dashboard", ["https://app.example.com/app#/"]),
    screen("s-0002", "/app", "listing", ["https://app.example.com/app#/admin/users"]),
    screen("s-0003", "/app", "detail", ["https://app.example.com/app#/admin/users/42"]),
  ];
  const tree = buildSiteTree(screens, []);
  const app = tree.find((n) => n.segment === "app");
  assert.ok(app, "/app ノードが存在");
  const admin = app!.children.find((n) => n.segment === "#admin");
  assert.ok(admin, "hash route #admin が枝になる");
  const users = admin!.children.find((n) => n.segment === "users");
  assert.ok(users, "#admin/users");
  assert.equal(users!.screenId, "s-0002");
  // id っぽい hash セグメントは {id} に畳む
  assert.ok(users!.children.some((n) => n.segment === "{id}" && n.screenId === "s-0003"), "#admin/users/{id}");
});

test("buildSiteTree branches URL-stable (pure-state) SPA screens via skeleton tag", () => {
  // hash も無く pathname も同一(URL が一切変わらない state 駆動 SPA)。DOM 骨格 hash で枝分かれ。
  const screens = [
    screen("s-0001", "/console", "dashboard", ["https://app.example.com/console"]),
    screen("s-0002", "/console", "listing", ["https://app.example.com/console"]),
  ];
  const tree = buildSiteTree(screens, []);
  const console_ = tree.find((n) => n.segment === "console");
  assert.ok(console_, "/console ノードが存在");
  assert.equal(console_!.screenId, null, "衝突した親には screen を載せない");
  assert.equal(console_!.children.length, 2, "2 つの state ビューが ~tag で枝分かれ");
  const tags = console_!.children.map((n) => n.segment).sort();
  assert.deepEqual(tags, ["~s-0001", "~s-0002"], "domSkeletonHash 由来の短縮子で一意化");
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
