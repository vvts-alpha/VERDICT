import { test } from "node:test";
import assert from "node:assert/strict";

import { InventoryBuilder, buildScreenFromObservation } from "./index.js";
import type { CapturedExchange, Observation } from "./index.js";

function obs(over: Partial<Observation> & { finalUrl: string }): Observation {
  return {
    requestedUrl: over.finalUrl,
    finalUrl: over.finalUrl,
    status: 200,
    title: over.title ?? "",
    domSkeleton: over.domSkeleton ?? "html>(body)",
    visibleText: over.visibleText ?? "",
    forms: over.forms ?? [],
    links: over.links ?? [],
    virtualRoutes: over.virtualRoutes ?? [],
    apiCalls: over.apiCalls ?? [],
    scripts: over.scripts ?? [],
  };
}

const productApi: CapturedExchange = {
  method: "GET",
  url: "https://shop.test/api/products/1",
  resourceType: "xhr",
  hasAuthorizationHeader: false,
  hasCookieHeader: true,
  requestBody: null,
  status: 200,
  responseBodySample: '{"id":1,"price":9.99}',
  responseContentType: "application/json",
};

test("buildScreenFromObservation derives template, params, apis, labels", () => {
  const built = buildScreenFromObservation(
    obs({ finalUrl: "https://shop.test/products/1", domSkeleton: "html>(body>(article))", apiCalls: [productApi] }),
  );
  assert.equal(built.screen.urlTemplate, "/products/{id}");
  assert.equal(built.screen.screenType, "detail");
  assert.deepEqual(
    built.screen.params.map((p) => `${p.name}:${p.guessedType}`),
    ["id:object_ref"],
  );
  assert.deepEqual(
    built.screen.apis.map((a) => `${a.method} ${a.urlTemplate}`),
    ["GET /api/products/{id}"],
  );
  assert.ok(built.screen.labels.includes("idor-candidate"));
});

test("InventoryBuilder dedups by (template, domSkeletonHash) and merges observed urls", () => {
  const inv = new InventoryBuilder();
  const a = inv.ingest(obs({ finalUrl: "https://shop.test/products/1", domSkeleton: "html>(body>(article))", apiCalls: [productApi] }));
  const b = inv.ingest(
    obs({
      finalUrl: "https://shop.test/products/2",
      domSkeleton: "html>(body>(article))",
      apiCalls: [{ ...productApi, url: "https://shop.test/api/products/2" }],
    }),
  );
  assert.equal(a.isNew, true);
  assert.equal(b.isNew, false, "same template+skeleton dedups");
  assert.equal(a.screen.screenId, "s-0001");
  assert.deepEqual(b.screen.observedUrls, ["https://shop.test/products/1", "https://shop.test/products/2"]);
  assert.equal(b.screen.apis.length, 1, "GET /api/products/{id} merged once");
  assert.equal(inv.screens().length, 1);
});

test("different DOM skeleton at same URL is a separate screen (SPA case)", () => {
  const inv = new InventoryBuilder();
  inv.ingest(obs({ finalUrl: "https://app.test/home", domSkeleton: "html>(body>(div))" }));
  inv.ingest(obs({ finalUrl: "https://app.test/home", domSkeleton: "html>(body>(table))" }));
  assert.equal(inv.screens().length, 2);
});

test("InventoryBuilder collapses list/detail pages differing only by item count (blog /post?id=N)", () => {
  const inv = new InventoryBuilder();
  // Same /post template. The skeleton differs only in the *count* of comments/paragraphs (structure is the same).
  const p1 = inv.ingest(obs({ finalUrl: "https://blog.test/post?postId=1", domSkeleton: "html>(body>(article>(h1,p,p,section>(div,div,div,div,div))))" }));
  const p2 = inv.ingest(obs({ finalUrl: "https://blog.test/post?postId=2", domSkeleton: "html>(body>(article>(h1,p,p,p,section>(div))))" }));
  assert.equal(p1.isNew, true);
  assert.equal(p2.isNew, false, "only item counts differ → same screen (no /post explosion)");
  assert.equal(inv.screens().length, 1);
  assert.deepEqual(p2.screen.observedUrls, ["https://blog.test/post?postId=1", "https://blog.test/post?postId=2"]);
});

test("2nd pass (seeded) dedups public pages by url-template despite DOM change (P1)", () => {
  // 1st pass (unauth): /catalog with a "login" navbar
  const first = new InventoryBuilder();
  first.ingest(obs({ finalUrl: "https://shop.test/catalog", domSkeleton: "html>(body>(navlogin,ul))" }));

  // 2nd pass (post-login): seed with unauth screens, re-crawl /catalog with a DIFFERENT navbar
  const second = new InventoryBuilder();
  second.seed(first.screens());
  const reCatalog = second.ingest(
    obs({ finalUrl: "https://shop.test/catalog", domSkeleton: "html>(body>(navlogout,ul))" }),
    "post-login",
  );
  assert.equal(reCatalog.isNew, false, "same url-template merges — no duplicate public page");

  const dash = second.ingest(obs({ finalUrl: "https://shop.test/dashboard", domSkeleton: "html>(body>(main))" }), "post-login");
  assert.equal(dash.isNew, true, "genuinely new url-template is auth-only");
  assert.equal(second.screens().length, 2, "catalog (deduped) + dashboard");
});

test("buildScreenFromObservation surfaces APIs from scripts + form actions (server-rendered apps)", () => {
  const built = buildScreenFromObservation(
    obs({
      finalUrl: "https://shop.test/products/p101",
      scripts: ["fetch('/api/products/p101').then(r=>r.json()); axios.post('/api/cart',{})"],
      forms: [{ action: "/search", method: "get", fields: [{ name: "q", type: "text" }] }],
    }),
  );
  const keys = built.screen.apis.map((a) => `${a.method} ${a.urlTemplate}`);
  assert.ok(keys.includes("GET /api/products/{id}"), "script-referenced API surfaced (slug id templated)");
  assert.ok(keys.includes("POST /api/cart"), "axios API surfaced");
  assert.ok(keys.includes("GET /search"), "form action endpoint surfaced");
});

test("a plain HTML form POST becomes a first-class API with reqSchema from its fields (not just XHR)", () => {
  const built = buildScreenFromObservation(
    obs({
      finalUrl: "https://shop.test/login",
      forms: [
        {
          action: "/sessions",
          method: "post",
          fields: [
            { name: "email", type: "email" },
            { name: "password", type: "password" },
            { name: "remember", type: "checkbox" },
            { name: "attempts", type: "number" },
          ],
        },
        // a GET form has no body (fields go in the query) → no reqSchema
        { action: "/search", method: "get", fields: [{ name: "q", type: "text" }] },
      ],
    }),
  );
  const post = built.screen.apis.find((a) => a.method === "POST" && a.urlTemplate === "/sessions");
  assert.ok(post, "form POST endpoint is an ApiCall");
  assert.equal(post!.reqSchema?.type, "object");
  const fields = post!.reqSchema?.type === "object" ? post!.reqSchema.fields : {};
  assert.equal(fields.email?.type, "string");
  assert.equal(fields.password?.type, "string");
  assert.equal(fields.remember?.type, "boolean"); // checkbox → boolean
  assert.equal(fields.attempts?.type, "number"); // number → number
  // a GET form has no body schema
  const get = built.screen.apis.find((a) => a.method === "GET" && a.urlTemplate === "/search");
  assert.equal(get!.reqSchema, null);
});
