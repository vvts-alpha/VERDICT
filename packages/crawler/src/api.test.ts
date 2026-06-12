import { test } from "node:test";
import assert from "node:assert/strict";

import { extractApiRefs, inferApiCall, inferJsonShape, isApiExchange } from "./index.js";
import type { CapturedExchange } from "./index.js";

function ex(over: Partial<CapturedExchange> = {}): CapturedExchange {
  return {
    method: "get",
    url: "https://e.com/api/orders/42",
    resourceType: "xhr",
    hasAuthorizationHeader: false,
    hasCookieHeader: false,
    requestBody: null,
    status: 200,
    responseBodySample: null,
    responseContentType: null,
    ...over,
  };
}

test("inferApiCall normalises path, masks auth, infers schema", () => {
  const api = inferApiCall(
    ex({
      method: "post",
      url: "https://e.com/api/orders/42?expand=items",
      hasAuthorizationHeader: true,
      requestBody: '{"qty":2}',
      responseContentType: "application/json; charset=utf-8",
      responseBodySample: '{"id":42,"items":[{"sku":"x"}]}',
    }),
  );
  assert.equal(api.method, "POST");
  assert.equal(api.urlTemplate, "/api/orders/{id}");
  assert.equal(api.auth, "bearer");
  assert.deepEqual(api.reqSchema, { type: "object", fields: { qty: { type: "number" } } });
  assert.deepEqual(api.resSchema, {
    type: "object",
    fields: {
      id: { type: "number" },
      items: { type: "array", items: { type: "object", fields: { sku: { type: "string" } } } },
    },
  });
});

test("auth detection prefers bearer, then cookie, else none", () => {
  assert.equal(inferApiCall(ex({ hasAuthorizationHeader: true, hasCookieHeader: true })).auth, "bearer");
  assert.equal(inferApiCall(ex({ hasCookieHeader: true })).auth, "cookie");
  assert.equal(inferApiCall(ex()).auth, "none");
});

test("non-json responses yield null resSchema", () => {
  const api = inferApiCall(ex({ responseContentType: "text/html", responseBodySample: "<html>" }));
  assert.equal(api.resSchema, null);
});

test("isApiExchange only accepts xhr/fetch", () => {
  assert.equal(isApiExchange(ex({ resourceType: "xhr" })), true);
  assert.equal(isApiExchange(ex({ resourceType: "fetch" })), true);
  assert.equal(isApiExchange(ex({ resourceType: "document" })), false);
  assert.equal(isApiExchange(ex({ resourceType: "image" })), false);
});

test("inferJsonShape handles primitives, null, and invalid", () => {
  assert.deepEqual(inferJsonShape('["a","b"]'), { type: "array", items: { type: "string" } });
  assert.deepEqual(inferJsonShape("[]"), { type: "array", items: { type: "unknown" } });
  assert.equal(inferJsonShape("not json"), null);
  assert.equal(inferJsonShape(null), null);
});

test("extractApiRefs mines fetch/axios/xhr/api-literals from page scripts", () => {
  const scripts = [
    `fetch('/api/orders/' + id).then(r => r.json()); axios.post("/api/cart", {});`,
    `var x = new XMLHttpRequest(); x.open('GET', '/api/profile');`,
    `const ASSET = '/static/app.js'; const EP = "/api/v2/search?q=";`,
  ];
  const keys = extractApiRefs(scripts, "https://shop.test/products/p1").map((a) => `${a.method} ${a.urlTemplate}`);
  assert.ok(keys.includes("GET /api/orders"), "fetch endpoint");
  assert.ok(keys.includes("POST /api/cart"), "axios endpoint");
  assert.ok(keys.includes("GET /api/profile"), "xhr endpoint");
  assert.ok(keys.includes("GET /api/v2/search"), "/api literal (query stripped)");
  assert.ok(!keys.some((k) => k.includes("app.js")), "static asset excluded");
});
