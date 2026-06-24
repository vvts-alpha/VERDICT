// inventory(Screen.apis = XHR ∪ フォームPOST)→ OpenAPI 3.0 への projection。
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildOpenApi, jsonShapeToSchema } from "./openapi.js";
import type { Screen, ApiCall, Param } from "./types/index.js";

function screen(over: Partial<Screen> & { urlTemplate: string }): Screen {
  return {
    screenId: "s-0001",
    observedUrls: [],
    authState: "unauth",
    screenType: "other",
    description: "",
    params: [],
    apis: [],
    screenshot: "",
    domSkeletonHash: "h",
    labels: [],
    ...over,
  };
}

test("jsonShapeToSchema maps object/array/primitive/unknown", () => {
  assert.deepEqual(jsonShapeToSchema({ type: "object", fields: { a: { type: "string" }, n: { type: "number" } } }), {
    type: "object",
    properties: { a: { type: "string" }, n: { type: "number" } },
  });
  assert.deepEqual(jsonShapeToSchema({ type: "array", items: { type: "boolean" } }), { type: "array", items: { type: "boolean" } });
  assert.deepEqual(jsonShapeToSchema({ type: "unknown" }), {});
});

test("buildOpenApi emits a path+method per api, with form POST body schema and query params", () => {
  const loginPost: ApiCall = {
    method: "POST",
    urlTemplate: "/sessions",
    auth: "none",
    reqSchema: { type: "object", fields: { email: { type: "string" }, password: { type: "string" } } },
    resSchema: null,
  };
  const productGet: ApiCall = { method: "GET", urlTemplate: "/api/products/{id}", auth: "bearer", reqSchema: null, resSchema: { type: "object", fields: { id: { type: "number" } } } };
  const searchQ: Param = { name: "q", in: "query", example: "x", guessedType: "free_text" };

  const doc = buildOpenApi(
    [
      screen({ urlTemplate: "/login", apis: [loginPost] }),
      screen({ urlTemplate: "/api/products/{id}", apis: [productGet] }),
      screen({ urlTemplate: "/search", params: [searchQ], apis: [{ method: "GET", urlTemplate: "/search", auth: "none", reqSchema: null, resSchema: null }] }),
    ],
    { baseUrl: "https://shop.test/" },
  );

  assert.equal((doc as any).openapi, "3.0.3");
  assert.deepEqual((doc as any).servers, [{ url: "https://shop.test" }]); // trailing slash stripped
  const paths = (doc as any).paths;

  // フォーム POST がボディスキーマ付きで出る
  assert.equal(paths["/sessions"].post.requestBody.content["application/json"].schema.properties.email.type, "string");
  assert.equal(paths["/sessions"].post.requestBody.content["application/json"].schema.properties.password.type, "string");

  // path param が出る + response schema
  const getProd = paths["/api/products/{id}"].get;
  assert.ok(getProd.parameters.some((p: any) => p.name === "id" && p.in === "path" && p.required === true));
  assert.equal(getProd.responses["200"].content["application/json"].schema.properties.id.type, "number");

  // 画面の query param が GET op に載る
  assert.ok(paths["/search"].get.parameters.some((p: any) => p.name === "q" && p.in === "query"));
});

test("buildOpenApi dedups the same (method, path) across screens", () => {
  const api: ApiCall = { method: "GET", urlTemplate: "/api/me", auth: "cookie", reqSchema: null, resSchema: null };
  const doc = buildOpenApi([screen({ urlTemplate: "/a", apis: [api] }), screen({ urlTemplate: "/b", apis: [api] })], { baseUrl: "https://x.test" });
  assert.deepEqual(Object.keys((doc as any).paths), ["/api/me"]); // 1 path, not duplicated
});
