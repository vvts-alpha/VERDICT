// Projection of the inventory (Screen.apis = XHR ∪ form POSTs) → OpenAPI 3.0.
import { test } from "node:test";
import assert from "node:assert/strict";
import { buildOpenApi, jsonShapeToSchema, schemaToJsonShape } from "./openapi.js";
import type { Screen, ApiCall, Param, JsonShape } from "./types/index.js";

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

  // Form POST is emitted with a body schema
  assert.equal(paths["/sessions"].post.requestBody.content["application/json"].schema.properties.email.type, "string");
  assert.equal(paths["/sessions"].post.requestBody.content["application/json"].schema.properties.password.type, "string");

  // path param is emitted + response schema
  const getProd = paths["/api/products/{id}"].get;
  assert.ok(getProd.parameters.some((p: any) => p.name === "id" && p.in === "path" && p.required === true));
  assert.equal(getProd.responses["200"].content["application/json"].schema.properties.id.type, "number");

  // The screen's query param lands on the GET op
  assert.ok(paths["/search"].get.parameters.some((p: any) => p.name === "q" && p.in === "query"));
});

test("buildOpenApi dedups the same (method, path) across screens", () => {
  const api: ApiCall = { method: "GET", urlTemplate: "/api/me", auth: "cookie", reqSchema: null, resSchema: null };
  const doc = buildOpenApi([screen({ urlTemplate: "/a", apis: [api] }), screen({ urlTemplate: "/b", apis: [api] })], { baseUrl: "https://x.test" });
  assert.deepEqual(Object.keys((doc as any).paths), ["/api/me"]); // 1 path, not duplicated
});

// ── ingest side: schemaToJsonShape (the inverse used to read a swagger.json) ──
test("schemaToJsonShape round-trips jsonShapeToSchema (object/array/primitive/unknown)", () => {
  const shapes: JsonShape[] = [
    {
      type: "object",
      fields: {
        a: { type: "string" },
        n: { type: "number" },
        b: { type: "boolean" },
        nested: { type: "object", fields: { arr: { type: "array", items: { type: "string" } } } },
      },
    },
    { type: "array", items: { type: "object", fields: { id: { type: "number" } } } },
    { type: "string" },
    { type: "unknown" },
  ];
  const noDeref = (): undefined => undefined;
  for (const s of shapes) assert.deepEqual(schemaToJsonShape(jsonShapeToSchema(s), noDeref), s);
});

test("schemaToJsonShape resolves $ref against components (integer→number, recursion cycle-guarded)", () => {
  const components: Record<string, Record<string, unknown>> = {
    "#/components/schemas/User": { type: "object", properties: { id: { type: "integer" }, self: { $ref: "#/components/schemas/User" } } },
  };
  const deref = (ref: string): Record<string, unknown> | undefined => components[ref];
  const shape = schemaToJsonShape({ $ref: "#/components/schemas/User" }, deref);
  assert.equal(shape.type, "object");
  if (shape.type === "object") {
    assert.equal(shape.fields.id?.type, "number"); // integer → number
    assert.equal(shape.fields.self?.type, "unknown"); // recursive ref stopped, no infinite loop
  }
});

test("schemaToJsonShape: allOf merges fields, oneOf takes first, enum→string, 3.1 [T,null]→T", () => {
  const noDeref = (): undefined => undefined;
  assert.deepEqual(
    schemaToJsonShape({ allOf: [{ type: "object", properties: { a: { type: "string" } } }, { type: "object", properties: { b: { type: "integer" } } }] }, noDeref),
    { type: "object", fields: { a: { type: "string" }, b: { type: "number" } } },
  );
  assert.equal(schemaToJsonShape({ oneOf: [{ type: "string" }, { type: "integer" }] }, noDeref).type, "string");
  assert.equal(schemaToJsonShape({ enum: ["a", "b"] }, noDeref).type, "string");
  assert.equal(schemaToJsonShape({ type: ["string", "null"] }, noDeref).type, "string"); // OpenAPI 3.1 nullable
});
