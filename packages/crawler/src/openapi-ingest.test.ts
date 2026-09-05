import { test } from "node:test";
import assert from "node:assert/strict";

import { parseOpenApiToScreens, apiCallToBuiltScreen } from "./index.js";
import { buildOpenApi } from "@veritas/core";
import type { ApiCall, Screen } from "@veritas/core";

const findApi = (screens: Screen[], method: string, template: string) =>
  screens.flatMap((s) => s.apis).find((a) => a.method === method && a.urlTemplate === template);

test("OpenAPI 3.0: paths→apis, {orderId}→{id}, $ref body/response, bearer auth", () => {
  const doc = {
    openapi: "3.0.3",
    components: {
      securitySchemes: { bearer: { type: "http", scheme: "bearer" } },
      schemas: {
        Order: { type: "object", properties: { id: { type: "integer" }, total: { type: "number" }, note: { type: "string" } } },
        NewOrder: { type: "object", properties: { total: { type: "number" }, qty: { type: "integer" } } },
      },
    },
    paths: {
      "/orders/{orderId}": {
        get: {
          security: [{ bearer: [] }],
          parameters: [{ name: "expand", in: "query", schema: { type: "string" } }],
          responses: { "200": { content: { "application/json": { schema: { $ref: "#/components/schemas/Order" } } } } },
        },
      },
      "/orders": {
        post: {
          requestBody: { content: { "application/json": { schema: { $ref: "#/components/schemas/NewOrder" } } } },
          responses: { "201": { description: "created" } },
        },
      },
    },
  };
  const screens = parseOpenApiToScreens(doc, "https://api.example.test");

  // {orderId} collapsed to inventory's {id}
  const get = findApi(screens, "GET", "/orders/{id}");
  assert.ok(get, "GET /orders/{id} produced");
  assert.equal(get!.auth, "bearer");
  assert.equal(get!.resSchema?.type, "object");
  const rf = get!.resSchema?.type === "object" ? get!.resSchema.fields : {};
  assert.equal(rf.id?.type, "number"); // integer → number, $ref resolved
  assert.equal(rf.total?.type, "number");

  // POST body from $ref
  const post = findApi(screens, "POST", "/orders");
  assert.ok(post, "POST /orders produced");
  assert.equal(post!.auth, "none");
  const bf = post!.reqSchema?.type === "object" ? post!.reqSchema.fields : {};
  assert.equal(bf.total?.type, "number");
  assert.equal(bf.qty?.type, "number");

  // the id path screen is an idor-candidate; a query param is captured; body params are captured
  const detail = screens.find((s) => s.urlTemplate === "/orders/{id}")!;
  assert.ok(detail.labels.includes("idor-candidate"));
  assert.ok(detail.labels.includes("authenticated-api"));
  assert.ok(detail.params.some((p) => p.name === "expand" && p.in === "query"));
  const createScreen = screens.find((s) => s.urlTemplate === "/orders")!;
  assert.ok(createScreen.params.some((p) => p.name === "qty" && p.in === "body" && p.guessedType === "qty"));
});

test("Swagger 2.0: basePath, in:body param, definitions $ref, apiKey-in-cookie auth", () => {
  const doc = {
    swagger: "2.0",
    host: "ignored.example",
    basePath: "/v2",
    securityDefinitions: { sess: { type: "apiKey", in: "cookie", name: "SESSION" } },
    definitions: { Pet: { type: "object", properties: { name: { type: "string" }, tags: { type: "array", items: { type: "string" } } } } },
    paths: {
      "/pets/{petId}": {
        get: { security: [{ sess: [] }], responses: { "200": { schema: { $ref: "#/definitions/Pet" } } } },
        put: { parameters: [{ name: "body", in: "body", schema: { $ref: "#/definitions/Pet" } }], responses: { "200": { description: "ok" } } },
      },
    },
  };
  // operator says the API lives here (host/basePath in the doc are advisory; --url is authoritative)
  const screens = parseOpenApiToScreens(doc, "https://api.example.test/v2");

  // 2.0 path under the base prefix, templated
  const get = findApi(screens, "GET", "/v2/pets/{id}");
  assert.ok(get, "GET /v2/pets/{id} produced");
  assert.equal(get!.auth, "cookie"); // apiKey-in-cookie
  assert.equal((get!.resSchema?.type === "object" ? get!.resSchema.fields : {}).name?.type, "string");

  // in:body PUT schema resolved from definitions
  const put = findApi(screens, "PUT", "/v2/pets/{id}");
  assert.ok(put, "PUT /v2/pets/{id} produced");
  const pf = put!.reqSchema?.type === "object" ? put!.reqSchema.fields : {};
  assert.equal(pf.name?.type, "string");
  assert.equal(pf.tags?.type, "array");

  // GET and PUT on the same path collapse to ONE screen (same template)
  assert.equal(screens.filter((s) => s.urlTemplate === "/v2/pets/{id}").length, 1);
});

test("augment: overlay a spec on an existing crawl screen — fills an empty reqSchema, no duplicate", () => {
  const crawl: Screen[] = [
    {
      screenId: "s-0001",
      urlTemplate: "/api/users/{id}",
      observedUrls: ["https://api.example.test/api/users/7"],
      authState: "post-login",
      screenType: "detail",
      description: "crawled",
      params: [{ name: "id", in: "path", example: "7", guessedType: "object_ref" }],
      apis: [{ method: "PATCH", urlTemplate: "/api/users/{id}", auth: "cookie", reqSchema: null, resSchema: null }], // crawl saw it, no body schema
      screenshot: "",
      domSkeletonHash: "realhash",
      labels: ["idor-candidate"],
    },
  ];
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/api/users/{userId}": {
        patch: { requestBody: { content: { "application/json": { schema: { type: "object", properties: { email: { type: "string" } } } } } }, responses: { "200": { description: "ok" } } },
      },
    },
  };
  const merged = parseOpenApiToScreens(doc, "https://api.example.test", crawl);

  // no duplicate screen for the same template
  assert.equal(merged.filter((s) => s.urlTemplate === "/api/users/{id}").length, 1);
  const patch = findApi(merged, "PATCH", "/api/users/{id}")!;
  // the crawl's empty reqSchema is filled from the spec
  assert.equal(patch.reqSchema?.type, "object");
  assert.equal((patch.reqSchema?.type === "object" ? patch.reqSchema.fields : {}).email?.type, "string");
});

test("round-trip sanity: buildOpenApi(parseOpenApiToScreens(doc)) preserves the operation set", () => {
  const doc = {
    openapi: "3.0.3",
    paths: {
      "/a/{x}": { get: { responses: { "200": { description: "ok" } } }, delete: { responses: { "204": { description: "no content" } } } },
      "/b": { post: { requestBody: { content: { "application/json": { schema: { type: "object", properties: { k: { type: "string" } } } } } }, responses: { "200": { description: "ok" } } } },
    },
  };
  const screens = parseOpenApiToScreens(doc, "https://x.test");
  const out = buildOpenApi(screens, { baseUrl: "https://x.test" }) as { paths: Record<string, Record<string, unknown>> };
  const ops = new Set<string>();
  for (const [p, methods] of Object.entries(out.paths)) for (const m of Object.keys(methods)) ops.add(`${m.toUpperCase()} ${p}`);
  assert.deepEqual(
    [...ops].sort(),
    ["DELETE /a/{id}", "GET /a/{id}", "POST /b"].sort(),
  );
});

// A JS-discovered endpoint (from extractApiRefs over a bundle) → a synthetic, diagnosable screen. Used by the pilot's
// analyze_js to enroll hidden endpoints so the diagnosis stage probes them.
test("apiCallToBuiltScreen: JS-discovered endpoint → concrete, IDOR-typed synthetic screen", () => {
  const api: ApiCall = { method: "GET", urlTemplate: "/api/v1/users/{id}", auth: "none", reqSchema: null, resSchema: null };
  const built = apiCallToBuiltScreen(api, "https://app.test/");
  assert.ok(built);
  assert.equal(built!.screen.urlTemplate, "/api/v1/users/{id}");
  assert.equal(built!.observedUrl, "https://app.test/api/v1/users/1"); // {id}→1, concrete + probeable
  assert.deepEqual(built!.screen.observedUrls, ["https://app.test/api/v1/users/1"]);
  assert.equal(built!.screen.apis[0]?.method, "GET");
  const idp = built!.screen.params.find((p) => p.name === "id");
  assert.ok(idp && idp.guessedType === "object_ref", "path {id} typed as an object ref (IDOR candidate)");
  assert.ok(built!.screen.domSkeletonHash.length > 0, "distinct DOM-less skeleton hash so dedup keeps it separate");
});

test("apiCallToBuiltScreen: unparseable base URL → null", () => {
  assert.equal(apiCallToBuiltScreen({ method: "GET", urlTemplate: "/x", auth: "none", reqSchema: null, resSchema: null }, "not a url"), null);
});

test("API upload validation accepts supported operations and rejects wrong formats and empty documents", async () => {
  const { validateOpenApiDocument } = await import("./openapi-ingest.js");
  for (const doc of [null, {}, { openapi: "3.0.3", paths: {} }, { openapi: "4.0", paths: { "/": { get: {} } } }]) {
    assert.throws(() => validateOpenApiDocument(doc));
  }
  validateOpenApiDocument({ openapi: "3.1.0", paths: { "/items": { post: {} } } });
  validateOpenApiDocument({ swagger: "2.0", paths: { "/items": { get: {} } } });
});
