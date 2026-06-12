import { test } from "node:test";
import assert from "node:assert/strict";

import {
  classifyPathSegment,
  extractQueryParams,
  isInScope,
  normalizePath,
  resolveLink,
} from "./index.js";
import { deriveScopeFromSingleUrl } from "@veritas/core";

test("normalizePath parameterises id-like segments", () => {
  assert.deepEqual(normalizePath("/orders/123"), {
    template: "/orders/{id}",
    params: [{ name: "id", example: "123" }],
  });
  assert.deepEqual(normalizePath("/a/1/b/2"), {
    template: "/a/{id}/b/{id2}",
    params: [
      { name: "id", example: "1" },
      { name: "id2", example: "2" },
    ],
  });
  assert.equal(normalizePath("/users/550e8400-e29b-41d4-a716-446655440000").template, "/users/{id}");
  assert.equal(normalizePath("/products/p101").template, "/products/{id}");
  assert.equal(normalizePath("/orders/").template, "/orders");
  assert.equal(normalizePath("/").template, "/");
});

test("classifyPathSegment distinguishes ids from static", () => {
  assert.equal(classifyPathSegment("123"), "id");
  assert.equal(classifyPathSegment("550e8400-e29b-41d4-a716-446655440000"), "id");
  assert.equal(classifyPathSegment("post-title-12"), "id");
  assert.equal(classifyPathSegment("p101"), "id", "prefix+digits slug id");
  assert.equal(classifyPathSegment("ORD2024"), "id");
  assert.equal(classifyPathSegment("products"), "static");
  assert.equal(classifyPathSegment("v2"), "static", "single digit version stays static");
});

test("extractQueryParams reads name/example pairs", () => {
  assert.deepEqual(extractQueryParams("?q=shoes&sort=price"), [
    { name: "q", example: "shoes" },
    { name: "sort", example: "price" },
  ]);
});

test("resolveLink absolutises and drops non-http / fragments", () => {
  assert.equal(resolveLink("https://e.com/x", "/y"), "https://e.com/y");
  assert.equal(resolveLink("https://e.com/x", "#section"), "https://e.com/x");
  assert.equal(resolveLink("https://e.com/x", "mailto:a@b.com"), null);
  assert.equal(resolveLink("https://e.com/x", "javascript:void(0)"), null);
});

test("isInScope enforces same-origin host + path prefixes", () => {
  const scope = deriveScopeFromSingleUrl("https://shop.test/");
  assert.equal(isInScope("https://shop.test/products", scope), true);
  assert.equal(isInScope("https://shop.test/", scope), true);
  assert.equal(isInScope("https://evil.test/", scope), false);
  assert.equal(isInScope("ftp://shop.test/x", scope), false);
});
