import { test } from "node:test";
import assert from "node:assert/strict";

import { classifyScreenType, deriveLabels, guessParamType } from "./index.js";
import type { Param } from "@veritas/core";
import type { FormObservation } from "./index.js";

function st(over: Partial<{ urlTemplate: string; finalUrl: string; forms: FormObservation[]; title: string; visibleText: string }>) {
  return classifyScreenType({
    urlTemplate: over.urlTemplate ?? "/x",
    finalUrl: over.finalUrl ?? "https://e.com/x",
    forms: over.forms ?? [],
    title: over.title ?? "",
    visibleText: over.visibleText ?? "",
  });
}

test("classifyScreenType applies a priority cascade", () => {
  assert.equal(st({ urlTemplate: "/login" }), "auth");
  assert.equal(
    st({ urlTemplate: "/x", forms: [{ action: null, method: "post", fields: [{ name: "pw", type: "password" }] }] }),
    "auth",
  );
  assert.equal(st({ urlTemplate: "/admin/users" }), "admin");
  assert.equal(st({ urlTemplate: "/checkout" }), "payment");
  assert.equal(st({ urlTemplate: "/products/{id}" }), "detail");
  assert.equal(
    st({ urlTemplate: "/contact", forms: [{ action: null, method: "post", fields: [{ name: "msg", type: "text" }] }] }),
    "form",
  );
  assert.equal(st({ urlTemplate: "/" }), "dashboard");
  assert.equal(st({ urlTemplate: "/about" }), "other");
});

test("guessParamType maps names/locations to types", () => {
  assert.equal(guessParamType("id", "path"), "object_ref");
  assert.equal(guessParamType("user_id", "query"), "object_ref");
  assert.equal(guessParamType("price", "body"), "price");
  assert.equal(guessParamType("quantity", "body"), "qty");
  assert.equal(guessParamType("avatar", "body"), "file");
  assert.equal(guessParamType("redirect", "query"), "free_text");
  assert.equal(guessParamType("sort", "query"), "enum");
  assert.equal(guessParamType("nonce", "query"), "unknown");
});

// IDOR-candidate recall: the old /id$/ was case-sensitive → it MISSED camelCase userId/orderId (the most common API id
// params), so those endpoints were never enrolled as IDOR candidates. Lock the strengthened detection.
test("guessParamType detects camelCase + id-shaped-value ids (IDOR recall)", () => {
  assert.equal(guessParamType("userId", "query"), "object_ref"); // was "unknown" before the fix
  assert.equal(guessParamType("orderId", "body"), "object_ref");
  assert.equal(guessParamType("accountId", "query"), "object_ref");
  assert.equal(guessParamType("uuid", "query"), "object_ref");
  assert.equal(guessParamType("customer_ref", "query"), "object_ref");
  assert.equal(guessParamType("account", "query"), "object_ref");
  // ambiguous NAME but id-shaped VALUE → object_ref via the example fallback
  assert.equal(guessParamType("q", "query", "550e8400-e29b-41d4-a716-446655440000"), "object_ref");
  assert.equal(guessParamType("x", "query", "10294"), "object_ref");
  // name-based semantics still win over an id-shaped number (no false id-typing)
  assert.equal(guessParamType("amount", "body", "42"), "price");
  assert.equal(guessParamType("quantity", "body", "50"), "qty");
});

test("deriveLabels surfaces attack hints", () => {
  const idParam: Param = { name: "id", in: "path", example: "1", guessedType: "object_ref" };
  assert.ok(deriveLabels("detail", [idParam], [], "").includes("idor-candidate"));
  assert.ok(deriveLabels("auth", [], [], "enter email and password").includes("auth"));
  assert.ok(deriveLabels("auth", [], [], "enter email and password").includes("pii"));
  const urlParam: Param = { name: "redirect_url", in: "query", example: "", guessedType: "free_text" };
  assert.ok(deriveLabels("other", [urlParam], [], "").includes("ssrf-candidate"));
  assert.ok(
    deriveLabels("detail", [], [{ method: "GET", urlTemplate: "/api/x", auth: "cookie", reqSchema: null, resSchema: null }], "")
      .includes("authenticated-api"),
  );
});
