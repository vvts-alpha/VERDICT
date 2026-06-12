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
