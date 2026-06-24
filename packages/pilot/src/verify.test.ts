// burp-verify の純粋部分(対象エンドポイント抽出)を検証。mergeBurpIssues が finding.description を
// "<detail> @ <url>" 形式で書くので、その末尾 URL を確実に拾えること。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { endpointOf } from "./verify.js";
import type { Finding } from "@veritas/core";

function fnd(description: string): Finding {
  return {
    id: "b-001",
    screenId: null,
    title: "[burp] Server-side template injection",
    severity: "high",
    source: { kind: "validator", validatorName: "burp" },
    description,
    reproSteps: "",
    evidenceIds: [],
    scopeBasis: "burp scan (in-scope)",
  };
}

test("endpointOf extracts the trailing '@ <url>' Burp merge writes", () => {
  assert.equal(
    endpointOf(fnd("Template injection detected. @ http://192.168.74.148:3000/rest/products/search?q=x")),
    "http://192.168.74.148:3000/rest/products/search?q=x",
  );
});

test("endpointOf returns null when there is no trailing URL", () => {
  assert.equal(endpointOf(fnd("Some detail with an @mention but no url")), null);
  assert.equal(endpointOf(fnd("plain description")), null);
});

test("endpointOf takes the LAST url (the merge appends the canonical one at the end)", () => {
  assert.equal(
    endpointOf(fnd("see http://a.test/early in detail @ https://b.test/final")),
    "https://b.test/final",
  );
});
