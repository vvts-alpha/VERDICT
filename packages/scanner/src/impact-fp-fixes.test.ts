// Regression tests for false-negative bugs in the scanner impact oracles found by the FP-oracle bug hunt (2026-09-02):
// heuristics that wrongly demoted real cross-user / secret findings. Each fails on the pre-fix code.
import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyCrossUserBody, isPublicByDesignClientCredential, impactOracle } from "./impact.js";

// #6 classifyCrossUserBody — compound camelCase sensitive keys (shippingAddress/phoneNo) must count as sensitive-pii,
// not be missed so the object falls through to "public-directory" and the IDOR is demoted.
test("classifyCrossUserBody: shippingAddress / phoneNo mark a real cross-user object sensitive-pii", () => {
  const body = '{"id":1002,"name":"Bob Smith","shippingAddress":"123 Main St Apt 4","phoneNo":"555-1234"}';
  assert.equal(classifyCrossUserBody(body).class, "sensitive-pii");
  // whitelisted compound emailAddress alone stays a directory card (not falsely escalated)
  assert.equal(classifyCrossUserBody('{"id":1,"name":"Bob","emailAddress":"bob@corp.example"}').class, "public-directory");
});

// #5 isPublicByDesignClientCredential — a real non-Google secret co-located with a public Maps key is NOT public.
test("isPublicByDesignClientCredential: a Stripe sk_live_ marker beside a public Maps key is NOT public-by-design", () => {
  const maps = "AIza" + "B".repeat(35);
  const stripe = "sk_live_51H8xABCDEFGHIJKLMNOPQR";
  const body = `<script src="https://maps.googleapis.com/maps/api/js?key=${maps}"></script><script>const s="${stripe}";</script>`;
  assert.equal(isPublicByDesignClientCredential(body, stripe), false); // the real secret must NOT be swallowed
  assert.equal(isPublicByDesignClientCredential(body, maps), true); // the Maps key itself is still public
});

// #11 impactOracle cross-user — a SHORT incidental self id ("1" in "unread":1) must not suppress a real cross-user read.
test("impactOracle: a short incidental self id does not suppress a real cross-user hit", () => {
  const body = '{"userId":2,"name":"Bob","phone":"555-0000","unread":1}';
  const hits = impactOracle(body, { requestedIdentity: "2", sessionIdentity: "1" });
  assert.ok(hits.some((h) => h.kind === "cross-user"), "cross-user hit must fire despite self id '1' appearing in unread:1");
  // a distinctive self id that genuinely appears still suppresses (own object), and requesting your own id never fires
  assert.equal(impactOracle('{"userId":10032,"name":"Me","phone":"555-1"}', { requestedIdentity: "10032", sessionIdentity: "10032" }).some((h) => h.kind === "cross-user"), false);
});
