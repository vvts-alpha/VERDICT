import { test } from "node:test";
import assert from "node:assert/strict";
import { detectUrlWrapper } from "./encoding.js";

test("detectUrlWrapper decodes a base64-wrapped return URL and re-wraps a payload (the SSO_ORIG_URI shape)", () => {
  const inner = "https://valerosupply-xtest.valero.com/";
  const b64 = Buffer.from(inner, "utf8").toString("base64"); // standard base64
  const w = detectUrlWrapper(b64);
  assert.ok(w, "recognized a base64-wrapped URL");
  assert.equal(w!.inner, inner);
  // re-wrapping an attacker URL round-trips back to a base64 value the app will decode
  const wrapped = w!.rewrap("https://evil.example/");
  assert.equal(Buffer.from(wrapped, "base64").toString("utf8"), "https://evil.example/");
});

test("detectUrlWrapper handles base64url (- and _) and strips padding on rewrap", () => {
  const inner = "https://host/path?a=1&b=2";
  const b64url = Buffer.from(inner, "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const w = detectUrlWrapper(b64url);
  assert.ok(w && w.kind === "base64url");
  assert.equal(w!.inner, inner);
  const wrapped = w!.rewrap("https://evil.example/x");
  assert.ok(!wrapped.includes("="));
  assert.equal(Buffer.from(wrapped.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"), "https://evil.example/x");
});

test("detectUrlWrapper decodes a percent-encoded URL", () => {
  const w = detectUrlWrapper(encodeURIComponent("https://host/next"));
  assert.ok(w && w.kind === "percent");
  assert.equal(w!.inner, "https://host/next");
  assert.equal(decodeURIComponent(w!.rewrap("https://evil/")), "https://evil/");
});

test("detectUrlWrapper ignores non-URL and random base64 (round-trip guard)", () => {
  assert.equal(detectUrlWrapper("plainvalue"), null);
  assert.equal(detectUrlWrapper("12345"), null);
  assert.equal(detectUrlWrapper(Buffer.from("just some text not a url", "utf8").toString("base64")), null);
});
