// Verify the WebUI auth signed-Cookie logic (role-bound sign/verify, matching, expiry, tampering, key rotation) without a browser/server.
import { test } from "node:test";
import assert from "node:assert/strict";

import { signSession, verifySession, authenticate } from "./auth.js";
import type { AuthConfig } from "./auth.js";

const CFG: AuthConfig = { operator: "hunter2", viewer: "look-only" };

test("signSession/verifySession round-trips the role and rejects tampering", () => {
  const now = 1_700_000_000_000;
  const tok = signSession(CFG, "operator", now);
  assert.match(tok, /^operator\.\d+\.[0-9a-f]{64}$/);
  assert.equal(verifySession(CFG, tok, now), "operator");
  assert.equal(verifySession(CFG, tok, now + 1000), "operator");
  // HMAC tampering → null
  assert.equal(verifySession(CFG, tok.replace(/.$/, "0"), now), null);
  // malformed → null
  assert.equal(verifySession(CFG, "garbage", now), null);
  assert.equal(verifySession(CFG, "operator.123", now), null);
});

test("a viewer cookie verifies as viewer, and role is bound into the signature (cannot be swapped to operator)", () => {
  const now = 1_700_000_000_000;
  const vtok = signSession(CFG, "viewer", now);
  assert.equal(verifySession(CFG, vtok, now), "viewer");
  // even rewriting the role part to operator, the HMAC won't match → null (no privilege escalation).
  const forged = vtok.replace(/^viewer\./, "operator.");
  assert.equal(verifySession(CFG, forged, now), null);
});

test("authenticate maps each password to its role, unknown → null (operator takes precedence)", () => {
  assert.equal(authenticate(CFG, "hunter2"), "operator");
  assert.equal(authenticate(CFG, "look-only"), "viewer");
  assert.equal(authenticate(CFG, "nope"), null);
  assert.equal(authenticate(CFG, ""), null);
  // if viewer is unset, the viewer password won't pass.
  assert.equal(authenticate({ operator: "hunter2" }, "look-only"), null);
  assert.equal(authenticate({ operator: "hunter2" }, "hunter2"), "operator");
});

test("changing either password rotates the signing key → existing cookies are invalidated", () => {
  const now = 1_700_000_000_000;
  const tok = signSession(CFG, "operator", now);
  assert.equal(verifySession({ operator: "hunter2", viewer: "changed" }, tok, now), null); // invalidated by viewer pw change
  assert.equal(verifySession({ operator: "changed", viewer: "look-only" }, tok, now), null); // invalidated by operator pw change
});

test("verifySession enforces the 7-day expiry window", () => {
  const now = 1_700_000_000_000;
  const tok = signSession(CFG, "viewer", now);
  assert.equal(verifySession(CFG, tok, now + 7 * 24 * 3600 * 1000 - 1), "viewer");
  assert.equal(verifySession(CFG, tok, now + 7 * 24 * 3600 * 1000 + 1), null); // expired
  assert.equal(verifySession(CFG, tok, now - 120_000), null); // issued in the future (beyond the clock-skew limit)
});
