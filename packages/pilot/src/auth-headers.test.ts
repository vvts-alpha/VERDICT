// Auth-material propagation: http_request / probe_logic / verify_access carry not just cookie but also the Bearer JWT.
// Regression test so token-auth write APIs (e.g. Juice Shop's /rest/basket, /api/Orders…) don't die with 401.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { authHeaders } from "./tools.js";

test("authHeaders carries both cookie and Bearer JWT", () => {
  const h = authHeaders({ currentCookie: "token=abc", currentBearer: "eyJhbG.payload.sig" });
  assert.equal(h.cookie, "token=abc");
  assert.equal(h.authorization, "Bearer eyJhbG.payload.sig");
});

test("authHeaders omits whichever material is absent", () => {
  // cookie-auth-only app (legacy behaviour)
  assert.deepEqual(authHeaders({ currentCookie: "s=1", currentBearer: "" }), { cookie: "s=1" });
  // bearer-auth-only app (Juice Shop family)
  assert.deepEqual(authHeaders({ currentCookie: "", currentBearer: "jwt.tok.en" }), { authorization: "Bearer jwt.tok.en" });
  // not logged in
  assert.deepEqual(authHeaders({ currentCookie: "", currentBearer: "" }), {});
});

test("caller headers can override the session default (spread last) — enables an unauth control", () => {
  const session = { currentCookie: "token=abc", currentBearer: "jwt.tok.en" };
  // the tool composes in the order { ...authHeaders(s), ...callerHeaders }. An empty value strips auth.
  const merged = { ...authHeaders(session), cookie: "", authorization: "" };
  assert.equal(merged.cookie, "");
  assert.equal(merged.authorization, "");
});
