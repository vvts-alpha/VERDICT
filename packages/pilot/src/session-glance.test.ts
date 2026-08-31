import { strict as assert } from "node:assert";
import { test } from "node:test";
import { cookieHints, cookieStructure, formatRequestDump, glanceCookie, parseCookieHeader, peekJwt } from "./session-glance.js";
import { forgeAlgNone } from "./jwt.js";

test("parseCookieHeader splits name=value pairs", () => {
  const cs = parseCookieHeader("sid=abc; locale=en; session=alice");
  assert.deepEqual(
    cs.map((c) => c.name),
    ["sid", "locale", "session"],
  );
  assert.equal(cs[2]?.value, "alice");
});

test("cookieHints: username as the session value is flagged (AI should judge this)", () => {
  const h = cookieHints("session", "alice", ["alice", "bob"]);
  assert.ok(h.some((x) => /alice/.test(x)));
});

test("cookieHints: random hex session is NOT flagged as identity", () => {
  const h = cookieHints("sid", "a1b2c3d4e5f6789012345678", ["alice"]);
  assert.equal(h.length, 0);
});

test("cookieStructure: jwt / numeric / hex", () => {
  assert.equal(cookieStructure("12345"), "numeric");
  assert.equal(cookieStructure("a".repeat(16)), "hex");
});

test("peekJwt: alg:none is unsigned", () => {
  const sample = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.sig";
  const none = forgeAlgNone(sample);
  assert.ok(none);
  const g = peekJwt(none!);
  assert.equal(g?.unsigned, true);
  assert.equal(g?.claims.sub, "alice");
});

test("glanceCookie keeps enough of a JWT to read header.payload", () => {
  const token = `${"a".repeat(40)}.${"b".repeat(80)}.${"c".repeat(20)}`;
  const g = glanceCookie({ name: "jwt", value: token, httpOnly: false }, []);
  assert.ok(g.value.length >= 120);
  assert.ok(g.hints.some((h) => /HttpOnly/i.test(h)));
});

test("formatRequestDump is a raw request the model can read", () => {
  const dump = formatRequestDump("GET", "https://app.test/me", "session=alice", "Bearer aaa.bbb.ccc");
  assert.match(dump, /^GET \/me HTTP\/1.1/);
  assert.match(dump, /Host: app.test/);
  assert.match(dump, /Cookie: session=alice/);
  assert.match(dump, /Authorization: Bearer aaa.bbb.ccc/);
});
