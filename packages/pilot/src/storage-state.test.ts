import { strict as assert } from "node:assert";
import { test } from "node:test";
import { bearerFromOrigins, normalizeOrigins } from "./storage-state.js";

test("bearerFromOrigins: localStorage.token (Juice Shop shape)", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigsigsigsigsigsig";
  assert.equal(
    bearerFromOrigins([{ origin: "https://app.test", localStorage: [{ name: "token", value: jwt }] }]),
    jwt,
  );
});

test("bearerFromOrigins: JSON-wrapped accessToken and Bearer prefix", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.sigsigsigsigsigsig";
  assert.equal(
    bearerFromOrigins([{ origin: "https://app.test", localStorage: [{ name: "auth", value: JSON.stringify({ accessToken: jwt }) }] }]),
    jwt,
  );
  assert.equal(
    bearerFromOrigins([{ origin: "https://app.test", localStorage: [{ name: "jwt", value: `Bearer ${jwt}` }] }]),
    jwt,
  );
});

test("bearerFromOrigins: ignores short / non-JWT values", () => {
  assert.equal(
    bearerFromOrigins([{ origin: "https://app.test", localStorage: [{ name: "theme", value: "dark" }, { name: "token", value: "abc" }] }]),
    "",
  );
});

test("normalizeOrigins drops malformed entries", () => {
  const out = normalizeOrigins([
    { origin: "https://app.test", localStorage: [{ name: "a", value: "1" }, { name: 3 }] },
    { origin: "", localStorage: [] },
    null,
  ]);
  assert.equal(out.length, 1);
  assert.deepEqual(out[0]?.localStorage, [{ name: "a", value: "1" }]);
});
