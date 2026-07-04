import { test } from "node:test";
import assert from "node:assert/strict";

import { parseTargetUrl, deriveScopeFromUrls } from "./index.js";

test("parseTargetUrl accepts explicit http(s) targets", () => {
  assert.equal(parseTargetUrl("https://app.example.com/x").host, "app.example.com");
  assert.equal(parseTargetUrl("http://localhost:3000").host, "localhost:3000");
});

test("parseTargetUrl rejects a schemeless dotted host (new URL would throw an opaque TypeError)", () => {
  assert.throws(() => parseTargetUrl("example.com"), /target URL/);
  assert.throws(() => parseTargetUrl("example.com/app"), /target URL/);
});

test("parseTargetUrl rejects host:port that new URL() silently misparses into an empty-host scope", () => {
  // new URL("juice.shop:3000") does NOT throw — protocol becomes "juice.shop:", host="" → a silently broken scope.
  assert.throws(() => parseTargetUrl("juice.shop:3000"), /must start with http/);
  assert.throws(() => parseTargetUrl("localhost:3000"), /must start with http/);
});

test("parseTargetUrl rejects non-http(s) schemes", () => {
  assert.throws(() => parseTargetUrl("ftp://example.com"), /must start with http/);
  assert.throws(() => parseTargetUrl("file:///etc/passwd"), /must start with http/);
});

test("deriveScopeFromUrls now fails clearly on a schemeless target instead of crashing / building an empty scope", () => {
  assert.throws(() => deriveScopeFromUrls(["example.com"]), /target URL/);
  assert.throws(() => deriveScopeFromUrls(["juice.shop:3000"]), /target URL/); // previously → inScopeHosts:[""] silently
  // a valid target still derives scope as before
  assert.deepEqual(deriveScopeFromUrls(["https://x.test/a"]).inScopeHosts, ["x.test"]);
});
