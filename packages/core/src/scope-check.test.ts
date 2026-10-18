import { test } from "node:test";
import assert from "node:assert/strict";

import { parseTargetUrl, deriveScopeFromUrls, isInScope } from "./index.js";

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

test("path prefixes: trailing `*` is a wildcard, allow wins over block, block wins over the default", () => {
  const base = { inScopeHosts: ["x.test"], outOfScopeHosts: [], inScopePathPrefixes: [], outOfScopePathPrefixes: [] };
  const inScope = (u: string) => isInScope(u, base);

  // trailing `*` behaves like a prefix glob — `/*` matches every path
  const wild = { ...base, inScopePathPrefixes: ["/*"] };
  assert.equal(isInScope("https://x.test/a", wild), true);
  assert.equal(isInScope("https://x.test/", wild), true);
  assert.equal(isInScope("https://x.test/admin/x", { ...base, outOfScopePathPrefixes: ["/admin*"] }), false);

  // an explicit allow-prefix overrides a block (exception carving)
  const except = { ...base, inScopePathPrefixes: ["/admin/public*"], outOfScopePathPrefixes: ["/admin"] };
  assert.equal(isInScope("https://x.test/admin/public/view", except), true);
  assert.equal(isInScope("https://x.test/admin/delete", except), false);

  // block applies when nothing is allowed; an allow-list narrows the default
  assert.equal(inScope("https://x.test/logout") && inScope("https://x.test/"), true);
  assert.equal(isInScope("https://x.test/logout", { ...base, outOfScopePathPrefixes: ["/logout"] }), false);
  assert.equal(isInScope("https://x.test/other", { ...base, inScopePathPrefixes: ["/app"] }), false);

  // a catch-all allow (the derived default "/") means "no narrowing" — blocks still apply under it
  const derived = { ...base, inScopePathPrefixes: ["/"], outOfScopePathPrefixes: ["/admin"] };
  assert.equal(isInScope("https://x.test/admin", derived), false);
  assert.equal(isInScope("https://x.test/orders", derived), true);
});
