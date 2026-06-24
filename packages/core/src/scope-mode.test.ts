import { test } from "node:test";
import assert from "node:assert/strict";
import { deriveScopeFromUrls, deriveScopeFromSingleUrl } from "./factories.js";
import { isInScope, hostMatches } from "./scope-check.js";

test("same-origin: only the exact seed host is in scope", () => {
  const scope = deriveScopeFromUrls(["https://app.example.com/dash"], "same-origin");
  assert.deepEqual(scope.inScopeHosts, ["app.example.com"]);
  assert.ok(isInScope("https://app.example.com/anything", scope));
  // a sibling API subdomain is NOT in scope under same-origin
  assert.ok(!isInScope("https://api.example.com/v1/users", scope));
});

test("etld: sibling subdomains (incl APIs) are in scope under the registrable domain", () => {
  const scope = deriveScopeFromUrls(["https://app.example.com/dash"], "etld");
  assert.deepEqual(scope.inScopeHosts, ["*.example.com"]);
  assert.ok(isInScope("https://app.example.com/dash", scope)); // seed
  assert.ok(isInScope("https://api.example.com/v1/users", scope)); // API subdomain → now in scope
  assert.ok(isInScope("https://example.com/", scope)); // apex
  // a different registrable domain stays out
  assert.ok(!isInScope("https://example.org/", scope));
  assert.ok(!isInScope("https://evil-example.com/", scope));
});

test("etld: multiple seeds union their registrable domains", () => {
  const scope = deriveScopeFromUrls(
    ["https://app.example.com/", "https://portal.acme.co.uk/login"],
    "etld",
  );
  assert.deepEqual(new Set(scope.inScopeHosts), new Set(["*.example.com", "*.acme.co.uk"]));
  assert.ok(isInScope("https://api.example.com/x", scope));
  assert.ok(isInScope("https://auth.acme.co.uk/y", scope));
  assert.ok(!isInScope("https://acme.com/y", scope)); // different suffix
});

test("unrestricted: any http(s) host passes, but protocol + out-of-scope still apply", () => {
  const scope = deriveScopeFromUrls(["https://app.example.com/"], "unrestricted");
  assert.deepEqual(scope.inScopeHosts, ["*"]);
  assert.ok(isInScope("https://anything.else.test/path", scope));
  assert.ok(!isInScope("ftp://anything.else.test/path", scope)); // protocol gate still wins
  // out-of-scope host still overrides the wildcard
  const withDeny = { ...scope, outOfScopeHosts: ["blocked.test"] };
  assert.ok(!isInScope("https://blocked.test/x", withDeny));
});

test("etld on an IP target falls back to exact host (no nonsense *.IP)", () => {
  const scope = deriveScopeFromUrls(["http://192.168.74.148:3000/"], "etld");
  assert.deepEqual(scope.inScopeHosts, ["192.168.74.148:3000"]);
  assert.ok(isInScope("http://192.168.74.148:3000/", scope)); // the target itself must be in scope
  assert.ok(isInScope("http://192.168.74.148:3000/rest/products", scope));
  assert.ok(!isInScope("http://10.0.0.1:3000/", scope)); // other host out
});

test("etld on localhost target falls back to exact host", () => {
  const scope = deriveScopeFromUrls(["http://localhost:8080/"], "etld");
  assert.deepEqual(scope.inScopeHosts, ["localhost:8080"]);
  assert.ok(isInScope("http://localhost:8080/app", scope));
});

test("etld scope matches a host carrying a non-default port (port-insensitive)", () => {
  const scope = deriveScopeFromUrls(["https://app.example.com:8443/"], "etld");
  assert.deepEqual(scope.inScopeHosts, ["*.example.com"]);
  assert.ok(isInScope("https://app.example.com:8443/x", scope)); // port must not break the wildcard
  assert.ok(isInScope("https://api.example.com:8443/v1", scope));
  assert.ok(isInScope("https://example.com/", scope)); // apex, default port
});

test("hostMatches: bare '*' is match-all", () => {
  assert.ok(hostMatches("whatever.test", ["*"]));
  assert.ok(!hostMatches("whatever.test", ["*.example.com"]));
});

test("deriveScopeFromSingleUrl stays same-origin (backward compatible)", () => {
  const scope = deriveScopeFromSingleUrl("https://app.example.com:8443/x");
  assert.deepEqual(scope.inScopeHosts, ["app.example.com:8443"]); // host includes port
  assert.deepEqual(scope.inScopePathPrefixes, ["/"]);
});
