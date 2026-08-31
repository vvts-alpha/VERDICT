import { strict as assert } from "node:assert";
import { test } from "node:test";
import { SSRF_CONTROL, SSRF_PAYLOADS, placeSsrfTarget, ssrfHit } from "./ssrf.js";

test("placeSsrfTarget: query param, {{SSRF}} in body, {{SSRF}} in url", () => {
  const q = placeSsrfTarget("https://app.test/stock", null, "stockApi", "http://127.0.0.1/admin");
  assert.ok(q);
  assert.match(q!.url, /stockApi=http/);
  const b = placeSsrfTarget("https://app.test/x", '{"url":"{{SSRF}}"}', undefined, "http://169.254.169.254/");
  assert.equal(b?.body, '{"url":"http://169.254.169.254/"}');
  const u = placeSsrfTarget("https://app.test/fetch?u={{SSRF}}", null, undefined, "http://127.0.0.1/");
  assert.ok(u!.url.includes(encodeURIComponent("http://127.0.0.1/")));
});

test("placeSsrfTarget returns null without a place to inject", () => {
  assert.equal(placeSsrfTarget("https://app.test/", null, undefined, "http://127.0.0.1/"), null);
});

test("ssrfHit: AWS metadata vs clean control", () => {
  const hit = ssrfHit("ami-id\nami-launch-index\ninstance-id\n", "cannot fetch verdict-ssrf-control.invalid");
  assert.equal(hit?.marker, "ami-id");
  assert.match(hit!.detail, /AWS/i);
});

test("ssrfHit: echoing the payload URL is NOT a hit", () => {
  const payload = SSRF_PAYLOADS[0]!;
  assert.equal(ssrfHit(`error fetching ${payload}`, `error fetching ${SSRF_CONTROL}`, payload), null);
  const gcp = "http://metadata.google.internal/computeMetadata/v1/";
  assert.equal(ssrfHit(`bad host ${gcp}`, `bad host ${SSRF_CONTROL}`, gcp), null);
});

test("ssrfHit: /etc/passwd via impact oracle, ambient copies ignored", () => {
  const passwd = "root:x:0:0:root:/root:/bin/bash";
  const hit = ssrfHit(passwd, "not found");
  assert.ok(hit);
  assert.match(hit!.marker, /root:/);
  assert.equal(ssrfHit(passwd, passwd), null);
});

test("SSRF_CONTROL uses the reserved .invalid TLD", () => {
  assert.match(SSRF_CONTROL, /\.invalid\//);
});
