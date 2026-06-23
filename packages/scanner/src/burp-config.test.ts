// pickBurpConfigs: survey の surface 規模から Burp named config を自動選択するヒューリスティック。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { pickBurpConfigs } from "./burp-rest.js";

const mk = (n: number, apisEach = 0): { screens: Array<{ apis: unknown[] }> } => ({
  screens: Array.from({ length: n }, () => ({ apis: Array.from({ length: apisEach }, () => ({})) })),
});

test("small surface → most complete crawl + full audit", () => {
  const { configs } = pickBurpConfigs(mk(5));
  assert.deepEqual(configs, ["Crawl strategy - most complete", "Audit checks - all except time-based detection methods"]);
});

test("medium surface → Burp default crawl (no crawl config) + full audit", () => {
  const { configs } = pickBurpConfigs(mk(20));
  assert.deepEqual(configs, ["Audit checks - all except time-based detection methods"]);
});

test("large surface → fastest crawl + full audit", () => {
  const { configs } = pickBurpConfigs(mk(50));
  assert.deepEqual(configs, ["Crawl strategy - fastest", "Audit checks - all except time-based detection methods"]);
});

test("very large surface → fastest crawl + critical-only audit (bound time)", () => {
  const { configs } = pickBurpConfigs(mk(120));
  assert.deepEqual(configs, ["Crawl strategy - fastest", "Audit checks - critical issues only"]);
});

test("reason reports screen and API counts", () => {
  const { reason } = pickBurpConfigs(mk(5, 3));
  assert.match(reason, /5 screens \/ 15 APIs/);
});
