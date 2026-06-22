// 認証壁サーキットブレーカ判定: 全プローブが 401 で何も通らない時だけ true。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { isAuthWalled } from "./tools.js";

const base = { findings: { length: 0 }, httpProbes: 0, httpThrough: 0, httpAuthWall: 0 };

test("trips when all probes are 401, nothing gets through, no findings", () => {
  assert.equal(isAuthWalled({ ...base, httpProbes: 14, httpAuthWall: 14, httpThrough: 0 }), true);
});

test("does NOT trip before the minimum sample", () => {
  assert.equal(isAuthWalled({ ...base, httpProbes: 6, httpAuthWall: 6, httpThrough: 0 }), false);
});

test("does NOT trip if anything got through (2xx)", () => {
  assert.equal(isAuthWalled({ ...base, httpProbes: 20, httpAuthWall: 18, httpThrough: 1 }), false);
});

test("does NOT trip if a finding was recorded", () => {
  assert.equal(isAuthWalled({ findings: { length: 1 }, httpProbes: 20, httpAuthWall: 20, httpThrough: 0 }), false);
});

test("does NOT trip when 401s are a minority (real authz mix, not a wall)", () => {
  assert.equal(isAuthWalled({ ...base, httpProbes: 20, httpAuthWall: 8, httpThrough: 0 }), false);
});
