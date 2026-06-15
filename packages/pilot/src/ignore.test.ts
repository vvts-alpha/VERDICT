// ignore_paths のパターン照合: 前方一致 + `*` ワイルドカード。低価値 CMS コンテンツ木の間引き用。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { pathIsIgnored } from "./tools.js";

const base = "https://www.example.gv.at/";

test("空パターンは常に false(間引き無効=全量抽出)", () => {
  assert.equal(pathIsIgnored("/artikel/x", [], base), false);
});

test("前方一致(末尾スラッシュ配下)", () => {
  const pats = ["/artikel/", "/news/"];
  assert.equal(pathIsIgnored("https://www.example.gv.at/artikel/12345", pats, base), true);
  assert.equal(pathIsIgnored("/news/2026/foo", pats, base), true);
  assert.equal(pathIsIgnored("/account/edit", pats, base), false);
});

test("`*` ワイルドカード", () => {
  const pats = ["/en/kultur/*", "/p*/detail"];
  assert.equal(pathIsIgnored("/en/kultur/museum", pats, base), true);
  assert.equal(pathIsIgnored("/produkt/detail", pats, base), true);
  assert.equal(pathIsIgnored("/en/wohnen/x", pats, base), false);
});

test("機能面のパスは誤って間引かない(前方一致の境界)", () => {
  const pats = ["/news/"];
  assert.equal(pathIsIgnored("/newsletter/signup", pats, base), false); // /news/ ではない
  assert.equal(pathIsIgnored("/api/news", pats, base), false);
});
