// ignore_paths pattern matching: prefix match + `*` wildcard. For pruning low-value CMS content trees.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { pathIsIgnored } from "./tools.js";

const base = "https://www.example.gv.at/";

test("empty patterns are always false (pruning disabled = exhaustive extraction)", () => {
  assert.equal(pathIsIgnored("/artikel/x", [], base), false);
});

test("prefix match (under a trailing slash)", () => {
  const pats = ["/artikel/", "/news/"];
  assert.equal(pathIsIgnored("https://www.example.gv.at/artikel/12345", pats, base), true);
  assert.equal(pathIsIgnored("/news/2026/foo", pats, base), true);
  assert.equal(pathIsIgnored("/account/edit", pats, base), false);
});

test("`*` wildcard", () => {
  const pats = ["/en/kultur/*", "/p*/detail"];
  assert.equal(pathIsIgnored("/en/kultur/museum", pats, base), true);
  assert.equal(pathIsIgnored("/produkt/detail", pats, base), true);
  assert.equal(pathIsIgnored("/en/wohnen/x", pats, base), false);
});

test("functional paths aren't pruned by mistake (prefix-match boundary)", () => {
  const pats = ["/news/"];
  assert.equal(pathIsIgnored("/newsletter/signup", pats, base), false); // not /news/
  assert.equal(pathIsIgnored("/api/news", pats, base), false);
});
