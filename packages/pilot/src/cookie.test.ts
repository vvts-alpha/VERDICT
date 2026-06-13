// 事前取得 Cookie ファイルの読み込み(loadCookieFile)— 生ヘッダ / Playwright storageState / 配列。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { loadCookieFile } from "./tools.js";

const dir = mkdtempSync(join(tmpdir(), "cookie-"));
const w = (name: string, content: string): string => {
  const p = join(dir, name);
  writeFileSync(p, content);
  return p;
};
const target = "https://app.example.com/";

test("生 Cookie ヘッダ", () => {
  const { header, browserCookies } = loadCookieFile(w("raw.txt", "sid=abc123; theme=dark"), target);
  assert.equal(header, "sid=abc123; theme=dark");
  assert.equal(browserCookies.length, 2);
  assert.deepEqual(browserCookies[0], { name: "sid", value: "abc123", domain: "app.example.com", path: "/" });
});

test("'Cookie:' プレフィックス + 余分な行を許容", () => {
  assert.equal(loadCookieFile(w("h.txt", "Cookie: sid=xyz\nignored second line"), target).header, "sid=xyz");
});

test("Playwright storageState JSON({cookies:[...]})", () => {
  const p = w("state.json", JSON.stringify({ cookies: [
    { name: "sid", value: "s1", domain: "app.example.com", path: "/" },
    { name: "csrf", value: "c1" },
  ] }));
  const { header, browserCookies } = loadCookieFile(p, target);
  assert.equal(header, "sid=s1; csrf=c1");
  assert.equal(browserCookies.length, 2);
  assert.equal(browserCookies[1]?.domain, "app.example.com"); // domain 欠落は target host で補完
});

test("単純配列 [{name,value}]", () => {
  assert.equal(loadCookieFile(w("arr.json", JSON.stringify([{ name: "a", value: "1" }])), target).header, "a=1");
});
