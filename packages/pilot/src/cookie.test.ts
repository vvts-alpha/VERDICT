// Loading a pre-captured cookie file (loadCookieFile) — raw header / Playwright storageState / array.

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

test("raw Cookie header", () => {
  const { header, browserCookies } = loadCookieFile(w("raw.txt", "sid=abc123; theme=dark"), target);
  assert.equal(header, "sid=abc123; theme=dark");
  assert.equal(browserCookies.length, 2);
  assert.deepEqual(browserCookies[0], { name: "sid", value: "abc123", domain: "app.example.com", path: "/" });
});

test("tolerates a 'Cookie:' prefix + extra lines", () => {
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
  assert.equal(browserCookies[1]?.domain, "app.example.com"); // missing domain is filled in from the target host
});

test("plain array [{name,value}]", () => {
  assert.equal(loadCookieFile(w("arr.json", JSON.stringify([{ name: "a", value: "1" }])), target).header, "a=1");
});

test("storageState origins restore Bearer even with zero cookies", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.sigsigsigsigsigsig";
  const p = w("spa.json", JSON.stringify({
    cookies: [],
    origins: [{ origin: "https://app.example.com", localStorage: [{ name: "token", value: jwt }] }],
  }));
  const loaded = loadCookieFile(p, target);
  assert.equal(loaded.header, "");
  assert.equal(loaded.browserCookies.length, 0);
  assert.equal(loaded.bearer, jwt);
  assert.equal(loaded.origins[0]?.localStorage[0]?.name, "token");
});

test("storageState with cookies + origins", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIyIn0.sigsigsigsigsigsig";
  const p = w("both.json", JSON.stringify({
    cookies: [{ name: "sid", value: "s1", domain: "app.example.com", path: "/" }],
    origins: [{ origin: "https://app.example.com", localStorage: [{ name: "token", value: jwt }] }],
  }));
  const loaded = loadCookieFile(p, target);
  assert.equal(loaded.header, "sid=s1");
  assert.equal(loaded.bearer, jwt);
});
