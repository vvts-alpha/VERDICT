// Exercise the built driver: browser callbacks must behave as shipped, independently of tsx transforms.
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PlaywrightDriver } from "../dist/index.js";

async function fixture(t, render) {
  const hits = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url, "http://fixture");
    hits.push(url.pathname);
    res.setHeader("content-type", "text/html");
    res.end(render(url, hits));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/`;
  const dir = mkdtempSync(join(tmpdir(), "verdict-browser-regression-"));
  let driver;
  t.after(async () => { await driver?.close(); server.closeAllConnections(); server.close(); rmSync(dir, { recursive: true, force: true }); });
  driver = await PlaywrightDriver.launch({ userDataDir: join(dir, "profile"), headless: true,
    ...(process.env.VERDICT_TEST_BROWSER ? { executablePath: process.env.VERDICT_TEST_BROWSER } : {}), settleMs: 0, navTimeoutMs: 5000 });
  return { driver, base, hits };
}

const form = (id, method = "get", action = `/search-${id}`) => `<form id="${id}" action="${action}" method="${method}"><input name="q" type="text"><button type="submit">Search</button></form>`;

test("all three forms with identical field names submit across reloads and DOM reordering", async (t) => {
  let renders = 0;
  const { driver, base, hits } = await fixture(t, (url) => {
    if (url.pathname !== "/") return "<html><body>Result</body></html>";
    renders++;
    return `<html><body>${(renders % 2 ? ["one", "two", "three"] : ["three", "one", "two"]).map((id) => form(id)).join("")}</body></html>`;
  });
  await driver.gotoUrl(base);
  assert.equal((await driver.snapshot()).forms.length, 3);
  const result = await driver.exerciseInputs({ aggressive: false, allow: (url) => url.startsWith(base) });
  assert.equal(result.exercised, 3);
  assert.deepEqual(hits.filter((p) => p.startsWith("/search-")), ["/search-one", "/search-two", "/search-three"]);
  assert.equal(result.discovered.length, 3);
});

test("standalone inputs remain usable after a previous input navigates", async (t) => {
  const { driver, base, hits } = await fixture(t, (url) => url.pathname === "/" ? `<html><body>
    <input id="one" type="search" onkeydown="if(event.key==='Enter')location.href='/search-one'">
    <input id="two" type="text" onkeydown="if(event.key==='Enter')location.href='/search-two'">
  </body></html>` : "<html><body>Result</body></html>");
  await driver.gotoUrl(base);
  const result = await driver.exerciseInputs({ aggressive: false, allow: (url) => url.startsWith(base) });
  assert.equal(result.exercised, 2);
  assert.deepEqual(hits.filter((p) => p.startsWith("/search-")), ["/search-one", "/search-two"]);
});

test("input sweep respects POST policy, scope/logout gates and successful submission cap", async (t) => {
  const { driver, base, hits } = await fixture(t, (url) => url.pathname === "/" ? `<html><body>
    ${form("write", "post")}${form("logout", "get", "/logout")}${form("outside", "get", "http://outside.invalid/")}
    ${form("one")}${form("two")}</body></html>` : "<html><body>Result</body></html>");
  await driver.gotoUrl(base);
  const result = await driver.exerciseInputs({ aggressive: false, cap: 1, allow: (url) => url.startsWith(base) && !url.includes("logout") });
  assert.equal(result.exercised, 1);
  assert.deepEqual(hits.filter((p) => p.startsWith("/search-")), ["/search-one"]);
  assert.ok(!hits.includes("/logout"));
});

test("browser budget refusal never falls through to route.continue", async (t) => {
  const { driver, base, hits } = await fixture(t, () => "<html><body>OK</body></html>");
  let reservations = 0;
  driver.setRequestGate(() => { if (reservations >= 1) throw new Error("budget"); reservations++; });
  await driver.gotoUrl(base);
  await driver.gotoUrl(`${base}second`);
  assert.equal(reservations, 1);
  assert.ok(!hits.includes("/second"));
});
