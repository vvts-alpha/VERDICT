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
    res.end(render(url));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}/`;
  const dir = mkdtempSync(join(tmpdir(), "verdict-dialog-regression-"));
  let driver;
  t.after(async () => {
    await driver?.close();
    server.closeAllConnections();
    server.close();
    rmSync(dir, { recursive: true, force: true });
  });
  driver = await PlaywrightDriver.launch({
    userDataDir: join(dir, "profile"),
    headless: true,
    ...(process.env.VERDICT_TEST_BROWSER ? { executablePath: process.env.VERDICT_TEST_BROWSER } : {}),
    settleMs: 0,
    navTimeoutMs: 5000,
  });
  return { driver, base, hits };
}

test("native alert, confirm and prompt unblock without changing their return values", async (t) => {
  const { driver, base } = await fixture(t, () => `<html><body><script>
    const native = ["alert", "confirm", "prompt"].every((name) => String(window[name]).includes("[native code]"));
    alert("alert-marker");
    const confirmed = confirm("confirm-marker");
    const prompted = prompt("prompt-marker");
    document.body.textContent = "native=" + native + " confirm=" + confirmed + " prompt=" + prompted;
  </script></body></html>`);
  await driver.gotoUrl(base);
  const text = (await driver.snapshot()).visibleText;
  assert.match(text, /native=true/);
  assert.match(text, /confirm=false/);
  assert.match(text, /prompt=null/);
});

test("beforeunload accepts the navigation after user activation", async (t) => {
  const { driver, base } = await fixture(t, (url) => url.pathname === "/leave" ? `<html><body>
    <button id="arm" onclick="window.addEventListener('beforeunload', (e) => { e.preventDefault(); e.returnValue = 'leave?'; })">Arm</button>
  </body></html>` : "<html><body>Arrived</body></html>");
  await driver.gotoUrl(`${base}leave`);
  const session = await driver.cdpSession();
  await session.send("Page.enable");
  const dialogs = [];
  session.on("Page.javascriptDialogOpening", (event) => dialogs.push(event.type));
  assert.equal(await driver.clickFirst(["#arm"]), true);
  await driver.gotoUrl(`${base}arrived`);
  assert.ok(dialogs.includes("beforeunload"));
  assert.equal(new URL(driver.currentUrl()).pathname, "/arrived");
});

test("dialog on a popup unblocks without a page-specific handler", async (t) => {
  const { driver, base, hits } = await fixture(t, (url) => {
    if (url.pathname === "/popup") return `<html><body><script>alert("popup-marker"); fetch("/popup-done");</script></body></html>`;
    return `<html><body><button id="open" onclick="window.open('/popup')">Open</button></body></html>`;
  });
  await driver.gotoUrl(base);
  assert.equal(await driver.clickFirst(["#open"]), true);
  const deadline = Date.now() + 4000;
  while (!hits.includes("/popup-done") && Date.now() < deadline) await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(hits.includes("/popup-done"));
});

test("XSS observer distinguishes a benign control from two dialog executions", async (t) => {
  const marker = "verdict-xss-dialog-marker";
  const { driver, base } = await fixture(t, (url) => {
    if (url.pathname === "/execute") return `<html><body><script>alert(${JSON.stringify(marker)});</script></body></html>`;
    return `<html><body>${marker}</body></html>`;
  });
  const control = await driver.detectXssExecution(`${base}benign`, marker);
  const replay1 = await driver.detectXssExecution(`${base}execute`, marker);
  const replay2 = await driver.detectXssExecution(`${base}execute`, marker);
  assert.equal(control.executed, false);
  assert.equal(replay1.executed, true);
  assert.equal(replay2.executed, true);
  assert.match(replay1.signal, /dialog\(alert\/confirm\/prompt\)/);
});
