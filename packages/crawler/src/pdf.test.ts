import { test } from "node:test";
import assert from "node:assert/strict";
import { join } from "node:path";

import { detectSystemChromium, resolvePlaywrightLaunch } from "./pdf.js";

const winEnv = {
  PROGRAMFILES: "C:\\Program Files",
  "PROGRAMFILES(X86)": "C:\\Program Files (x86)",
  LOCALAPPDATA: "C:\\Users\\u\\AppData\\Local",
};

test("detectSystemChromium returns the first existing candidate", () => {
  const edge = join("C:\\Program Files", "Microsoft", "Edge", "Application", "msedge.exe");
  const found = detectSystemChromium({
    platform: "win32",
    env: winEnv,
    exists: (p) => p === edge,
  });
  assert.equal(found, edge);
});

test("resolvePlaywrightLaunch prefers an existing explicit path over env", () => {
  const choice = resolvePlaywrightLaunch(
    { executablePath: "D:\\Chrome\\chrome.exe" },
    {
      platform: "win32",
      env: { VERDICT_BROWSER_PATH: "C:\\other\\chrome.exe" },
      exists: (p) => p === "D:\\Chrome\\chrome.exe",
    },
  );
  assert.deepEqual(choice, { executablePath: "D:\\Chrome\\chrome.exe" });
});

test("resolvePlaywrightLaunch skips a stale VERDICT_BROWSER_PATH and uses installed Chrome", () => {
  const chrome = join("C:\\Program Files", "Google", "Chrome", "Application", "chrome.exe");
  const choice = resolvePlaywrightLaunch(
    {},
    {
      platform: "win32",
      env: { VERDICT_BROWSER_PATH: "C:\\missing\\chrome.exe", ...winEnv, LOCALAPPDATA: "" },
      exists: (p) => p === chrome,
    },
  );
  assert.deepEqual(choice, { executablePath: chrome });
});

test("resolvePlaywrightLaunch on Windows falls back to Edge channel, not Playwright's headless_shell", () => {
  const choice = resolvePlaywrightLaunch(
    {},
    { platform: "win32", env: {}, exists: () => false },
  );
  assert.deepEqual(choice, { channel: "msedge" });
});

test("resolvePlaywrightLaunch on Linux with no browser leaves Playwright's default", () => {
  const choice = resolvePlaywrightLaunch(
    {},
    { platform: "linux", env: {}, exists: () => false },
  );
  assert.deepEqual(choice, {});
});
