const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const { test } = require("node:test");
const afterPack = require("./after-pack.cjs");

async function fixture(t, executable = "MZ-windows-fixture") {
  const appOutDir = await fs.mkdtemp(path.join(os.tmpdir(), "verdict-package-"));
  t.after(() => fs.rm(appOutDir, { recursive: true, force: true }));
  const scope = path.join(appOutDir, "resources/app/node_modules/@anthropic-ai");
  for (const name of ["claude-agent-sdk", "claude-agent-sdk-win32-x64", "claude-agent-sdk-win32-arm64", "claude-agent-sdk-linux-x64", "claude-agent-sdk-linux-x64-musl", "claude-agent-sdk-darwin-arm64"]) {
    await fs.mkdir(path.join(scope, name), { recursive: true });
  }
  await fs.writeFile(path.join(scope, "claude-agent-sdk-win32-x64/claude.exe"), executable);
  await fs.writeFile(path.join(scope, "claude-agent-sdk/sdk.mjs"), "export {};");
  return { scope, context: { appOutDir, electronPlatformName: "win32", arch: 1 } };
}

test("Windows artifact retains its executable and shared SDK, excluding foreign platforms and architectures", async (t) => {
  const { scope, context } = await fixture(t);
  const nested = path.join(scope, "claude-agent-sdk/node_modules/@anthropic-ai/claude-agent-sdk-linux-x64");
  await fs.mkdir(nested, { recursive: true });
  await afterPack(context);
  assert.deepEqual((await fs.readdir(scope)).sort(), ["claude-agent-sdk", "claude-agent-sdk-win32-x64"]);
  assert.equal(await fs.readFile(path.join(scope, "claude-agent-sdk-win32-x64/claude.exe"), "utf8"), "MZ-windows-fixture");
  assert.equal(await fs.readFile(path.join(scope, "claude-agent-sdk/sdk.mjs"), "utf8"), "export {};");
  await assert.rejects(fs.stat(nested), { code: "ENOENT" });
});

test("Windows packaging fails when the native executable is missing", async (t) => {
  const { scope, context } = await fixture(t);
  await fs.unlink(path.join(scope, "claude-agent-sdk-win32-x64/claude.exe"));
  await assert.rejects(afterPack(context), { code: "ENOENT" });
});

test("Windows packaging rejects a non-Windows executable", async (t) => {
  const { context } = await fixture(t, "\x7fELF");
  await assert.rejects(afterPack(context), /Invalid Windows SDK executable/);
});
