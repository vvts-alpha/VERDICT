const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const directory = path.resolve(process.argv[2]);
const app = path.join(directory, "resources/app");
const scope = path.join(app, "node_modules/@anthropic-ai");
assert.deepEqual(fs.readdirSync(scope).filter(name => name.startsWith("claude-agent-sdk-")), ["claude-agent-sdk-win32-x64"]);
const env = { ...process.env, ELECTRON_RUN_AS_NODE: "1" };
delete env.NODE_TEST_CONTEXT;
const cli = spawnSync(path.join(directory, "VERDICT.exe"), [path.join(app, "node_modules/@veritas/cli/dist/main.js"), "--help"],
  { env, encoding: "utf8", timeout: 30_000 });
assert.equal(cli.status, 0, cli.error?.message ?? cli.stderr);
assert.match(cli.stdout, /pilot/);
const native = spawnSync(path.join(scope, "claude-agent-sdk-win32-x64/claude.exe"), ["--version"], { encoding: "utf8", timeout: 30_000 });
assert.equal(native.status, 0, native.error?.message ?? native.stderr);
assert.match(native.stdout, /Claude Code/);
console.log("Packaged Windows CLI, native SDK, and platform contents verified.");
