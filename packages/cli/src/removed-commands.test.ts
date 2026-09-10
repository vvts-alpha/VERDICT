import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cliPath = fileURLToPath(new URL("../dist/main.js", import.meta.url));

test("CLI rejects retired reconnaissance commands and promotion flags", () => {
  const env = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const run = (...args: string[]) => spawnSync(process.execPath, [cliPath, ...args], { env, encoding: "utf8", timeout: 10_000 });
  const help = run("--help");
  assert.equal(help.status, 0, help.stderr);
  assert.doesNotMatch(help.stdout, /\basr\b|from-asr/);
  const recon = run("asr", "--domain", "example.test");
  assert.equal(recon.status, 1);
  assert.match(recon.stderr, /unknown command: asr/);
  const promotion = run("pilot", "--from-asr", "retired-run");
  assert.equal(promotion.status, 1);
  assert.match(promotion.stderr, /Unknown option.*from-asr/);
  const runsDir = mkdtempSync(join(tmpdir(), "verdict-cli-retired-"));
  try {
    for (const [id, file, content] of [
      ["inventory", "asset_inventory.json", '{"assets":[]}'],
      ["metadata", "run.json", '{"command":"asr"}'],
    ] as const) {
      mkdirSync(join(runsDir, id));
      const path = join(runsDir, id, file);
      writeFileSync(path, content);
      const resumed = run("pilot", "--resume", "--id", id, "--out", runsDir);
      assert.equal(resumed.status, 1);
      assert.match(resumed.stderr, /no longer supported/);
      assert.equal(readFileSync(path, "utf8"), content);
    }
  } finally {
    rmSync(runsDir, { recursive: true, force: true });
  }
});
