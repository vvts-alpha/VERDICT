// .env parser: export prefix / comments / quotes / split on first =. loadDotEnv gives the shell precedence.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseDotEnv, loadDotEnv } from "./dotenv.js";

test("parseDotEnv: basic + export + comment + quotes + = in a URL", () => {
  const env = parseDotEnv(
    [
      "# comment",
      "",
      "BURP_API=http://172.29.176.1:1337",
      "export BURP_PROXY=http://172.29.176.1:8082",
      'BURP_RESOURCE_POOL="250ms"',
      "QUOTED='a b'",
      "WITH_EQ=k=v&x=y", // preserve = inside the value
      "  SPACED = trimmed ",
    ].join("\n"),
  );
  assert.equal(env.BURP_API, "http://172.29.176.1:1337");
  assert.equal(env.BURP_PROXY, "http://172.29.176.1:8082");
  assert.equal(env.BURP_RESOURCE_POOL, "250ms");
  assert.equal(env.QUOTED, "a b");
  assert.equal(env.WITH_EQ, "k=v&x=y");
  assert.equal(env.SPACED, "trimmed");
});

test("loadDotEnv: only applies unset keys; shell export takes precedence", () => {
  const dir = mkdtempSync(join(tmpdir(), "dotenv-"));
  writeFileSync(join(dir, ".env"), "PH_TEST_NEW=fromfile\nPH_TEST_EXISTING=fromfile\n");
  process.env.PH_TEST_EXISTING = "fromshell"; // already exported
  delete process.env.PH_TEST_NEW;
  const loaded = loadDotEnv(dir);
  assert.deepEqual(loaded, ["PH_TEST_NEW"]); // does not overwrite existing keys
  assert.equal(process.env.PH_TEST_NEW, "fromfile");
  assert.equal(process.env.PH_TEST_EXISTING, "fromshell");
  delete process.env.PH_TEST_NEW;
  delete process.env.PH_TEST_EXISTING;
});

test("loadDotEnv: empty when there is no .env", () => {
  const dir = mkdtempSync(join(tmpdir(), "dotenv-none-"));
  assert.deepEqual(loadDotEnv(dir), []);
});
