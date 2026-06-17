// .env パーサ: export 接頭辞 / コメント / クォート / 最初の = 分割。loadDotEnv は shell 優先。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseDotEnv, loadDotEnv } from "./dotenv.js";

test("parseDotEnv: 基本 + export + コメント + クォート + URL の =", () => {
  const env = parseDotEnv(
    [
      "# comment",
      "",
      "BURP_API=http://172.29.176.1:1337",
      "export BURP_PROXY=http://172.29.176.1:8082",
      'BURP_RESOURCE_POOL="250ms"',
      "QUOTED='a b'",
      "WITH_EQ=k=v&x=y", // 値の中の = は保持
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

test("loadDotEnv: 未設定キーだけ反映・shell の export が優先", () => {
  const dir = mkdtempSync(join(tmpdir(), "dotenv-"));
  writeFileSync(join(dir, ".env"), "PH_TEST_NEW=fromfile\nPH_TEST_EXISTING=fromfile\n");
  process.env.PH_TEST_EXISTING = "fromshell"; // 既に export 済み
  delete process.env.PH_TEST_NEW;
  const loaded = loadDotEnv(dir);
  assert.deepEqual(loaded, ["PH_TEST_NEW"]); // 既存キーは上書きしない
  assert.equal(process.env.PH_TEST_NEW, "fromfile");
  assert.equal(process.env.PH_TEST_EXISTING, "fromshell");
  delete process.env.PH_TEST_NEW;
  delete process.env.PH_TEST_EXISTING;
});

test("loadDotEnv: .env が無ければ空", () => {
  const dir = mkdtempSync(join(tmpdir(), "dotenv-none-"));
  assert.deepEqual(loadDotEnv(dir), []);
});
