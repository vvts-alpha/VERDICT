import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { bundledWordlistPath, loadWordlist, parseWordlist, WORDLIST_IDS } from "./wordlists.js";

// --wordlist resolution: a bundled id or a filesystem path; anything else fails fast so a typo can't
// silently downgrade the run to the small built-in list.

test("standard / unset → undefined = the in-code PATH_WORDLIST default", () => {
  assert.equal(loadWordlist(undefined), undefined);
  assert.equal(loadWordlist("standard"), undefined);
  assert.equal(loadWordlist(""), undefined);
});

test("extended loads the bundled SecLists common.txt (~4.7k root-relative paths)", () => {
  const list = loadWordlist("extended")!;
  assert.ok(list.length > 4_000, `expected ~4.7k entries, got ${list.length}`);
  assert.ok(list.every((p) => p.startsWith("/")), "every entry normalized to a root-relative path");
  assert.ok(list.includes("/admin"), "common.txt staples present");
  // comment/license header stripped by parseWordlist
  assert.ok(!list.some((p) => p.startsWith("/#") || p.includes("SecLists")));
});

test("a filesystem path loads a custom list (comments + blanks stripped, leading / enforced)", () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-wl-"));
  try {
    const file = join(dir, "my.txt");
    writeFileSync(file, "# comment\n\nsupport/logs\n/encryptionkeys\n admin \n");
    const list = loadWordlist(file)!;
    assert.deepEqual(list.sort(), ["/admin", "/encryptionkeys", "/support/logs"].sort());
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a bad spec fails fast with both explanations — never a silent standard fallback", () => {
  assert.throws(() => loadWordlist("extnded-typo"), /--wordlist.*bundled id.*cannot be read as a file/s);
});

test("parseWordlist caps absurdly large inputs and dedupes", () => {
  const list = parseWordlist(`${"a/".repeat(0)}${Array.from({ length: 10 }, (_, i) => `p${i}`).join("\n")}\np0\n`);
  assert.equal(new Set(list).size, list.length, "deduped");
  assert.equal(list.length, 10);
});

test("bundledWordlistPath resolves inside the package for every non-standard id", () => {
  for (const id of WORDLIST_IDS.filter((i) => i !== "standard")) {
    const p = bundledWordlistPath(id);
    assert.ok(p.endsWith(`${id}.txt`) && p.includes("wordlists"), p);
  }
});
