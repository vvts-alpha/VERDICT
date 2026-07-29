// A caller-supplied header must REPLACE a default of the same name case-insensitively — not collide into two keys that
// undici comma-combines (which silently neutered header-injection probes like probe_sqli location:"header:User-Agent"
// and garbled the recorded evidence). Covers foldHeaders + FetchHttpClient.effectiveHeaders.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { FetchHttpClient, foldHeaders } from "./http.js";

test("foldHeaders folds case-insensitively, last-wins, one key per name", () => {
  const h = foldHeaders({ "user-agent": "default", "x-a": "1" }, { "X-A": "2" }, { "User-Agent": "payload" });
  const names = Object.keys(h).map((k) => k.toLowerCase());
  assert.equal(new Set(names).size, names.length, "no duplicate header names by lowercase");
  assert.equal(names.filter((n) => n === "user-agent").length, 1);
  const ua = Object.entries(h).find(([k]) => k.toLowerCase() === "user-agent")![1];
  assert.equal(ua, "payload"); // caller replaced the default
  const xa = Object.entries(h).find(([k]) => k.toLowerCase() === "x-a")![1];
  assert.equal(xa, "2"); // last-wins across the case difference
});

test("FetchHttpClient.effectiveHeaders lets a caller User-Agent replace the default (single header)", () => {
  const c = new FetchHttpClient({});
  const eff = c.effectiveHeaders({ "User-Agent": "sqli-payload' AND SLEEP(5)-- -" });
  const uaKeys = Object.keys(eff).filter((k) => k.toLowerCase() === "user-agent");
  assert.equal(uaKeys.length, 1, "exactly one user-agent header");
  assert.equal(eff[uaKeys[0]!], "sqli-payload' AND SLEEP(5)-- -");
});
