// impactOracle: verifies each impact signal firing + two-stage FP suppression (placeholder / anti-ambient) + cross-user + CTF-default-OFF.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { impactOracle, formatImpact } from "./impact.js";

const kinds = (body: string, ctx = {}) => impactOracle(body, ctx).map((s) => s.kind);

test("detects concrete impact signals (passwd / private key / AWS key / uid / php / JWT)", () => {
  assert.ok(kinds("root:x:0:0:root:/root:/bin/bash").includes("file-leak"));
  assert.ok(kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIE...").includes("secret"));
  assert.ok(kinds("creds: AKIA1234567890ABCDEF here").includes("secret"));
  assert.ok(kinds("uid=0(root) gid=0(root) groups=0(root)").includes("command-output"));
  assert.ok(kinds("<?php $db='secret'; ?>").includes("source-leak"));
  assert.ok(kinds("token eyJhbGciOiJIUzI1Ni19.eyJzdWIiOiIxIn0.abcdef here").includes("secret")); // JWT
});

test("suppresses documentation placeholders (no false secret)", () => {
  assert.deepEqual(kinds("aws_key = AKIAIOSFODNN7EXAMPLE"), []);
  assert.deepEqual(kinds("api_key: your-api-key-here"), []);
  assert.deepEqual(kinds("password = xxxxxxxxxxxx"), []);
});

test("anti-ambient: a signal already present in the baseline does not fire", () => {
  const body = "BEGIN... -----BEGIN PRIVATE KEY-----\nABC";
  // appears in baseline too → ambient → suppressed
  assert.deepEqual(impactOracle(body, { baselineBody: body }), []);
  // present only in the exploit response → fires
  assert.ok(impactOracle(body, { baselineBody: "nothing here" }).length > 0);
});

test("cross-user fires only when the victim id is present and the attacker's own id is not", () => {
  // attacker = user 10032, victim = 10052: response shows victim, not attacker → cross-user
  assert.ok(kinds("Receipt for account 10052", { requestedIdentity: "10052", sessionIdentity: "10032" }).includes("cross-user"));
  // response shows the attacker's OWN id → not cross-user (it's just my own object)
  assert.ok(!kinds("Receipt for 10052 owner 10032", { requestedIdentity: "10052", sessionIdentity: "10032" }).includes("cross-user"));
  // victim id also in baseline → ambient → no fire
  assert.ok(!kinds("acct 10052", { requestedIdentity: "10052", baselineBody: "acct 10052" }).includes("cross-user"));
});

test("CTF flag detection is OFF by default, ON only with an explicit flagRegex", () => {
  assert.deepEqual(kinds("FLAG{abc123}"), []); // no flagRegex → not a signal (no CTF coupling on real engagements)
  assert.ok(kinds("FLAG{abc123}", { flagRegex: /FLAG\{[^}]+\}/ }).includes("ctf-flag"));
});

test("formatImpact renders a readable one-liner", () => {
  const sig = impactOracle("uid=0(root) gid=0(root)");
  assert.match(formatImpact(sig), /command-output\[high\]/);
});
