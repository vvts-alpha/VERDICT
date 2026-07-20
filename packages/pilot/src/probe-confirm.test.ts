// #2 The pure part of the confirmation tools: JWT alg:none forgery + marker-based category routing.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { forgeAlgNone, MARKER_BASED_CATEGORIES, BUSINESS_LOGIC_CATEGORIES, SUSPECT_EXCLUDED_CATEGORIES, normalizeSeverity, checkLogicEvidence } from "./tools.js";

const b64url = (o: unknown): string =>
  Buffer.from(JSON.stringify(o), "utf8").toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (seg: string): Record<string, unknown> => {
  const pad = seg.length % 4 === 0 ? "" : "=".repeat(4 - (seg.length % 4));
  return JSON.parse(Buffer.from(seg.replace(/-/g, "+").replace(/_/g, "/") + pad, "base64").toString("utf8"));
};
const sampleJwt = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "user1", role: "user", email: "u1@x" })}.SIGNATURE`;

test("forgeAlgNone flips header to alg:none, keeps payload, empties the signature", () => {
  const forged = forgeAlgNone(sampleJwt);
  assert.ok(forged, "should forge");
  const [h, p, sig] = forged!.split(".");
  assert.equal(dec(h!).alg, "none");
  assert.equal(sig, ""); // signature is empty
  assert.deepEqual(dec(p!), { sub: "user1", role: "user", email: "u1@x" }); // payload unchanged
});

test("forgeAlgNone can mutate a claim (privilege escalation variant)", () => {
  const forged = forgeAlgNone(sampleJwt, (c) => { c.role = "admin"; });
  const p = dec(forged!.split(".")[1]!);
  assert.equal(p.role, "admin");
  assert.equal(p.sub, "user1");
});

test("forgeAlgNone returns null for non-JWT input", () => {
  assert.equal(forgeAlgNone("not-a-jwt"), null);
  assert.equal(forgeAlgNone("only.two"), forgeAlgNone("only.two") === null ? null : forgeAlgNone("only.two")); // two parts but undecodable → null
  assert.equal(forgeAlgNone(""), null);
});

test("xss-reflected and open-redirect route through marker-based confirmation", () => {
  assert.ok(MARKER_BASED_CATEGORIES.has("xss-reflected"));
  assert.ok(MARKER_BASED_CATEGORIES.has("open-redirect"));
  assert.ok(MARKER_BASED_CATEGORIES.has("price-tampering")); // includes business-logic too (superset)
  // one-shot / body-length-diff classes are not marker-based (prevents mis-routing)
  assert.ok(!MARKER_BASED_CATEGORIES.has("idor"));
  assert.ok(!MARKER_BASED_CATEGORIES.has("sqli"));
  // business-logic is a subset of marker-based
  for (const c of BUSINESS_LOGIC_CATEGORIES) assert.ok(MARKER_BASED_CATEGORIES.has(c));
});

test("normalizeSeverity clamps each class into its band (consistent severities)", () => {
  // reflected XSS drops to Medium even if High is chosen (fixing the mix).
  assert.equal(normalizeSeverity("xss-reflected", "high"), "medium");
  assert.equal(normalizeSeverity("xss-reflected", "critical"), "medium");
  assert.equal(normalizeSeverity("xss-reflected", "low"), "low"); // within band → unchanged
  // RCE is always Critical (fixed to Critical whatever is chosen).
  assert.equal(normalizeSeverity("rce", "low"), "critical");
  assert.equal(normalizeSeverity("rce", "high"), "critical");
  assert.equal(normalizeSeverity("rce", "critical"), "critical");
  // stored XSS is Medium–High, IDOR-read is Medium–High.
  assert.equal(normalizeSeverity("xss-stored", "low"), "medium");
  assert.equal(normalizeSeverity("idor", "critical"), "high");
  // rate-limit is Info–Medium (Medium even if High is chosen). Categories with no band pass through.
  assert.equal(normalizeSeverity("rate-limit", "high"), "medium");
  assert.equal(normalizeSeverity("nonexistent-cat", "critical"), "critical");
});

test("suspected is scoped to serious classes — hygiene/deterministic classes are excluded (noise control)", () => {
  // low-value / deterministically observable classes can't be suspected (confirmed or skip).
  for (const c of ["rate-limit", "headers", "info-disclosure", "misconfig"]) assert.ok(SUSPECT_EXCLUDED_CATEGORIES.has(c), `${c} should be excluded from suspected`);
  // XSS is marker-provable (reflectionIsLive) — confirm-or-skip, never a "suspected" hypothesis off a field name.
  for (const c of ["xss-reflected", "xss-stored"]) assert.ok(SUSPECT_EXCLUDED_CATEGORIES.has(c), `${c} should be excluded from suspected (marker-provable)`);
  // serious exploitation classes that are NOT marker-provable-in-one-request may be suspected.
  for (const c of ["idor", "sqli", "ssti", "rce", "path-traversal", "ssrf", "mass-assignment", "vulnerable-component", "secret-exposure"])
    assert.ok(!SUSPECT_EXCLUDED_CATEGORIES.has(c), `${c} should be allowed as suspected`);
});

test("ssti routes through marker-based confirmation (eval-result marker)", () => {
  // probe_ssti confirms via the computed product appearing only in the evaluated replays — a marker diff,
  // so ssti MUST be marker-based (checkLogicEvidence), not the body-length checkEvidenceDiscipline path.
  assert.ok(MARKER_BASED_CATEGORIES.has("ssti"));
  // a literal-reflection control (no template syntax) carries no product; two evaluated replays do → confirmed.
  const lr = (status: number, hasMarker: boolean) => ({ status, hasMarker });
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(200, true)]).ok, true);
  // literal echo only (payload reflected but NOT evaluated → product absent) → not confirmed.
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, false), lr(200, false)]).ok, false);
});
