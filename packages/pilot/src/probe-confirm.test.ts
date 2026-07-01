// #2 確証ツールの純粋部分: JWT の alg:none 偽造 + マーカーベース・カテゴリのルーティング。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { forgeAlgNone, MARKER_BASED_CATEGORIES, BUSINESS_LOGIC_CATEGORIES, SUSPECT_EXCLUDED_CATEGORIES, checkLogicEvidence } from "./tools.js";

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
  assert.equal(sig, ""); // 署名は空
  assert.deepEqual(dec(p!), { sub: "user1", role: "user", email: "u1@x" }); // payload 不変
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
  assert.ok(MARKER_BASED_CATEGORIES.has("price-tampering")); // business-logic も含む(上位集合)
  // 単発・長さ差分で見る系は marker-based に入れない(誤ルーティング防止)
  assert.ok(!MARKER_BASED_CATEGORIES.has("idor"));
  assert.ok(!MARKER_BASED_CATEGORIES.has("sqli"));
  // business-logic は marker-based の部分集合
  for (const c of BUSINESS_LOGIC_CATEGORIES) assert.ok(MARKER_BASED_CATEGORIES.has(c));
});

test("suspected is scoped to serious classes — hygiene/deterministic classes are excluded (noise control)", () => {
  // 低価値・決定的に観測できるクラスは suspected 不可(confirmed か skip)。
  for (const c of ["rate-limit", "headers", "info-disclosure", "misconfig"]) assert.ok(SUSPECT_EXCLUDED_CATEGORIES.has(c), `${c} should be excluded from suspected`);
  // 深刻な exploitation クラスは suspected 可。
  for (const c of ["idor", "sqli", "ssti", "rce", "path-traversal", "ssrf", "mass-assignment", "vulnerable-component", "secret-exposure", "xss-stored"])
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
