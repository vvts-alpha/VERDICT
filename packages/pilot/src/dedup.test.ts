// Regression test for finding dedup. Verifies that the 21 raw findings from a real run (user-reported)
// collapse under the (class × endpoint × param) key down to only the distinct ones.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { CATEGORIES, appWideSignature, coarseClass, dedupKey, normEndpoint } from "./tools.js";

const base = "http://localhost:3000";

test("coarseClass folds wording variants of the same class", () => {
  for (const v of [
    "Reflected XSS",
    "Reflected XSS (CWE-79)",
    "Reflected Cross-Site Scripting (XSS)",
    "Reflected Cross-Site Scripting (CWE-79)",
  ]) {
    assert.equal(coarseClass(v), "xss-reflected", v);
  }
  assert.equal(coarseClass("Stored XSS (CWE-79)"), "xss-stored");
  assert.equal(coarseClass("Broken Access Control (IDOR)"), "idor");
  assert.equal(coarseClass("IDOR / BOLA (Broken Object Level Authorization)"), "idor");
  assert.equal(coarseClass("IDOR / Broken Object Level Authorization (write)"), "idor-write");
  assert.equal(coarseClass("Path Traversal / Arbitrary File Read (CWE-22)"), "path-traversal");
});

test("normEndpoint folds concrete ids and {id} templates together", () => {
  assert.equal(normEndpoint("/orders/o10", base), normEndpoint("/orders/{id}", base));
  assert.equal(normEndpoint(`${base}/orders/o10?x=1`, base), "/orders/{id}");
  assert.notEqual(normEndpoint("/orders/{id}", base), normEndpoint("/orders/{id}/receipt", base));
});

test("the 21 real raw findings dedupe to 8 distinct holes", () => {
  // [vulnClass, endpoint, param]  — real user-reported data, shaped as Claude would likely pass it
  const raw: Array<[string, string, string | undefined]> = [
    // ── Reflected XSS on /search?q= (13 wording variants) → 1 ──
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS (CWE-79)", "/search", "q"],
    ["Reflected Cross-Site Scripting (XSS)", "/search", "q"],
    ["Reflected XSS (CWE-79)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected Cross-Site Scripting (CWE-79)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    ["Reflected Cross-Site Scripting (XSS)", "/search", "q"],
    ["Reflected XSS", "/search", "q"],
    // ── the distinct ones ──
    ["Path Traversal / Arbitrary File Read (CWE-22)", "/download", "file"],
    ["Broken Access Control (IDOR)", "/addresses/{id}", undefined], // addresses read
    ["IDOR / BOLA", "/orders/o10", undefined], // orders read (3 entries → 1)
    ["IDOR / BOLA (Broken Object Level Authorization)", "/orders/o11", undefined],
    ["Broken Access Control (IDOR/BOLA)", "/orders/{id}", undefined],
    ["IDOR / Broken Object Level Authorization (write)", "/addresses/12/edit", undefined], // write-IDOR
    ["IDOR / BOLA", "/orders/o10/receipt", undefined], // receipt
    ["Stored XSS (CWE-79)", "/support/new", "body"],
    ["Stored XSS (CWE-79)", "/support/tickets/42", "body"], // reply
  ];

  const keys = new Set(raw.map(([c, e, p]) => dedupKey(c, e, p, base)));
  assert.equal(raw.length, 22); // 13 XSS + 9 others as listed
  assert.equal(keys.size, 8, [...keys].sort().join("\n"));

  // all /search XSS collapse to 1 key
  const searchKeys = new Set(
    raw.filter(([, e]) => e === "/search").map(([c, e, p]) => dedupKey(c, e, p, base)),
  );
  assert.equal(searchKeys.size, 1);
});

test("canonical categories are idempotent and dedupe stably", () => {
  // record_finding passes the canonical category enum → coarseClass must be idempotent
  // (in particular xss-stored must not be mis-folded into xss-reflected).
  for (const c of CATEGORIES) {
    assert.equal(coarseClass(c), c, `coarseClass(${c}) should be idempotent`);
  }
  assert.notEqual(
    dedupKey("xss-stored", "/support/new", "body", base),
    dedupKey("xss-reflected", "/support/new", "body", base),
  );
  const holes: Array<[string, string, string | undefined]> = [
    ["xss-reflected", "/search", "q"],
    ["path-traversal", "/download", "file"],
    ["idor", "/addresses/{id}", undefined],
    ["idor", "/orders/o10", undefined],
    ["idor-write", "/addresses/12/edit", undefined],
    ["idor", "/orders/o10/receipt", undefined],
    ["xss-stored", "/support/new", "body"],
    ["xss-stored", "/support/tickets/42", "body"],
  ];
  assert.equal(new Set(holes.map(([c, e, p]) => dedupKey(c, e, p, base))).size, 8);
});

test("appWideSignature folds server-wide defects across endpoints (the low-noise fix)", () => {
  // a-mvor6nuu: ~30 low findings that were really 2 issues — a global verbose-error handler
  // (stack traces) and a missing security-header policy. Same mechanism → one dedup key, so
  // repeat reports merge into a single finding accumulating affected endpoints.
  const sig = (c: string, t: string) => dedupKey(c, "/api/Addresss/{id}", undefined, base, appWideSignature(c, t));
  const sig2 = (c: string, t: string) => dedupKey(c, "/rest/track-order", undefined, base, appWideSignature(c, t));
  // missing headers on two endpoints → one key
  assert.equal(sig("headers", "Missing Content-Security-Policy on /api/Addresss/{id}"), sig2("headers", "Missing security headers on /rest/track-order"));
  // verbose stack traces under different labels merge — the mechanism is the key, not the category spelling
  assert.equal(
    sig("info-disclosure", "Verbose Express stack trace disclosed by /api/Addresss"),
    sig2("misconfig", "Verbose 500 stack trace leaks internal paths on /rest/track-order"),
  );
  // directory listing under two roots → one key
  assert.equal(sig("info-disclosure", "Directory listing of /ftp/"), sig2("info-disclosure", "Directory listing at /support/logs"));
  // endpoint-specific disclosures keep their endpoint — never fold into a different hole
  assert.notEqual(
    dedupKey("info-disclosure", "/api/Users/{id}", undefined, base, appWideSignature("info-disclosure", "read another user's PII from /api/Users/5")),
    dedupKey("info-disclosure", "/rest/track-order/{id}", undefined, base, appWideSignature("info-disclosure", "read another user's order")),
  );
  // ...and they never merge into the app-wide buckets either
  assert.notEqual(
    dedupKey("info-disclosure", "/api/Users/{id}", undefined, base, appWideSignature("info-disclosure", "PII leak")),
    sig("info-disclosure", "stack trace leaked"),
  );
  // a real distinct category is untouched
  assert.equal(appWideSignature("idor", "stack trace anything"), null);
  // a-mvor6nuu f-073/f-077: the CLAIM is a distinct hole (extension bypass / file read) — incidental
  // description words like "allow-list", "listing", or "framework version" must NOT swallow it.
  assert.equal(appWideSignature("misconfig", "Quarantined malware files downloadable without auth, bypassing the /ftp extension allow-list"), null);
  assert.equal(appWideSignature("info-disclosure", "Restricted backup manifest and internal detection config readable via null-byte extension bypass"), null);
  // verbose/unhandled error phrasings still fold into the stack-trace mechanism
  assert.equal(appWideSignature("info-disclosure", "Unhandled internal error (sortQuery.split) discloses details"), "stack-trace");
  assert.equal(appWideSignature("info-disclosure", "Verbose error page on /ftp leaks internals"), "stack-trace");
});

test("appWideSignature: a-mvpd1md3 missed phrasings — auto-index, unsigned-JWT, soft-404", () => {
  // 20 rows of ONE serve-index mechanism were titled "...auto-index confirmed (lead x)" — the old
  // 'directory listing|index of|serve-index' pattern never matched the 'auto-index' wording.
  assert.equal(appWideSignature("misconfig", "/ftp unauthenticated auto-index confirmed (lead 97e965db)"), "dir-listing");
  assert.equal(appWideSignature("misconfig", "Directory auto-index at /ftp/quarantine/ (lead4)"), "dir-listing");
  assert.equal(appWideSignature("info-disclosure", "/ftp exposes an unauthenticated auto-index (lead a95ed2e0)"), "dir-listing");

  // JWT signature non-verification is ONE middleware property — sibling labels and endpoints fold.
  assert.equal(appWideSignature("session", "Unsigned JWT (alg:none) accepted — auth bypass on POST /api/Quantitys"), "jwt-no-verify");
  assert.equal(appWideSignature("session", "JWT signature never verified on /rest/order-history"), "jwt-no-verify");
  assert.equal(appWideSignature("session", "JWT signature verification bypass — unsigned alg:none token accepted as admin"), "jwt-no-verify");
  assert.equal(appWideSignature("session", "/profile serves authenticated profile content to an unsigned (alg:none) JWT"), "jwt-no-verify");
  assert.equal(appWideSignature("session", "Unsigned alg:none JWT accepted as a valid session → admin impersonation"), "jwt-no-verify");
  assert.equal(appWideSignature("secret-exposure", "All users' security-answer hashes exposed unauthenticated via alg:none JWT"), "jwt-no-verify");
  // ...but a session finding about a DIFFERENT mechanism (cookie attribute, weak secret) is not this hole.
  assert.equal(appWideSignature("session", "JS-readable (non-HttpOnly) session JWT cookie is the sole auth credential"), null);
  assert.equal(appWideSignature("session", "Weak HMAC secret on session JWT allows offline forgery"), null);

  // One catch-all handler answering unknown paths with a 200 shell — reported once per prefix.
  assert.equal(appWideSignature("misconfig", "Soft-404: unknown /promotion sub-paths return HTTP 200 SPA"), "soft-404");
  assert.equal(appWideSignature("misconfig", "Missing static assets masked by SPA catch-all (soft 404 returns 200)"), "soft-404");
  assert.equal(appWideSignature("misconfig", "api-docs/openapi.json asset: soft-404 Swagger UI shell instead of spec"), "soft-404");
  assert.equal(appWideSignature("misconfig", "/promotion asset returns 200 SPA shell for arbitrary non-existent paths"), "soft-404");
  // ...and a misconfig that isn't a catch-all claim stays endpoint-scoped.
  assert.equal(appWideSignature("misconfig", "CAPTCHA challenge endpoint discloses its own answer"), null);
});

test("appWideSignature: cited forge evidence is a language-independent jwt-no-verify signal", () => {
  // A non-English title defeats every title regex — the probe_jwt evidence record still identifies the
  // mechanism, so --language runs keep the app-wide fold (and the sibling labels it spans).
  const jwt = [{ validator: "claude-pilot-jwt" }];
  assert.equal(appWideSignature("session", "署名未検証のJWTが受理された", jwt), "jwt-no-verify");
  assert.equal(appWideSignature("info-disclosure", "JWT未検証で注文履歴が読める", jwt), "jwt-no-verify");
  assert.equal(appWideSignature("secret-exposure", "全ユーザーのハッシュが漏洩", jwt), "jwt-no-verify");
  // cat scope: a non-forge category citing jwt evidence as supporting material keeps its own key
  assert.equal(appWideSignature("idor", "JWT未検証で他人のデータ", jwt), null);
  // unrelated evidence can't conjure the fold either
  assert.equal(appWideSignature("session", "署名未検証のJWTが受理された", [{ validator: "claude-pilot-session" }]), null);
});
