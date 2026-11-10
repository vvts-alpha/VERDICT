// record_finding evidence-discipline structural check: ok only when the negative control is distinguishable from the positives and the positives are stable with each other.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { checkEvidenceDiscipline, checkLogicEvidence, citesForgeEvidence, sessionForgeClaim, sessionForgeControlOk } from "./tools.js";

const r = (status: number, bodyLen: number) => ({ status, bodyLen });
const lr = (status: number, hasMarker: boolean) => ({ status, hasMarker });
const req = (method: string, url: string) => ({ request: { method, url } });
const ctl = (method: string, url: string, status: number, body = "") => ({
  request: { method, url },
  response: { status, headers: {}, body },
});

test("ok: control fails (different status) + 2 stable positives", () => {
  assert.equal(checkEvidenceDiscipline(r(404, 12), [r(200, 800), r(200, 810)]).ok, true);
});

test("ok: differential by body length alone (same status)", () => {
  // IDOR-like: invalid id → 200/empty shell, valid adjacent id → 200/victim data
  assert.equal(checkEvidenceDiscipline(r(200, 40), [r(200, 900), r(200, 880)]).ok, true);
});

test("reject: fewer than 2 positive replays", () => {
  const v = checkEvidenceDiscipline(r(404, 0), [r(200, 800)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, />=2 positive/);
});

test("reject: positives disagree (unstable / flaky)", () => {
  const v = checkEvidenceDiscipline(r(404, 0), [r(200, 800), r(500, 30)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /unstable|disagree/);
});

test("reject: control indistinguishable from positives (catch-all)", () => {
  const v = checkEvidenceDiscipline(r(200, 805), [r(200, 800), r(200, 810)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /catch-all|indistinguishable/);
});

// ── business-logic marker-based gate ──
test("logic ok: marker accepted in 2 stable positives, absent in baseline", () => {
  // e.g. price=1 goes through and the order confirmation shows "total":1 (absent in the legitimate-price baseline)
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(200, true)]).ok, true);
});

test("logic reject: marker also in the legit baseline (not discriminating)", () => {
  const v = checkLogicEvidence(lr(200, true), [lr(200, true), lr(200, true)]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /baseline/);
});

test("logic reject: a manipulated replay lacks the marker (not accepted)", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(200, false)]).ok, false);
});

test("logic reject: a manipulated replay was rejected (>=400)", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true), lr(403, true)]).ok, false);
});

test("logic reject: fewer than 2 positives", () => {
  assert.equal(checkLogicEvidence(lr(200, false), [lr(200, true)]).ok, false);
});

// B6: reflected XSS confirms on a 4xx error page too (a payload reflected into a custom 403/404 still executes). The
// status<400 "accepted" gate is right for business-logic but wrong for reflection classes — requireSuccess:false skips it.
test("checkLogicEvidence: requireSuccess:false confirms a marker on a 4xx page (status doesn't gate reflection)", () => {
  const ctrl = { status: 200, hasMarker: false };
  const pos403 = [{ status: 403, hasMarker: true }, { status: 403, hasMarker: true }];
  assert.equal(checkLogicEvidence(ctrl, pos403).ok, false); // default (business-logic): status>=400 rejected
  assert.equal(checkLogicEvidence(ctrl, pos403, { requireSuccess: false }).ok, true); // XSS: error-page reflection still executes
});

// ── forge-acceptance session evidence: the control must isolate the auth variable ──
// a-mvpd1md3 lies: "alg:none JWT accepted" confirmed on a control that was a different endpoint+method
// (DELETE /api/Users/999999→401 vs GET /api/Users/1→200 — the GET is just public), or a WAF-500 on the
// same path. Neither demonstrated THIS surface refuses a request without the forged material.

test("sessionForgeClaim: titles that claim forged material was accepted", () => {
  assert.equal(sessionForgeClaim("Unsigned JWT (alg:none) accepted — auth bypass on POST /api/Quantitys"), true);
  assert.equal(sessionForgeClaim("JWT signature never verified on /rest/order-history"), true);
  assert.equal(sessionForgeClaim("JWT signature verification bypass — unsigned alg:none token accepted as admin"), true);
  assert.equal(sessionForgeClaim("/profile serves authenticated profile content to an unsigned (alg:none) JWT"), true);
  assert.equal(sessionForgeClaim("JS-readable (non-HttpOnly) session JWT cookie is the sole auth credential"), false);
  assert.equal(sessionForgeClaim("Session cookie missing Secure flag"), false);
  // over-match guard: "Session X bypass" stays gated (fixation IS forge-shaped — planted session
  // material accepted), but a crypto-strength finding with no acceptance claim does not.
  assert.equal(sessionForgeClaim("Session fixation bypass via unrotated cookie"), true);
  assert.equal(sessionForgeClaim("Weak JWT signature secret allows offline cracking"), false);
  // non-English titles skip the text claim — the structural signal (below) carries them
  assert.equal(sessionForgeClaim("署名未検証のJWTが受理された"), false);
});

test("citesForgeEvidence: a jwt validator record is the language-independent forge signal", () => {
  // A finding whose cited evidence came from probe_jwt is making a forge-acceptance claim
  // even when the title is in a language sessionForgeClaim can't parse.
  assert.equal(citesForgeEvidence([{ validator: "claude-pilot-jwt" }]), true);
  assert.equal(citesForgeEvidence([{ validator: "claude-pilot-jwt" }, { validator: "manual" }]), true);
  assert.equal(citesForgeEvidence([{ validator: "claude-pilot-session" }, { validator: "manual" }]), false);
  assert.equal(citesForgeEvidence([{}]), false);
  assert.equal(citesForgeEvidence([]), false);
});

test("sessionForgeControlOk ok: same-surface denial + forged replay accepted", () => {
  // probe_jwt shape: garbage token on E → 401; alg:none token on E → 200 (twice).
  assert.equal(
    sessionForgeControlOk(ctl("POST", "http://t/api/Quantitys", 401), [req("POST", "http://t/api/Quantitys"), req("POST", "http://t/api/Quantitys")]).ok,
    true,
  );
});

test("sessionForgeControlOk reject: control is a different endpoint+method (f-068)", () => {
  const v = sessionForgeControlOk(ctl("DELETE", "http://t/api/Users/999999", 401), [req("GET", "http://t/api/Users/1"), req("GET", "http://t/api/Users/1")]);
  assert.equal(v.ok, false);
  assert.match((v as { reason: string }).reason, /different surface/);
});

test("sessionForgeControlOk reject: same surface but the control was never a denial (f-127 WAF-500, f-126 200)", () => {
  const waf = sessionForgeControlOk(ctl("GET", "http://t/profile", 500, "<title>Error: Blocked illegal activity</title>"), [req("GET", "http://t/profile"), req("GET", "http://t/profile")]);
  assert.equal(waf.ok, false);
  assert.match((waf as { reason: string }).reason, /not a denial/);
  const pub = sessionForgeControlOk(ctl("GET", "http://t/rest/user/whoami", 200, "{}"), [req("GET", "http://t/rest/user/whoami"), req("GET", "http://t/rest/user/whoami")]);
  assert.equal(pub.ok, false);
  assert.match((pub as { reason: string }).reason, /not a denial/);
});

test("sessionForgeControlOk reject: control succeeded like the positives (endpoint is public — claim is vacuous)", () => {
  const v = sessionForgeControlOk(ctl("GET", "http://t/api/Users/1", 201), [req("GET", "http://t/api/Users/1"), req("GET", "http://t/api/Users/1")]);
  assert.equal(v.ok, false);
});

test("sessionForgeControlOk ok: login-redirect control counts as a denial", () => {
  const c = { request: { method: "GET", url: "http://t/rest/order-history" }, response: { status: 302, headers: { location: "/login" }, body: "" } };
  // isAuthRedirect treats a redirect to a login page as a refusal.
  assert.equal(sessionForgeControlOk(c, [req("GET", "http://t/rest/order-history"), req("GET", "http://t/rest/order-history")]).ok, true);
});
