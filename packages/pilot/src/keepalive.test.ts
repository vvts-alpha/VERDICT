// Keepalive raw-HTTP touch helpers — mergeSetCookie (pick up a rotated session cookie without a page load) and
// touchIsDead (spot an expired session from the touch response). Both are pure, so no driver/network needed.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mergeSetCookie, touchIsDead } from "./tools.js";

test("mergeSetCookie: no Set-Cookie leaves the header unchanged", () => {
  assert.equal(mergeSetCookie("verdict_session=abc; other=1", undefined), "verdict_session=abc; other=1");
  assert.equal(mergeSetCookie("verdict_session=abc", ""), "verdict_session=abc");
});

test("mergeSetCookie: a rotated cookie overwrites its old value, others survive", () => {
  const merged = mergeSetCookie("verdict_session=OLD; keep=1", "verdict_session=NEW; Path=/; HttpOnly");
  assert.equal(merged, "verdict_session=NEW; keep=1");
});

test("mergeSetCookie: a brand-new cookie is added alongside the existing ones", () => {
  const merged = mergeSetCookie("a=1", "csrf=xyz; Path=/");
  assert.equal(merged, "a=1; csrf=xyz");
});

test("mergeSetCookie: a comma inside Expires does not split a single cookie", () => {
  const merged = mergeSetCookie("sid=old", "sid=new; Expires=Wed, 09-Jun-2027 10:18:14 GMT; Path=/");
  assert.equal(merged, "sid=new");
});

test("mergeSetCookie: undici-joined multiple Set-Cookie both apply", () => {
  const merged = mergeSetCookie("sid=old; theme=dark", "sid=new; Path=/, token=T2; Expires=Wed, 09-Jun-2027 10:18:14 GMT");
  assert.equal(merged, "sid=new; theme=dark; token=T2");
});

test("mergeSetCookie: an empty value is ignored (never drops a live cookie)", () => {
  const merged = mergeSetCookie("sid=live", "sid=; Max-Age=0");
  assert.equal(merged, "sid=live");
});

test("touchIsDead: 401/403 mean the session expired", () => {
  assert.equal(touchIsDead(401, undefined, "{}"), true);
  assert.equal(touchIsDead(403, undefined, "forbidden"), true);
});

test("touchIsDead: a redirect to a login-ish location is dead", () => {
  assert.equal(touchIsDead(302, "https://app.example.com/login?next=/orders", ""), true);
  assert.equal(touchIsDead(302, "https://app.example.com/dashboard", ""), false);
});

test("touchIsDead: a login/denied body is dead even on a 200", () => {
  assert.equal(touchIsDead(200, undefined, "<form>Please sign in with your password</form>"), true);
});

test("touchIsDead: a normal authed 200 is alive", () => {
  assert.equal(touchIsDead(200, undefined, '{"orders":[{"id":1}]}'), false);
});
