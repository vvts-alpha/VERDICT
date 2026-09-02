// impactOracle: verifies each impact signal firing + two-stage FP suppression (placeholder / anti-ambient) + cross-user + CTF-default-OFF.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { impactOracle, formatImpact, identityAppears, classifyCrossUserBody, looksLikePublicCatalogPage, isBrowserGoogleMapsApiKey, isFirebaseWebApiKey, isRecaptchaSiteKey, isPublicByDesignClientCredential } from "./impact.js";

const kinds = (body: string, ctx = {}) => impactOracle(body, ctx).map((s) => s.kind);

test("detects concrete impact signals (passwd / private key / AWS key / uid / php / JWT)", () => {
  assert.ok(kinds("root:x:0:0:root:/root:/bin/bash").includes("file-leak"));
  assert.ok(kinds("-----BEGIN RSA PRIVATE KEY-----\nMIIE...").includes("secret"));
  assert.ok(kinds("creds: AKIA1234567890ABCDEF here").includes("secret"));
  assert.ok(kinds("uid=0(root) gid=0(root) groups=0(root)").includes("command-output"));
  assert.ok(kinds("<?php $db='secret'; ?>").includes("source-leak"));
  assert.ok(kinds("token eyJhbGciOiJIUzI1Ni19.eyJzdWIiOiIxIn0.abcdef here").includes("secret")); // JWT
});

test("detects Stripe / GitHub / GitLab / npm / SendGrid / Google-OAuth / OpenAI keys (first-party JS-bundle secrets)", () => {
  assert.ok(kinds("stripe(\"sk_live_51H8xQ2eZvKYlo2Cabcdef12345ghijk\")").includes("secret"));
  assert.ok(kinds("Authorization: token ghp_16C7e42F292c6912E7710c838347Ae178B4a01").includes("secret"));
  assert.ok(kinds("gitlab: glpat-ABCdef1234567890ghIJ").includes("secret"));
  assert.ok(kinds("//_authToken=npm_abcdefghijklmnopqrstuvwxyz0123456789").includes("secret"));
  assert.ok(kinds("SG.aBcDeFgHiJkLmNoPqRsTuv.aBcDeFgHiJkLmNoPqRsTuvWxYz01234567890123456").includes("secret"));
  assert.ok(kinds("client_secret: GOCSPX-abcdef1234567890ABCDEF").includes("secret"));
  assert.ok(kinds("openai='sk-proj-abcdef1234567890ABCDEFxyz'").includes("secret"));
  assert.deepEqual(kinds("const publishable = 'pk_test_notasecret'"), []); // publishable/test keys are not flagged
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

test("identityAppears: a DISTINCT token matches; an embedded substring does not (the false-cross-user fix)", () => {
  assert.ok(identityAppears('{"orderId":1002,"n":1}', "1002")); // standalone token
  assert.ok(!identityAppears('{"total":31002410}', "1002")); // embedded inside 31002410 → NOT a match
  assert.ok(identityAppears("order 6 belongs to victim", "6")); // single-digit standalone still works
});

test("cross-user does NOT fire when the victim id only appears EMBEDDED in an unrelated number", () => {
  // "1002" is not really referenced — it's a substring of the total 31002 → before word-boundary this false-confirmed IDOR
  assert.ok(!kinds("your order total is 31002 cents", { requestedIdentity: "1002", sessionIdentity: "77" }).includes("cross-user"));
});

test("classifyCrossUserBody: people-picker card (displayName + work email + tenant) is a directory; phone/address/internal id are sensitive", () => {
  assert.equal(classifyCrossUserBody('{"id":26,"username":"alice","displayName":"Alice"}', "26").class, "public-directory");
  assert.equal(classifyCrossUserBody('{"id":26,"name":"Alice","avatar":"https://cdn/a.png"}', "26").class, "public-directory");
  assert.equal(classifyCrossUserBody('{"id":26,"username":"alice","email":"alice@corp.test"}', "26").class, "public-directory");
  assert.equal(
    classifyCrossUserBody(
      '{"email":"ediscmanager@verticalediscovery.us","isDeleted":false,"photoUrl":"/api/Profiles/46564/photo","tenantId":8,"id":46564,"displayName":"edisc manager","tenantName":"verticalediscovery"}',
      "46564",
    ).class,
    "public-directory",
  );
  assert.equal(classifyCrossUserBody('{"id":26,"phone":"+81-90-1234-5678"}', "26").class, "sensitive-pii");
  assert.equal(classifyCrossUserBody('{"id":26,"address":"1 Main St"}', "26").class, "sensitive-pii");
  assert.equal(classifyCrossUserBody('{"id":"alice","userId":9981,"username":"alice"}', "alice").class, "sensitive-pii");
});

test("classifyCrossUserBody: order/basket JSON is a private object, not a public profile", () => {
  assert.equal(classifyCrossUserBody('{"order":6,"total":42,"owner":"victim"}', "6").class, "private-object");
  assert.equal(classifyCrossUserBody('{"id":2,"UserId":2,"Products":[{"id":1}]}', "2").class, "private-object");
});

test("cross-user does NOT fire on a tenant people-picker profile (work email + displayName is intended)", () => {
  const ctx = { requestedIdentity: "26", sessionIdentity: "1" };
  assert.ok(!kinds('{"id":26,"username":"alice","displayName":"Alice"}', ctx).includes("cross-user"));
  assert.ok(!kinds('{"id":26,"username":"alice","email":"alice@corp.test"}', ctx).includes("cross-user"));
  assert.ok(
    !kinds(
      '{"email":"ediscmanager@verticalediscovery.us","isDeleted":false,"photoUrl":"/api/Profiles/46564/photo","tenantId":8,"id":46564,"displayName":"edisc manager","tenantName":"verticalediscovery"}',
      { requestedIdentity: "46564", sessionIdentity: "48807" },
    ).includes("cross-user"),
  );
  assert.ok(kinds('{"id":26,"phone":"+81-90-1234-5678","displayName":"Alice"}', ctx).includes("cross-user"));
  assert.ok(kinds('{"order":6,"total":42,"owner":"victim"}', { requestedIdentity: "6", sessionIdentity: "5" }).includes("cross-user"));
});

test("CTF flag detection is OFF by default, ON only with an explicit flagRegex", () => {
  assert.deepEqual(kinds("FLAG{abc123}"), []); // no flagRegex → not a signal (no CTF coupling on real engagements)
  assert.ok(kinds("FLAG{abc123}", { flagRegex: /FLAG\{[^}]+\}/ }).includes("ctf-flag"));
});

test("formatImpact renders a readable one-liner", () => {
  const sig = impactOracle("uid=0(root) gid=0(root)");
  assert.match(formatImpact(sig), /command-output\[high\]/);
});

const VALERO_STORE = `<!doctype html>
<html lang="en"><head>
<meta property="og:type" content="place" />
<meta property="place:location:latitude" content="29.3187">
<meta property="place:location:longitude" content="-98.5541">
<meta name="description" content="Find a Valero gas station near you." />
<title>12511 SW LOOP 410</title>
<link rel="canonical" href="https://locations-xtest.valero.com/en-us/LocationDetails/Index/5602-UTSA-BLVD/0000021053" />
</head><body>
<a href="https://www.valero.com/find-station" class="is-active">Find a Station</a>
<a href="tel:2105550100">210-555-0100</a>
<address>12511 SW LOOP 410, San Antonio, TX</address>
</body></html>`;

test("looksLikePublicCatalogPage: Valero LocationDetails / og:type place is a store locator", () => {
  assert.equal(looksLikePublicCatalogPage(VALERO_STORE), true);
  assert.equal(looksLikePublicCatalogPage("<html><body>Receipt for order 12</body></html>"), false);
});

test("classifyCrossUserBody: public store locator is a directory even with address/tel on the page", () => {
  assert.equal(classifyCrossUserBody(VALERO_STORE, "0000021053").class, "public-directory");
});

test("cross-user does NOT fire on a public store/location catalog (Valero sequential store id is not IDOR)", () => {
  const ctx = { requestedIdentity: "0000021053", sessionIdentity: "" };
  assert.ok(!kinds(VALERO_STORE, ctx).includes("cross-user"));
});

// 39-char AIza fixture (same shape as a live key; not a credential). Must not match PLACEHOLDERS (no "dummy"/"example").
const GMAPS_KEY = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";

test("isBrowserGoogleMapsApiKey: Maps JS loader is public-by-design; hardcoded KEY= is not", () => {
  const loader = `<script src="https://maps.googleapis.com/maps/api/js?v=weekly&libraries=places&key=${GMAPS_KEY}"></script>`;
  assert.equal(isBrowserGoogleMapsApiKey(loader), true);
  assert.equal(isBrowserGoogleMapsApiKey(loader, GMAPS_KEY), true);
  assert.equal(isBrowserGoogleMapsApiKey(`const KEY="${GMAPS_KEY}";`), false);
  assert.equal(isBrowserGoogleMapsApiKey("no keys here"), false);
});

test("impactOracle: Google Maps JS API key in the loader is not a secret; .env / const KEY= still is", () => {
  const loader = `<script src="https://maps.googleapis.com/maps/api/js?v=weekly&libraries=places&key=${GMAPS_KEY}"></script>`;
  assert.deepEqual(kinds(loader), []);
  assert.ok(kinds(`GOOGLE_MAPS_API_KEY=${GMAPS_KEY}`).includes("secret"));
  assert.ok(kinds(`const KEY="${GMAPS_KEY}";`).includes("secret"));
});

test("Firebase web apiKey / reCAPTCHA site key are public-by-design; hardcoded AIza is not", () => {
  const fb = `firebase.initializeApp({apiKey:"${GMAPS_KEY}",authDomain:"app.firebaseapp.com"});`;
  assert.equal(isFirebaseWebApiKey(fb), true);
  assert.equal(isPublicByDesignClientCredential(fb), true);
  assert.deepEqual(kinds(fb), []);
  const site = "6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_M5";
  const widget = `<div class="g-recaptcha" data-sitekey="${site}"></div><script src="https://www.google.com/recaptcha/api.js"></script>`;
  assert.equal(isRecaptchaSiteKey(widget), true);
  assert.equal(isPublicByDesignClientCredential(widget), true);
  assert.equal(isPublicByDesignClientCredential(`const KEY="${GMAPS_KEY}";`), false);
});
