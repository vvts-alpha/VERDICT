import { test } from "node:test";
import assert from "node:assert/strict";

import { detectTakeover } from "./index.js";

test("detectTakeover: S3 NoSuchBucket + s3 CNAME → likely AWS/S3", () => {
    const t = detectTakeover({ cnames: ["mybucket.s3.amazonaws.com"], status: 404, body: "<Error><Code>NoSuchBucket</Code></Error>" });
    assert.equal(t?.service, "AWS/S3");
    assert.equal(t?.vulnerable, true);
    assert.equal(t?.confidence, "likely");
    assert.equal(t?.cname, "mybucket.s3.amazonaws.com");
});

test("detectTakeover: GitHub Pages fingerprint without a matching CNAME → potential", () => {
    const t = detectTakeover({ cnames: [], status: 404, body: "There isn't a GitHub Pages site here." });
    assert.equal(t?.service, "GitHub Pages");
    assert.equal(t?.confidence, "potential");
});

test("detectTakeover: dangling CNAME to github.io (nothing serves) → potential", () => {
    const t = detectTakeover({ cnames: ["victim.github.io"], status: null, body: "" });
    assert.equal(t?.service, "GitHub Pages");
    assert.equal(t?.confidence, "potential");
    assert.match(t?.note ?? "", /Dangling CNAME/);
});

test("detectTakeover: a claimed bucket (normal 200, no fingerprint) → null", () => {
    assert.equal(detectTakeover({ cnames: ["app.s3.amazonaws.com"], status: 200, body: "<html>my site</html>" }), null);
});

// Comprehensive claimed-vs-dangling review: a SERVING host behind a service that's generally NOT takeover-able is a
// CLAIMED live resource, not a takeover. These lock the CloudFront-403 false positive (secure.sophos.co.jp) shut.
test("detectTakeover: claimed CloudFront (serves the generic 403 error, CNAME resolves) → null, NOT a takeover", () => {
    const t = detectTakeover({ cnames: ["d30v7i0kora5sx.cloudfront.net"], status: 403, body: "ERROR: The request could not be satisfied" });
    assert.equal(t, null); // was wrongly flagged "likely / medium" — a live CloudFront distribution is claimed
});

test("detectTakeover: a serving Shopify (shop unavailable page) → null, NOT a takeover (usually claimed)", () => {
    const t = detectTakeover({ cnames: ["shop.myshopify.com"], status: 404, body: "Sorry, this shop is currently unavailable" });
    assert.equal(t, null);
});

test("detectTakeover: a vulnerable:true service serving its SPECIFIC unclaimed page is still a real lead", () => {
    // guards against over-suppressing: S3 NoSuchBucket served with a 404 must remain a takeover lead
    const t = detectTakeover({ cnames: ["gone.s3.amazonaws.com"], status: 404, body: "<Code>NoSuchBucket</Code>" });
    assert.equal(t?.vulnerable, true);
    assert.equal(t?.confidence, "likely");
});
