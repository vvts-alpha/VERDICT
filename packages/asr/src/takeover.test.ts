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

test("detectTakeover: a non-vulnerable service (Shopify) is flagged but vulnerable:false", () => {
    const t = detectTakeover({ cnames: ["shop.myshopify.com"], status: 404, body: "Sorry, this shop is currently unavailable" });
    assert.equal(t?.service, "Shopify");
    assert.equal(t?.vulnerable, false);
});
