import { strict as assert } from "node:assert";
import { test } from "node:test";
import { disclosureHit, looksLikeRobotsTxt, looksLikeSitemapXml, looksLikePublicWebFile } from "./disclosure.js";

test("disclosureHit: AWS key is secret-exposure (not ambient in control)", () => {
  // impact.ts: /\bAKIA[0-9A-Z]{16}\b/ ; PLACEHOLDERS include AKIAIOSFODNN7EXAMPLE
  const real = "AKIA" + "ABCDEFGHIJKLMNOP"; // 4+16
  const hit = disclosureHit(`creds ${real}`, "no secrets here");
  assert.equal(hit?.category, "secret-exposure");
  assert.ok(hit?.marker.includes("AKIA"));
});

test("disclosureHit: documentation placeholder AWS key is ignored", () => {
  assert.equal(disclosureHit("AKIAIOSFODNN7EXAMPLE in docs", ""), null);
});

test("disclosureHit: directory listing is info-disclosure", () => {
  const hit = disclosureHit("<html><title>Index of /backup</title>", "404 not found");
  assert.deepEqual(hit?.category, "info-disclosure");
  assert.equal(hit?.marker, "Index of");
});

test("disclosureHit: listing also in the control is ambient (not a hit)", () => {
  const listing = "<title>Index of /</title>";
  assert.equal(disclosureHit(listing, listing), null);
});

test("disclosureHit: Python traceback is info-disclosure", () => {
  const hit = disclosureHit("Traceback (most recent call last):\n  File \"app.py\"", "404");
  assert.equal(hit?.category, "info-disclosure");
  assert.equal(hit?.marker, "Traceback (most recent call last)");
});

const GMAPS_KEY = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";

test("disclosureHit: Maps JS loader key is not secret-exposure; hardcoded AIza still is", () => {
  const loader = `<script src="https://maps.googleapis.com/maps/api/js?v=weekly&key=${GMAPS_KEY}"></script>`;
  assert.equal(disclosureHit(loader, "404"), null);
  const hit = disclosureHit(`const KEY="${GMAPS_KEY}";`, "404");
  assert.equal(hit?.category, "secret-exposure");
});

test("looksLikeRobotsTxt: User-agent + Sitemap/Allow is robots.txt; WAF/HTML is not", () => {
  assert.equal(
    looksLikeRobotsTxt("User-agent: *\nAllow: /\nSitemap: https://locations.example.com/sitemap.xml\n"),
    true,
  );
  assert.equal(looksLikeRobotsTxt("<html><title>Request Rejected</title><body>The requested URL was rejected.</body></html>"), false);
  assert.equal(looksLikeRobotsTxt("<html><body>Find a Station</body></html>"), false);
});

test("looksLikeSitemapXml / looksLikePublicWebFile: urlset is a sitemap, not disclosure", () => {
  const sm = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://app.test/</loc></url></urlset>`;
  assert.equal(looksLikeSitemapXml(sm), true);
  assert.equal(looksLikePublicWebFile(sm), true);
  assert.equal(looksLikeSitemapXml("<html><body>not a sitemap</body></html>"), false);
});
