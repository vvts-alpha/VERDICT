import { strict as assert } from "node:assert";
import { test } from "node:test";
import { coerceFetchUrl, controlSvg, extractFetchUrls, xssSvg, xxeSvg } from "./upload.js";

test("coerceFetchUrl: absolute and root-relative only (bare filenames dropped)", () => {
  const base = "https://app.test/api/upload";
  assert.equal(coerceFetchUrl("https://app.test/files/a.svg", base), "https://app.test/files/a.svg");
  assert.equal(coerceFetchUrl("/files/a.svg", base), "https://app.test/files/a.svg");
  assert.equal(coerceFetchUrl("a.svg", base), null);
  assert.equal(coerceFetchUrl("javascript:alert(1)", base), null);
  assert.equal(coerceFetchUrl("data:text/html,x", base), null);
});

test("extractFetchUrls: JSON url + Location + html href", () => {
  const base = "https://app.test/upload";
  assert.deepEqual(
    extractFetchUrls(JSON.stringify({ ok: true, url: "/files/x.svg" }), {}, base),
    ["https://app.test/files/x.svg"],
  );
  assert.deepEqual(extractFetchUrls("ok", { location: "https://app.test/dl/1" }, base), ["https://app.test/dl/1"]);
  assert.deepEqual(
    extractFetchUrls(`<a href="/files/y.svg">y</a>`, {}, base),
    ["https://app.test/files/y.svg"],
  );
});

test("extractFetchUrls ignores a nested filename-only field", () => {
  assert.deepEqual(extractFetchUrls(JSON.stringify({ filename: "photo.svg", size: 12 }), {}, "https://app.test/u"), []);
});

test("xssSvg puts the marker in a live onerror attribute (not inside <script>)", () => {
  const svg = xssSvg("vXssTOK");
  assert.match(svg, /onerror="vXssTOK"/);
  assert.ok(!/<script/i.test(svg));
  assert.ok(controlSvg().includes("verdict-ctrl"));
});

test("xxeSvg plants a file:// ENTITY", () => {
  const xml = xxeSvg("file:///etc/passwd");
  assert.match(xml, /SYSTEM "file:\/\/\/etc\/passwd"/);
  assert.match(xml, /&xxe;/);
});
