// Unit tests for the FAM-1 injection-location factory (pure, no network).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import type { HttpRequest } from "@veritas/scanner";
import { parseLocation, placePayload, oobFilesToMultipart, filesHaveOobPlaceholder } from "./inject.js";

const base = (over: Partial<HttpRequest> = {}): HttpRequest => ({ method: "GET", url: "https://app.test/api/orders/42?sort=asc", headers: { "x-a": "1" }, body: null, ...over });

test("parseLocation parses each form and rejects malformed", () => {
  assert.deepEqual(parseLocation("query:q"), { kind: "query", name: "q" });
  assert.deepEqual(parseLocation("header:X-Forwarded-For"), { kind: "header", name: "X-Forwarded-For" });
  assert.deepEqual(parseLocation("cookie:sid"), { kind: "cookie", name: "sid" });
  assert.deepEqual(parseLocation("path"), { kind: "path" });
  assert.deepEqual(parseLocation("path:2"), { kind: "path", index: 2 });
  assert.deepEqual(parseLocation("path:-1"), { kind: "path", index: -1 });
  assert.deepEqual(parseLocation("json:/user/id"), { kind: "json", pointer: "/user/id" });
  assert.deepEqual(parseLocation("json:user.id"), { kind: "json", pointer: "user.id" });
  assert.equal(parseLocation("query:"), null); // missing name
  assert.equal(parseLocation("bogus:x"), null);
  assert.equal(parseLocation("path:abc"), null); // non-integer index
});

test("placePayload query sets/overwrites the param, keeps other params", () => {
  const r = placePayload(base(), { kind: "query", name: "id" }, "1' AND SLEEP(5)-- -")!;
  const u = new URL(r.url);
  assert.equal(u.searchParams.get("id"), "1' AND SLEEP(5)-- -");
  assert.equal(u.searchParams.get("sort"), "asc"); // untouched
  assert.equal(r.headers!["x-a"], "1"); // base headers preserved
});

test("placePayload header is case-insensitive overwrite", () => {
  const r = placePayload(base({ headers: { "User-Agent": "orig", "x-a": "1" } }), { kind: "header", name: "user-agent" }, "p4yload")!;
  // exactly one user-agent header, with the injected value
  const uaKeys = Object.keys(r.headers!).filter((k) => k.toLowerCase() === "user-agent");
  assert.equal(uaKeys.length, 1);
  assert.equal(r.headers![uaKeys[0]!], "p4yload");
  assert.equal(r.headers!["x-a"], "1");
});

test("placePayload cookie merges into an existing Cookie header, preserving other cookies", () => {
  const r = placePayload(base({ headers: { Cookie: "sid=abc; theme=dark" } }), { kind: "cookie", name: "sid" }, "x' OR 1=1")!;
  const c = r.headers!["Cookie"]!;
  assert.match(c, /sid=x' OR 1=1/);
  assert.match(c, /theme=dark/);
  // sid appears once (replaced, not duplicated)
  assert.equal(c.match(/sid=/g)!.length, 1);
});

test("placePayload cookie creates the Cookie header when none exists", () => {
  const r = placePayload(base({ headers: {} }), { kind: "cookie", name: "tracking" }, "v")!;
  assert.equal(r.headers!["Cookie"], "tracking=v");
});

test("placePayload path replaces the last segment by default, encoded", () => {
  const r = placePayload(base(), { kind: "path" }, "1 OR 1=1")!;
  const u = new URL(r.url);
  assert.equal(u.pathname, "/api/orders/1%20OR%201%3D1");
  assert.equal(u.searchParams.get("sort"), "asc"); // query preserved
});

test("placePayload path targets a specific and a negative index", () => {
  assert.equal(new URL(placePayload(base(), { kind: "path", index: 0 }, "X")!.url).pathname, "/X/orders/42");
  assert.equal(new URL(placePayload(base(), { kind: "path", index: -1 }, "X")!.url).pathname, "/api/orders/X");
  assert.equal(placePayload(base(), { kind: "path", index: 9 }, "X"), null); // out of range
});

test("placePayload path returns null when there is no segment", () => {
  assert.equal(placePayload(base({ url: "https://app.test/" }), { kind: "path" }, "X"), null);
});

test("placePayload json sets a nested field and application/json content-type", () => {
  const r = placePayload(base({ method: "POST", body: null }), { kind: "json", pointer: "/user/name" }, "' OR '1'='1")!;
  assert.deepEqual(JSON.parse(r.body!), { user: { name: "' OR '1'='1" } });
  const ct = Object.entries(r.headers!).find(([k]) => k.toLowerCase() === "content-type")?.[1];
  assert.equal(ct, "application/json");
});

test("placePayload json merges into an existing JSON body, dotted pointer", () => {
  const r = placePayload(base({ method: "POST", body: JSON.stringify({ q: "orig", page: 2 }) }), { kind: "json", pointer: "q" }, "{{X}}")!;
  assert.deepEqual(JSON.parse(r.body!), { q: "{{X}}", page: 2 });
});

test("placePayload json honors an explicit contentType override", () => {
  const r = placePayload(base({ method: "POST" }), { kind: "json", pointer: "a" }, "v", "application/vnd.api+json")!;
  const ct = Object.entries(r.headers!).find(([k]) => k.toLowerCase() === "content-type")?.[1];
  assert.equal(ct, "application/vnd.api+json");
});

test("placePayload json declines a non-object body / unparseable body", () => {
  assert.equal(placePayload(base({ method: "POST", body: "[1,2,3]" }), { kind: "json", pointer: "a" }, "v"), null);
  assert.equal(placePayload(base({ method: "POST", body: "not json" }), { kind: "json", pointer: "a" }, "v"), null);
});

test("placePayload query returns null on an unparseable url", () => {
  assert.equal(placePayload(base({ url: "::::" }), { kind: "query", name: "q" }, "v"), null);
});

test("placePayload does not mutate the base request", () => {
  const b = base({ headers: { "x-a": "1" } });
  placePayload(b, { kind: "header", name: "x-a" }, "changed");
  assert.equal(b.headers!["x-a"], "1"); // original untouched
});

test("oobFilesToMultipart substitutes {{OOB}} into text content and base64-encodes it", () => {
  const sub = (v: string) => v.replace(/\{\{OOB\}\}/g, "abc.oastify.test");
  const mp = oobFilesToMultipart([{ name: "file", filename: "x.svg", contentType: "image/svg+xml", content: '<svg><!ENTITY x SYSTEM "http://{{OOB}}/">' }], sub);
  assert.equal(mp.files.length, 1);
  assert.equal(mp.files[0]!.filename, "x.svg");
  assert.equal(mp.files[0]!.contentType, "image/svg+xml");
  assert.equal(Buffer.from(mp.files[0]!.base64, "base64").toString("utf8"), '<svg><!ENTITY x SYSTEM "http://abc.oastify.test/">');
});

test("oobFilesToMultipart passes pre-encoded base64 through unchanged (no substitution)", () => {
  const b64 = Buffer.from("GIF89a\x00raw").toString("base64");
  const mp = oobFilesToMultipart([{ name: "f", filename: "x.gif", base64: b64 }], (v) => v.replace("{{OOB}}", "H"));
  assert.equal(mp.files[0]!.base64, b64);
});

test("filesHaveOobPlaceholder detects {{OOB}} only in substitutable text content", () => {
  assert.equal(filesHaveOobPlaceholder([{ content: "a {{OOB}} b" }], "{{OOB}}"), true);
  assert.equal(filesHaveOobPlaceholder([{ content: "no marker" }], "{{OOB}}"), false);
  assert.equal(filesHaveOobPlaceholder(undefined, "{{OOB}}"), false);
  // base64 wins over content in the sender, so a marker in content is NOT substitutable → gate must NOT pass on it
  assert.equal(filesHaveOobPlaceholder([{ content: "{{OOB}}", base64: "QUJD" }], "{{OOB}}"), false);
});

test("parseLocation rejects a path index with trailing garbage (does not silently mis-aim)", () => {
  assert.equal(parseLocation("path:2abc"), null);
  assert.equal(parseLocation("path:0x10"), null);
  assert.equal(parseLocation("path:1e3"), null);
  assert.deepEqual(parseLocation("path:-2"), { kind: "path", index: -2 });
});

test("placePayload json rejects prototype-chain keys and never pollutes Object.prototype", () => {
  const b = base({ method: "POST", body: null });
  assert.equal(placePayload(b, { kind: "json", pointer: "/__proto__/isAdmin" }, "yes"), null);
  assert.equal(placePayload(b, { kind: "json", pointer: "constructor.prototype.x" }, "yes"), null);
  assert.equal(placePayload(b, { kind: "json", pointer: "__proto__.polluted" }, "PWNED"), null);
  // the global prototype was NOT touched by any of the above
  assert.equal(({} as Record<string, unknown>)["isAdmin"], undefined);
  assert.equal(({} as Record<string, unknown>)["polluted"], undefined);
  assert.equal(({} as Record<string, unknown>)["x"], undefined);
});
