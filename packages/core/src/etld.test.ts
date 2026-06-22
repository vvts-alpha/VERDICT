import { test } from "node:test";
import assert from "node:assert/strict";
import { registrableDomain } from "./etld.js";

test("registrableDomain: plain 2-label domain stays as-is", () => {
  assert.equal(registrableDomain("example.com"), "example.com");
});

test("registrableDomain: subdomains collapse to eTLD+1", () => {
  assert.equal(registrableDomain("app.example.com"), "example.com");
  assert.equal(registrableDomain("api.staging.example.com"), "example.com");
});

test("registrableDomain: multi-part ccTLDs keep 3 labels", () => {
  assert.equal(registrableDomain("app.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("www.example.co.jp"), "example.co.jp");
  assert.equal(registrableDomain("shop.example.com.au"), "example.com.au");
});

test("registrableDomain: bare eTLD+1 under a multi-part suffix is unchanged", () => {
  assert.equal(registrableDomain("example.co.uk"), "example.co.uk");
});

test("registrableDomain: IPs and single labels are returned verbatim", () => {
  assert.equal(registrableDomain("127.0.0.1"), "127.0.0.1");
  assert.equal(registrableDomain("localhost"), "localhost");
});

test("registrableDomain: case-insensitive and trailing dot tolerant", () => {
  assert.equal(registrableDomain("App.Example.COM"), "example.com");
  assert.equal(registrableDomain("app.example.com."), "example.com");
});
