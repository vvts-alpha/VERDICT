// Parent-prefix backfill. Survey only enrolls what it navigated, so a controller/directory prefix (/Account implied by
// /Account/AccountEdit) that is itself a live page but was never linked stays unmapped — an un-clickable folder in the
// site tree (the a-mrk0y9tc symptom). deriveParentPrefixes lists every static ancestor that is NOT already a screen so a
// deterministic post-survey pass can probe it. These pin the pure derivation (the enrol pass is thin driver glue).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { deriveParentPrefixes } from "./tools.js";

const sc = (urlTemplate: string, host = "http://h") => ({ urlTemplate, observedUrls: [`${host}${urlTemplate}`] });

test("MVC controllers: derives the unmapped parent of each deep action, deduped", () => {
  const got = deriveParentPrefixes(
    [sc("/Account/AccountEdit"), sc("/Account/AccountMenu"), sc("/AccountPlayer/AccountPlayerList"), sc("/")],
    { targetUrl: "http://h/" },
  );
  assert.deepEqual(got, ["http://h/Account", "http://h/AccountPlayer"]);
});

test("a directory prefix (/Html from /Html/qa.html) is derived just the same", () => {
  const got = deriveParentPrefixes([sc("/Html/qa.html"), sc("/Html/TermsOfUse.html")], { targetUrl: "http://h/" });
  assert.deepEqual(got, ["http://h/Html"]);
});

test("a parent that is ALREADY a screen is not re-probed", () => {
  const got = deriveParentPrefixes(
    [sc("/Account"), sc("/Account/AccountEdit"), sc("/AccountPlayer/AccountPlayerList")],
    { targetUrl: "http://h/" },
  );
  assert.deepEqual(got, ["http://h/AccountPlayer"]); // /Account excluded (exists); /AccountPlayer kept
});

test("an ancestor containing a dynamic segment ({id}) is skipped, but a static shallower one is kept", () => {
  const got = deriveParentPrefixes([sc("/products/{id}/reviews")], { targetUrl: "http://h/" });
  assert.deepEqual(got, ["http://h/products"]); // NOT http://h/products/{id}
});

test("deep nesting yields every static ancestor (shallowest last)", () => {
  const got = deriveParentPrefixes([sc("/a/b/c")], { targetUrl: "http://h/" });
  assert.deepEqual(got, ["http://h/a/b", "http://h/a"]);
});

test("root-only inventory has no parent to derive", () => {
  assert.deepEqual(deriveParentPrefixes([sc("/")], { targetUrl: "http://h/" }), []);
});

test("ignore_paths prunes derived prefixes too", () => {
  const got = deriveParentPrefixes([sc("/cms/content/page1")], { targetUrl: "http://h/", ignorePaths: ["/cms"] });
  assert.deepEqual(got, []); // both /cms/content and /cms fall under the ignored /cms
});

test("a session-destroying ancestor (/account/logout) is never a probe candidate, but /account is", () => {
  const got = deriveParentPrefixes([sc("/account/logout/confirm")], { targetUrl: "http://h/" });
  assert.ok(!got.includes("http://h/account/logout")); // logout prefix filtered (GETting it would kill the session)
  assert.ok(got.includes("http://h/account")); // the safe shallower prefix survives
});

test("prefixes resolve against the screen's OWN origin (multi-host stays distinct)", () => {
  const got = deriveParentPrefixes(
    [
      { urlTemplate: "/api/users", observedUrls: ["https://api.example.com/api/users"] },
      { urlTemplate: "/app/home", observedUrls: ["https://app.example.com/app/home"] },
    ],
    { targetUrl: "https://app.example.com/" },
  );
  assert.ok(got.includes("https://api.example.com/api")); // origin taken from observedUrls, not the target
  assert.ok(got.includes("https://app.example.com/app"));
});
