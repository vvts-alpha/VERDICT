// Error/login catch-all handling — looksLikeErrorCatchAll (don't enroll the error page / don't derail the crawl onto it)
// and frontierLinks skipping referer-gated routes. Grounded in the a-mre85zq4 ASP.NET run (ErrLogin/ErrFatal catch-all).

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { looksLikeErrorCatchAll, frontierLinks, anchorLinkSelectors } from "./tools.js";
import { deriveScopeFromUrls } from "@veritas/core";

const obs = (o: { requestedUrl: string; finalUrl: string; visibleText?: string }) => ({
  requestedUrl: o.requestedUrl,
  finalUrl: o.finalUrl,
  visibleText: o.visibleText ?? "",
});

test("catch-all: ASP.NET aspxerrorpath redirect is an error page", () => {
  assert.equal(
    looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/CupEntry/EntryCupList", finalUrl: "http://x/Html/ErrFatal.html?aspxerrorpath=/CupEntry/EntryCupList" })),
    true,
  );
});

test("catch-all: an ErrX / error / 404 static page is an error page", () => {
  assert.equal(looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/a", finalUrl: "http://x/Html/ErrLogin.html" })), true);
  assert.equal(looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/a", finalUrl: "http://x/error.aspx" })), true);
  assert.equal(looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/a", finalUrl: "http://x/404.html" })), true);
});

test("catch-all: a bounce (requested != final) onto a login/denied body is an error page", () => {
  assert.equal(
    looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/orders/9", finalUrl: "http://x/account/gate", visibleText: "Please sign in with your password to continue" })),
    true,
  );
});

test("not catch-all: a real authenticated screen", () => {
  assert.equal(looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/orders", finalUrl: "http://x/orders", visibleText: "Your orders: #1001 #1002" })), false);
});

test("not catch-all: navigating directly to the login page (requested == final, no bounce) is a real screen", () => {
  // A login page reached without a redirect is a legitimate screen to map — only a BOUNCE onto a login body is the tell.
  assert.equal(looksLikeErrorCatchAll(obs({ requestedUrl: "http://x/login", finalUrl: "http://x/login", visibleText: "sign in / password" })), false);
});

test("frontierLinks skips referer-gated routes (won't re-queue a route that bounces on cold nav)", () => {
  const scope = deriveScopeFromUrls(["https://app.example.com/"], "etld");
  const s = {
    scope,
    lockToSeeds: false,
    visited: new Set<string>(),
    ignorePaths: [] as string[],
    targetUrl: "https://app.example.com/",
    refererGated: new Set<string>(["https://app.example.com/CupEntry/EntryCupList"]),
  };
  const o = { finalUrl: "https://app.example.com/menu", links: ["https://app.example.com/CupEntry/EntryCupList", "https://app.example.com/ok"] };
  const got = new Set(frontierLinks(o, s));
  assert.ok(!got.has("https://app.example.com/CupEntry/EntryCupList"), "referer-gated route must not be re-queued");
  assert.ok(got.has("https://app.example.com/ok"), "a normal link is still queued");
});

test("anchorLinkSelectors: exact path, absolute URL, and suffix variants to find the link on the anchor page", () => {
  const sels = anchorLinkSelectors("http://133.125.102.119/CupEntry/EntryCupList");
  assert.deepEqual(sels, [
    'a[href="/CupEntry/EntryCupList"]',
    'a[href="http://133.125.102.119/CupEntry/EntryCupList"]',
    'a[href$="/CupEntry/EntryCupList"]',
  ]);
});
