// Regression: an unreachable host behind --burp-proxy returns a Burp "SOCKS: Host unreachable" page (often HTTP 200).
// probe_headers / record_finding must refuse it, else it produces false "missing header" findings on a host that was
// never actually reached (the ca-xtest.valero.com run recorded 4 such false findings on a Burp error page).
import { test } from "node:test";
import assert from "node:assert/strict";
import { looksLikeProxyError } from "./tools.js";

test("looksLikeProxyError flags a Burp SOCKS 'Host unreachable' page", () => {
  const burp = `<html><head><title>Burp Suite</title></head><body><h1>Error</h1><p>SOCKS: Host unreachable</p></body></html>`;
  assert.equal(looksLikeProxyError(burp), true);
});

test("looksLikeProxyError flags tunnel/proxy connection errors", () => {
  assert.equal(looksLikeProxyError("ERR_TUNNEL_CONNECTION_FAILED"), true);
  assert.equal(looksLikeProxyError("Proxy error: tunnel connection failed"), true);
  assert.equal(looksLikeProxyError("ERR_PROXY_CONNECTION_FAILED"), true);
});

test("looksLikeProxyError does NOT flag a real application page", () => {
  const realPage = `<html><head><title>Valero MyCard</title></head><body><form action="SignIn.aspx">Sign In</form></body></html>`;
  assert.equal(looksLikeProxyError(realPage), false);
});
