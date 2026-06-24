import { test } from "node:test";
import assert from "node:assert/strict";
import { buildRawRequest, auditIssuesToBurpIssues } from "./burp-audit.js";

test("buildRawRequest: GET with session headers, CRLF, no body", () => {
  const raw = buildRawRequest({
    method: "get",
    pathWithQuery: "/shop?q=test",
    hostHeader: "192.168.74.148:8000",
    headers: { Cookie: "session=abc", Authorization: "Bearer jwt.tok" },
  });
  assert.match(raw, /^GET \/shop\?q=test HTTP\/1\.1\r\n/);
  assert.match(raw, /\r\nHost: 192\.168\.74\.148:8000\r\n/);
  assert.match(raw, /\r\nCookie: session=abc\r\n/);
  assert.match(raw, /\r\nAuthorization: Bearer jwt\.tok\r\n/);
  assert.ok(raw.endsWith("\r\n\r\n")); // body 無し → ヘッダ終端で終わる
  assert.ok(!/Content-Length/.test(raw));
});

test("buildRawRequest: POST sets Content-Type + correct byte Content-Length", () => {
  const body = '{"email":"a@b","n":1}';
  const raw = buildRawRequest({
    method: "POST",
    pathWithQuery: "/api/login",
    hostHeader: "x.test",
    headers: { Cookie: "s=1" },
    body,
    contentType: "application/json",
  });
  assert.match(raw, /\r\nContent-Type: application\/json\r\n/);
  assert.match(raw, new RegExp(`\\r\\nContent-Length: ${Buffer.byteLength(body)}\\r\\n`));
  assert.ok(raw.endsWith("\r\n\r\n" + body));
});

test("auditIssuesToBurpIssues: maps fields, decodes evidence, redacts, drops FALSE_POSITIVE", () => {
  const reqB64 = Buffer.from("GET /shop?q=x HTTP/1.1\r\nCookie: session=secret\r\n\r\n", "utf8").toString("base64");
  const respB64 = Buffer.from("HTTP/1.1 200 OK\r\n\r\n<b>xss</b>", "utf8").toString("base64");
  const out = auditIssuesToBurpIssues([
    {
      found_at: 1,
      name: "Cross-site scripting (reflected)",
      severity: "HIGH",
      confidence: "FIRM",
      url: "http://192.168.74.148:8000/shop",
      detail: "reflected",
      evidence: [{ request_b64: reqB64, response_b64: respB64 }],
    },
    { name: "noise", severity: "FALSE_POSITIVE", url: "http://x/y" }, // 捨てる
    { severity: "HIGH" }, // name 無し → 捨てる
  ]);
  assert.equal(out.length, 1);
  const i = out[0]!;
  assert.equal(i.name, "Cross-site scripting (reflected)");
  assert.equal(i.host, "http://192.168.74.148:8000");
  assert.equal(i.path, "/shop");
  assert.equal(i.severity, "HIGH"); // burpSeverity が後段で high に正規化
  assert.match(i.detail, /confidence: FIRM/);
  assert.match(i.request, /Cookie: <redacted>/); // 伏字
  assert.match(i.response, /<b>xss<\/b>/);
});
