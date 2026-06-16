// Burp REST の issue_events → BurpIssue マッピング(取り込み経路に乗せる)。pure 部分を固定。

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { restIssuesToBurpIssues, parseTaskId } from "./burp-rest.js";

const b64 = (s: string): string => Buffer.from(s, "utf8").toString("base64");

test("parseTaskId: bare '3' も '/v0.1/scan/3' も拾う(実機の Location は bare)", () => {
  assert.equal(parseTaskId("3"), "3");
  assert.equal(parseTaskId("/v0.1/scan/42"), "42");
  assert.equal(parseTaskId("http://127.0.0.1:1337/v0.1/scan/7"), "7");
  assert.equal(parseTaskId(""), null);
  assert.equal(parseTaskId("none"), null);
});

test("issue_found を BurpIssue 形にマップ(severity/host/path/detail + 証拠の base64 復号 + Cookie 伏字)", () => {
  const events = [
    {
      type: "issue_found",
      issue: {
        name: "SQL injection",
        origin: "https://app.example.com",
        path: "/search",
        severity: "high",
        description: "<b>SQLi</b> in <i>q</i>",
        remediation: "Use parameterized queries",
        evidence: [
          {
            request_response: {
              request: [{ type: "DataSegment", data: b64("GET /search?q=1 HTTP/1.1\r\nCookie: sid=secret\r\n\r\n") }],
              response: [{ type: "DataSegment", data: b64("HTTP/1.1 200 OK\r\n\r\nerror in SQL syntax") }],
            },
          },
        ],
      },
    },
  ];
  const [i] = restIssuesToBurpIssues(events);
  assert.ok(i);
  assert.equal(i.name, "SQL injection");
  assert.equal(i.host, "https://app.example.com");
  assert.equal(i.path, "/search");
  assert.equal(i.severity, "high");
  assert.equal(i.detail, "SQLi in q"); // タグ除去
  assert.match(i.request, /GET \/search/);
  assert.match(i.request, /Cookie: <redacted>/); // 資格情報は伏字
  assert.match(i.response, /error in SQL syntax/);
});

test("issue_found 以外と名前無しは除外", () => {
  const events = [
    { type: "issue_resolved", issue: { name: "stale" } },
    { type: "issue_found", issue: {} },
    { type: "issue_found", issue: { name: "Reflected XSS", origin: "https://x", path: "/p", severity: "medium" } },
  ];
  const out = restIssuesToBurpIssues(events);
  assert.equal(out.length, 1);
  assert.equal(out[0]?.name, "Reflected XSS");
  assert.equal(out[0]?.request, ""); // 証拠なしは空文字
});
