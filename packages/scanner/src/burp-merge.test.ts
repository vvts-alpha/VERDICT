// Burp INFO の per-URL 重複を畳む(同一 issue 名 = 1 finding + URL リスト)。
// Burp は "CORS: arbitrary origin trusted" を URL ごとに吐くので、畳まないとレポートが水増しする。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Finding, ScopePolicy } from "@veritas/core";
import { mergeBurpIssues } from "./burp-merge.js";
import type { BurpIssue } from "./burp.js";

const scope: ScopePolicy = {
  inScopeHosts: ["app.example.com"],
  outOfScopeHosts: [],
  inScopePathPrefixes: ["/"],
  outOfScopePathPrefixes: [],
  approvalPathPrefixes: [],
  approvalMethods: [],
  rate: { requestsPerMinute: 60, maxConcurrent: 2 },
};

function fakeStore() {
  const findings: Finding[] = [];
  return { findings, store: { upsertFinding: (_id: string, f: Finding) => findings.push(f) } };
}

function issue(name: string, path: string, severity = "Information"): BurpIssue {
  return { name, host: "https://app.example.com", path, severity, detail: `${name} detail`, background: "", request: "", response: "" } as BurpIssue;
}

test("collapses the same Burp issue across many URLs into ONE finding with a URL list", () => {
  const { findings, store } = fakeStore();
  const issues = [
    issue("CORS: arbitrary origin trusted", "/"),
    issue("CORS: arbitrary origin trusted", "/api-docs/"),
    issue("CORS: arbitrary origin trusted", "/robots.txt"),
    issue("CORS: arbitrary origin trusted", "/ftp/legal.md"),
    issue("Robots.txt file", "/robots.txt"),
  ];
  const dir = mkdtempSync(join(tmpdir(), "burpmerge-"));
  const res = mergeBurpIssues(store, "a-1", { findings: [], scope }, dir, issues);
  // 4 件の CORS → 1 finding、robots → 1 finding = 計 2(以前は per-URL で 5 件に膨れていた)。
  assert.equal(res.added, 2);
  const cors = findings.find((f) => f.title.includes("CORS"))!;
  assert.match(cors.title, /\(4 URLs\)/);
  assert.match(cors.description, /\+3 more URL\(s\)/);
  // 代表 URL が末尾 "@ <url>" に残る(verifyBurpFindings の endpointOf 抽出が壊れない)。
  assert.match(cors.description, /@ https:\/\/app\.example\.com\/$/);
});

test("out-of-scope dropped; in-scope deduped against existing claude-pilot finding by (category × path)", () => {
  const { findings, store } = fakeStore();
  const existing: Finding[] = [
    { id: "f-001", screenId: null, title: "[xss-reflected] reflected on /search", severity: "high", source: { kind: "validator", validatorName: "claude-pilot" }, description: "", reproSteps: "", evidenceIds: [], scopeBasis: "" },
  ];
  const issues = [
    issue("Cross-site scripting (reflected)", "/search"), // 既存 claude-pilot と同カテゴリ×パス → skip
    { ...issue("CORS", "/"), host: "https://evil.example.org" } as BurpIssue, // out-of-scope
  ];
  const dir = mkdtempSync(join(tmpdir(), "burpmerge-"));
  const res = mergeBurpIssues(store, "a-1", { findings: existing, scope }, dir, issues);
  assert.equal(res.oos, 1);
  assert.equal(res.skipped, 1);
  assert.equal(res.added, 0);
  assert.equal(findings.length, 0);
});
