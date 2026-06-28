// triageBurpInfo: Burp の High 未満 issue を「実脆弱性の入口」リードへ分類する純関数の検証。
// 実レポート(juice-shop)に出た issue 名を使い、有望リードの抽出・集約・並びと hygiene 除外を確認する。
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { triageBurpInfo, formatBurpLeads } from "./burp-triage.js";
import type { BurpIssue } from "./burp.js";

function issue(name: string, path = "/", severity = "Information"): BurpIssue {
  return { name, host: "https://shop.test", path, severity, detail: "", background: "", request: "", response: "" };
}

test("flags reflected/stored/DOM XSS reflection points as high-priority leads", () => {
  const leads = triageBurpInfo([
    issue("Input returned in response (reflected)", "/rest/products/search"),
    issue("Cross-site scripting (reflected)", "/search"),
    issue("Input returned in response (stored)", "/api/Feedbacks"),
    issue("DOM data manipulation (DOM-based)", "/#/track"),
  ]);
  const byLead = Object.fromEntries(leads.map((l) => [l.lead, l]));
  assert.equal(byLead["xss-reflected"]?.priority, "high");
  assert.equal(byLead["xss-reflected"]?.count, 2); // reflected XSS + input-returned(reflected) collapse
  assert.equal(byLead["xss-stored"]?.priority, "high");
  assert.equal(byLead["xss-dom"]?.priority, "high");
});

test("external service interaction → SSRF/OOB high lead; CORS/CSRF → medium", () => {
  const leads = triageBurpInfo([
    issue("External service interaction (DNS)", "/profile/image/url"),
    issue("External service interaction (HTTP)", "/profile/image/url"),
    issue("Cross-origin resource sharing: arbitrary origin trusted", "/rest/user/whoami"),
    issue("Cross-origin resource sharing", "/rest/products"),
    issue("Cross-site request forgery", "/profile", "Medium"),
  ]);
  const byLead = Object.fromEntries(leads.map((l) => [l.lead, l]));
  assert.equal(byLead["ssrf"]?.priority, "high");
  assert.equal(byLead["ssrf"]?.count, 2);
  assert.equal(byLead["cors"]?.priority, "medium");
  assert.equal(byLead["cors"]?.count, 2); // both CORS variants collapse into one lead
  assert.equal(byLead["csrf"]?.priority, "medium");
});

test("excludes pure-hygiene issues (no lead)", () => {
  const leads = triageBurpInfo([
    issue("Cookie without HttpOnly flag set", "/", "Low"),
    issue("Unencrypted communications", "/", "Low"),
    issue("HTML does not specify charset"),
    issue("Content type is not specified"),
    issue("Email addresses disclosed"),
    issue("Path-relative style sheet import"),
  ]);
  assert.deepEqual(leads, []); // none of these are "entry points" → not surfaced
});

test("leads are sorted high → medium → low, then by count; sampleUrls captured", () => {
  const leads = triageBurpInfo([
    issue("Robots.txt file", "/robots.txt"), // low
    issue("Cross-origin resource sharing", "/a"), // medium
    issue("Cross-origin resource sharing", "/b"),
    issue("Cross-site scripting (reflected)", "/x"), // high
  ]);
  assert.equal(leads[0]!.priority, "high");
  assert.ok(leads.findIndex((l) => l.lead === "cors") < leads.findIndex((l) => l.lead === "hidden-surface"));
  const cors = leads.find((l) => l.lead === "cors")!;
  assert.deepEqual(cors.sampleUrls, ["https://shop.test/a", "https://shop.test/b"]);
});

test("formatBurpLeads renders one actionable line per lead", () => {
  const lines = formatBurpLeads(triageBurpInfo([issue("External service interaction (DNS)", "/p")]));
  assert.equal(lines.length, 1);
  assert.match(lines[0]!, /\[high\] ssrf — 1 issue\(s\):/);
  assert.match(lines[0]!, /probe_oob/);
});
