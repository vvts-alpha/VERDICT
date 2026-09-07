import { test } from "node:test";
import assert from "node:assert/strict";
import type { Finding } from "@veritas/core";
import type { EvidenceRecord, EvidenceStore } from "@veritas/scanner";
import { consolidateFindings, evidenceFindingKey, qualifyFinding } from "./finding-review.js";

function finding(id: string, title: string, ids: string[], extra: Partial<Finding> = {}): Finding {
  return { id, title, evidenceIds: ids, screenId: id, severity: "high", verdict: "confirmed", source: { kind: "validator", validatorName: "claude-pilot" }, description: "Original claim", reproSteps: "Original steps", scopeBasis: "authorized", ...extra };
}
function record(id: string, url: string, body: string | null, response = '{}', extra: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return { id, screenId: "s-1", validator: "claude-pilot", kind: "positive_replay", recordedAt: "2026-09-07", note: "probe", request: { method: body ? "POST" : "GET", url, body, headers: {} }, response: { status: 200, headers: {}, body: response, finalUrl: url, durationMs: 1 }, ...extra };
}
const evidence = (...records: EvidenceRecord[]) => ({ records } as EvidenceStore);

test("SQLi consolidates the actual input despite endpoint spelling; keeps different methods, inputs and hosts", () => {
  const a = record("a", "https://app.test/login", JSON.stringify({ email: "' OR '1'='1'--" }));
  const b = { ...a, id: "b" };
  const c = record("c", "https://app.test/login?q=' OR 1=1--", null);
  const d = record("d", "https://other.test/login", a.request.body ?? null);
  const e = record("e", "https://app.test/login", JSON.stringify({ username: "' OR 1=1--" }));
  const fs = [a,b,c,d,e].map(r => finding(r.id, "[sqli] Login injection", [r.id]));
  assert.equal(consolidateFindings(fs, evidence(a,b,c,d,e)), 1);
  assert.equal(fs[1]!.duplicateOf, "a");
  assert.deepEqual(fs[0]!.evidenceIds, ["a", "b"]);
  assert.ok(fs.slice(2).every(f => !f.duplicateOf));
});

test("DOM XSS groups by hash route and input, preserving different SPA sinks", () => {
  const records = ["search?q=a", "search?q=b", "profile?q=a", "search?name=a"].map((hash,i) => record(String(i), `https://app.test/#/${hash}`, null, "XSS EXECUTED", { validator: "claude-pilot-dom-xss" }));
  const fs = records.map(r => finding(r.id, "[xss-reflected] DOM XSS", [r.id]));
  assert.equal(consolidateFindings(fs, evidence(...records)), 1);
  assert.ok(!fs[2]!.duplicateOf && !fs[3]!.duplicateOf);
});

test("address writes consolidate object IDs but preserve PUT vs DELETE", () => {
  const records = [1,2,3].map((id,i) => {
    const r = record(String(i), `https://app.test/addresses/${id}`, '{}');
    r.request.method = i === 2 ? "DELETE" : "PUT";
    return r;
  });
  const fs = records.map(r => finding(r.id, "[idor-write] Address takeover", [r.id]));
  assert.equal(consolidateFindings(fs, evidence(...records)), 1);
  assert.ok(!fs[2]!.duplicateOf);
});

test("password digest observations prefer confirmed without importing suspected severity or claims", () => {
  const a = record("a", "https://app.test/whoami", null, '{"password":"0123456789abcdef0123456789abcdef"}');
  const b = { ...a, id: "b" };
  const lead = finding("lead", "[session] Password digest embedded in JWT", ["a"], { verdict: "suspected", severity: "critical" });
  const confirmed = finding("confirmed", "[session] JWT embeds password hash", ["b"], { severity: "medium" });
  assert.equal(consolidateFindings([lead,confirmed], evidence(a,b)), 1);
  assert.equal(lead.duplicateOf, "confirmed");
  assert.equal(confirmed.severity, "medium");
  assert.equal(confirmed.description, "Original claim");
  assert.equal(consolidateFindings([lead,confirmed], evidence(a,b)), 0);
  const unrelated = finding("x", "[session] JWT forgery permits account takeover", ["a"]);
  assert.equal(evidenceFindingKey(unrelated, evidence(a)), undefined);
});

test("upload acceptance cannot confirm stored XSS; execution control and two replays can", () => {
  const c = record("c", "https://app.test/upload", '{}', 'Invalid mime', { kind: "negative_control" });
  const a = record("a", "https://app.test/upload", '{}', '{"imagePath":"payload.jpg"}');
  const b = { ...a, id: "b" };
  const f = finding("f", "[xss-stored] Unsafe file upload", ["c","a","b"]);
  assert.match(qualifyFinding(f, evidence(c,a,b))!, /does not establish browser/);
  assert.equal(f.verdict, "suspected");
  assert.equal(f.severity, "medium");
  const trusted = [c,a,b].map(r => ({ ...r, validator: "claude-pilot-stored-xss", response: { ...r.response, body: r.kind === "negative_control" ? "no execution" : "XSS EXECUTED — sink fired" } }));
  const proved = finding("proved", "[xss-stored] File upload XSS", ["c","a","b"]);
  assert.equal(qualifyFinding(proved, evidence(...trusted)), undefined);
  assert.equal(proved.verdict, "confirmed");
  // An HTTP body containing the marker is not trusted browser instrumentation.
  assert.ok(qualifyFinding(finding("fake", "[xss-stored] File upload", ["c","a","b"]), evidence(...trusted.map(r => ({ ...r, validator: "claude-pilot" })))));
});

test("negative deposit acceptance retains validation flaw without claiming theft", () => {
  const a = record("a", "https://app.test/wallet", '{"balance":-5}', '{"data":-5}');
  const b = { ...a, id: "b" };
  const f = finding("f", "[price-tampering] Wallet accepts negative deposit", ["a","b"]);
  assert.ok(qualifyFinding(f, evidence(a,b)));
  assert.equal(f.verdict, "confirmed");
  assert.equal(f.severity, "medium");
  assert.match(f.description, /not established/);
});

test("JWT forgery grouping requires matching probe technique, separate from digest disclosure", () => {
  const a = record("a", "https://app.test/wallet", null, '{}', { validator: "claude-pilot-jwt", note: "jwt alg:none #1" });
  const b = record("b", "https://app.test/cards", null, '{}', { validator: "claude-pilot-jwt", note: "jwt alg:none #2" });
  const c = { ...b, id: "c", note: "jwt weak HMAC #1" };
  const fs = [a,b,c].map(r => finding(r.id, "[session] JWT alg:none forgery", [r.id]));
  assert.equal(consolidateFindings(fs, evidence(a,b,c)), 1);
  assert.ok(!fs[2]!.duplicateOf);
});

test("session-analysis duplicate lead is not promoted without a confirmed disclosure", () => {
  const a = record("a", "https://app.test/profile", null, '{}', { validator: "claude-pilot-session" });
  const b = { ...a, id: "b" };
  const fs = [a,b].map(r => finding(r.id, "[session] JWT embeds password hash", [r.id], { verdict: "suspected" }));
  assert.equal(consolidateFindings(fs, evidence(a,b)), 1);
  assert.equal(fs[0]!.verdict, "suspected");
});
