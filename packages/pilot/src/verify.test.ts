// Verify the pure part of burp-verify (target endpoint extraction). mergeBurpIssues writes finding.description
// in the "<detail> @ <url>" form, so make sure the trailing URL is reliably picked up.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { endpointOf, confirmedLeadSeverity, reverifiedSeverity, reverifiedVerdict } from "./verify.js";
import type { Finding } from "@veritas/core";

function fnd(description: string): Finding {
  return {
    id: "b-001",
    screenId: null,
    title: "[burp] Server-side template injection",
    severity: "high",
    source: { kind: "validator", validatorName: "burp" },
    description,
    reproSteps: "",
    evidenceIds: [],
    scopeBasis: "burp scan (in-scope)",
  };
}

test("endpointOf extracts the trailing '@ <url>' Burp merge writes", () => {
  assert.equal(
    endpointOf(fnd("Template injection detected. @ http://192.168.74.148:3000/rest/products/search?q=x")),
    "http://192.168.74.148:3000/rest/products/search?q=x",
  );
});

test("endpointOf returns null when there is no trailing URL", () => {
  assert.equal(endpointOf(fnd("Some detail with an @mention but no url")), null);
  assert.equal(endpointOf(fnd("plain description")), null);
});

test("endpointOf takes the LAST url (the merge appends the canonical one at the end)", () => {
  assert.equal(
    endpointOf(fnd("see http://a.test/early in detail @ https://b.test/final")),
    "https://b.test/final",
  );
});

// ── ① Reproducing a Burp reflection must NOT bump a finding to High. A confirmed sub-High lead is raised only to its
//    vuln CLASS band max (reflected-XSS = Medium per the pilot's own SEVERITY_BAND), NOT the entry-point hint priority. ──
test("confirmedLeadSeverity caps reflected/DOM XSS at Medium — never auto-High (the ① regression)", () => {
  assert.equal(confirmedLeadSeverity("xss-reflected"), "medium"); // was wrongly "high" via the hint priority
  assert.equal(confirmedLeadSeverity("xss-dom"), "medium");
  assert.equal(confirmedLeadSeverity("open-redirect"), "medium");
  assert.equal(confirmedLeadSeverity("csrf"), "medium");
});

test("confirmedLeadSeverity keeps genuinely-serious classes at High, and caps anything ambiguous at Medium", () => {
  assert.equal(confirmedLeadSeverity("xss-stored"), "high"); // persistent, affects other users
  assert.equal(confirmedLeadSeverity("ssrf"), "high");
  assert.equal(confirmedLeadSeverity("cors"), "medium"); // unlisted/ambiguous lead → Medium cap, never auto-High
  assert.equal(confirmedLeadSeverity("info-disclosure"), "medium");
  assert.equal(confirmedLeadSeverity(undefined), "medium");
});

test("reverifiedSeverity: confirmed raises UPWARD-ONLY to the class band (never lowers a higher current, never exceeds)", () => {
  assert.equal(reverifiedSeverity("confirmed", "info", "medium"), "medium"); // info reflection proven as real XSS → Medium
  assert.equal(reverifiedSeverity("confirmed", "low", "high"), "high");
  assert.equal(reverifiedSeverity("confirmed", "high", "medium"), "high"); // a Burp-native High is not lowered by the cap
});

test("reverifiedSeverity: INCONCLUSIVE keeps the severity unchanged — a bare reproduced reflection gets no bump (the ① core)", () => {
  assert.equal(reverifiedSeverity("inconclusive", "low", "medium"), "low");
  assert.equal(reverifiedSeverity("inconclusive", "info", "medium"), "info");
  assert.equal(reverifiedSeverity("inconclusive", "info"), "info");
});

test("reverifiedSeverity: refuted (could not reproduce at all) drops to info", () => {
  assert.equal(reverifiedSeverity("refuted", "high", "high"), "info");
  assert.equal(reverifiedSeverity("refuted", "medium"), "info");
});

// Burp imports carry no verdict field, and findingVerdict() defaults undefined→"confirmed". So a non-confirmed re-verify
// MUST set the verdict explicitly, or an inconclusive/refuted finding stays counted in the confirmed total + headlined.
test("reverifiedVerdict: only a confirmed outcome is 'confirmed'; inconclusive/refuted → 'suspected' (leave the confirmed count)", () => {
  assert.equal(reverifiedVerdict("confirmed"), "confirmed");
  assert.equal(reverifiedVerdict("inconclusive"), "suspected");
  assert.equal(reverifiedVerdict("refuted"), "suspected");
});
