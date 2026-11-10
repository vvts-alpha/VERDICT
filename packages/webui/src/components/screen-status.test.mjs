import { test } from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { screenHonestyMap } from "./screen-status.ts";
import { Scenarios, scenarioCoverage } from "./Scenarios.tsx";

const row = (status, checkClass = "idor") => ({
  id: `check-${status}`, screenId: "s-0001", target: "GET /orders/{id}", subject: "member",
  checkClass, status, evidenceIds: [], findingIds: [], updatedAt: "2026-02-01",
});
const note = (message) => ({ type: "note", payload: { message } });
const viewWith = (overrides = {}) => ({
  screenScans: [{ screenId: "s-0001", status: "clean" }],
  screenHonesty: {
    "s-0001": { status: "unverified", raw: "clean", legacy: false, gaps: 1, unfulfilled: 1 },
  },
  screenCheckSummaries: {
    "s-0001": {
      verdict: "unverified", gaps: 1, unfulfilled: 1,
      classes: [{
        checkClass: "idor", status: "blocked", gaps: 1, unfulfilled: 1,
        outcomes: [{ status: "blocked", count: 1 }],
      }],
    },
  },
  checkExecutions: [row("planned"), row("blocked")],
  events: [note("✓ s-0001 → clean [idor:tested-clean]")],
  screens: [{ screenId: "s-0001", urlTemplate: "/orders" }],
  findings: [],
  ...overrides,
});

test("WebUI reads core honesty rather than recomputing satisfaction from a failed probe", () => {
  const view = viewWith();
  assert.strictEqual(screenHonestyMap(view).get("s-0001"), view.screenHonesty["s-0001"]);
  const coverage = scenarioCoverage(view).get("s-0001");
  assert.equal(coverage.verdict, "unverified");
  assert.equal(coverage.provenance, "ledger");
  assert.deepEqual(coverage.entries.map(({ status, gaps, unfulfilled }) => [status, gaps, unfulfilled]), [["blocked", 1, 1]]);
  const html = renderToStaticMarkup(createElement(Scenarios, { view, onJump: () => {} }));
  assert.match(html, /\+1 gaps/);
  assert.match(html, /\+1 plan/);
  assert.match(html, /unverified/);
  assert.doesNotMatch(html, />clean<\/span>/);
});

test("raw http-request cannot validate a self-reported clean coverage note", () => {
  const view = viewWith({
    screenHonesty: { "s-0001": { raw: "clean", status: "unknown-records", legacy: true, gaps: 0, unfulfilled: 0 } },
    screenCheckSummaries: { "s-0001": { verdict: "unverified", gaps: 0, unfulfilled: 0, classes: [] } },
    checkExecutions: [row("tested-clean", "http-request")],
  });
  assert.equal(screenHonestyMap(view).get("s-0001")?.status, "unknown-records");
  assert.deepEqual(scenarioCoverage(view).get("s-0001"), {
    verdict: "unknown-records", entries: [], provenance: "ledger",
  });
  const html = renderToStaticMarkup(createElement(Scenarios, { view, onJump: () => {} }));
  assert.match(html, /unknown-records/);
  assert.doesNotMatch(html, /derived from recorded check executions[^]*?border-success/);
});

test("a legacy clean note without ledger or honesty projection remains only a breadcrumb", () => {
  const view = viewWith({
    screenHonesty: undefined, screenCheckSummaries: undefined, checkExecutions: [],
  });
  assert.equal(screenHonestyMap(view).get("s-0001")?.status, "unknown-records");
  assert.deepEqual(scenarioCoverage(view).get("s-0001"), {
    verdict: "unknown-records",
    entries: [{ cls: "idor", status: "tested-clean", others: [], gaps: 0, unfulfilled: 0 }],
    provenance: "note",
  });
  const html = renderToStaticMarkup(createElement(Scenarios, { view, onJump: () => {} }));
  assert.match(html, /unknown-records \(note\)/);
  assert.match(html, /idor: tested-clean \(note\)/);
  assert.doesNotMatch(html, />clean \(note\)<\/span>/);

  // A note can also outlive the scan row in an older snapshot.
  assert.equal(scenarioCoverage({ ...view, screenScans: [] }).get("s-0001")?.verdict, "unknown-records");
});

test("a legacy finding needs a finding on that screen, not a coverage note", () => {
  const view = viewWith({
    screenScans: [{ screenId: "s-0001", status: "finding" }],
    screenHonesty: undefined, screenCheckSummaries: undefined, checkExecutions: [],
    events: [note("✓ s-0001 → finding [idor:found]")],
  });
  assert.equal(screenHonestyMap(view).get("s-0001")?.status, "unknown-records");
  assert.equal(scenarioCoverage(view).get("s-0001")?.verdict, "unknown-records");

  const finding = {
    id: "finding-1", screenId: "s-0001", title: "Confirmed issue", severity: "high",
    source: { kind: "validator", validatorName: "existing" }, description: "Recorded finding",
    reproSteps: "", evidenceIds: ["ev-existing"], scopeBasis: "in scope",
  };
  assert.equal(scenarioCoverage({ ...view, findings: [{ ...finding, screenId: "s-0002" }] }).get("s-0001")?.verdict, "unknown-records");
  const backed = { ...view, findings: [finding], events: [note("✓ s-0001 → clean [idor:tested-clean]")] };
  assert.equal(scenarioCoverage(backed).get("s-0001")?.verdict, "finding");
  assert.match(renderToStaticMarkup(createElement(Scenarios, { view: backed, onJump: () => {} })), /finding \(note\)/);
});

test("raw HTTP alone cannot validate a clean note when both projections are missing", () => {
  const view = viewWith({
    screenHonesty: undefined, screenCheckSummaries: undefined,
    checkExecutions: [row("tested-clean", "http-request")],
  });
  assert.equal(screenHonestyMap(view).get("s-0001")?.status, "unknown-records");
  assert.deepEqual(scenarioCoverage(view).get("s-0001"), {
    verdict: "unverified", entries: [], provenance: "ledger",
  });
  const html = renderToStaticMarkup(createElement(Scenarios, { view, onJump: () => {} }));
  assert.match(html, /unverified/);
  assert.doesNotMatch(html, />clean<\/span>/);
});

test("WebUI follows core's retry/identity decision while preserving other-principal gaps", () => {
  const retry = viewWith({
    screenHonesty: { "s-0001": { raw: "clean", status: "clean", legacy: false, gaps: 0, unfulfilled: 0 } },
    screenCheckSummaries: {
      "s-0001": {
        verdict: "clean", gaps: 0, unfulfilled: 0,
        classes: [{
          checkClass: "idor", status: "tested-clean", gaps: 0, unfulfilled: 0,
          outcomes: [{ status: "unverified", count: 1 }, { status: "tested-clean", count: 1 }],
        }],
      },
    },
    checkExecutions: [row("planned"), row("unverified"), row("tested-clean")],
  });
  assert.equal(screenHonestyMap(retry).get("s-0001")?.status, "clean");
  assert.equal(scenarioCoverage(retry).get("s-0001")?.verdict, "clean");
  assert.deepEqual(scenarioCoverage(retry).get("s-0001")?.entries[0]?.others, [{ status: "unverified", count: 1 }]);
  const recoveredHtml = renderToStaticMarkup(createElement(Scenarios, { view: retry, onJump: () => {} }));
  assert.match(recoveredHtml, /history: \+1 unverified/);
  assert.doesNotMatch(recoveredHtml, /\+1 gaps/);

  const differentPrincipal = viewWith({
    checkExecutions: retry.checkExecutions,
    screenCheckSummaries: {
      "s-0001": {
        verdict: "unverified", gaps: 1, unfulfilled: 0,
        classes: [{ checkClass: "idor", status: "unverified", gaps: 1, unfulfilled: 0, outcomes: [] }],
      },
    },
  });
  assert.equal(screenHonestyMap(differentPrincipal).get("s-0001")?.status, "unverified");
  assert.equal(scenarioCoverage(differentPrincipal).get("s-0001")?.entries[0]?.gaps, 1);
  assert.match(renderToStaticMarkup(createElement(Scenarios, { view: differentPrincipal, onJump: () => {} })), /\+1 gaps/);
});

test("a clean class with an unfulfilled slot never renders as clean coverage", () => {
  const view = viewWith({
    screenHonesty: { "s-0001": { raw: "clean", status: "unverified", legacy: false, gaps: 0, unfulfilled: 1 } },
    screenCheckSummaries: {
      "s-0001": {
        verdict: "unverified", gaps: 0, unfulfilled: 1,
        classes: [{ checkClass: "idor", status: "tested-clean", gaps: 0, unfulfilled: 1, outcomes: [{ status: "tested-clean", count: 1 }] }],
      },
    },
  });
  assert.equal(scenarioCoverage(view).get("s-0001")?.verdict, "unverified");
  const html = renderToStaticMarkup(createElement(Scenarios, { view, onJump: () => {} }));
  assert.match(html, /idor: tested-clean/);
  assert.match(html, /\+1 plan/);
  assert.doesNotMatch(html, /border-success text-success[^>]*>idor: tested-clean/);
});

test("capped note window does not affect projected coverage; older snapshots fail closed", () => {
  const view = viewWith({ events: Array.from({ length: 300 }, (_, i) => note(`later log ${i}`)) });
  assert.equal(scenarioCoverage(view).get("s-0001")?.verdict, "unverified");
  const olderServer = viewWith({ screenHonesty: undefined, screenCheckSummaries: undefined });
  assert.equal(screenHonestyMap(olderServer).get("s-0001")?.status, "unknown-records");
  assert.equal(scenarioCoverage(olderServer).get("s-0001")?.verdict, "unverified");
  const legacy = viewWith({
    checkExecutions: [], screenCheckSummaries: {},
    screenHonesty: { "s-0001": { raw: "clean", status: "unknown-records", legacy: true, gaps: 0, unfulfilled: 0 } },
  });
  assert.deepEqual(scenarioCoverage(legacy).get("s-0001")?.verdict, "unknown-records");
  assert.equal(scenarioCoverage(legacy).get("s-0001")?.provenance, "note");
  assert.match(renderToStaticMarkup(createElement(Scenarios, { view: legacy, onJump: () => {} })), /unknown-records \(note\)/);
});
