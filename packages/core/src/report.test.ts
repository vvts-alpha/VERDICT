// M7: report generation and stop-condition evaluation.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, buildReport, buildReportModel, renderReportHtml, deriveScopeFromSingleUrl, evaluateStop, recordRequests } from "./index.js";
import type { Finding, Screen } from "./index.js";

function screen(id: string, urlTemplate: string): Screen {
  return {
    screenId: id, urlTemplate, observedUrls: [`https://shop.test${urlTemplate}`], authState: "unauth",
    screenType: "detail", description: "", params: [], apis: [], screenshot: "", domSkeletonHash: id, labels: [],
  };
}

function seedWithFinding(dir: string): AssessmentStore {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({
    id: "a-1",
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
  });
  store.upsertScreen("a-1", screen("s-0001", "/orders/{id}"));
  const finding: Finding = {
    id: "vf-1", screenId: "s-0001", title: "Exposed sensitive file: /.git/config", severity: "high",
    source: { kind: "validator", validatorName: "exposed_file" }, description: "/.git/config is publicly readable",
    reproSteps: "GET /.git/config → 200 with [core]", evidenceIds: ["ev-1", "ev-2", "ev-3"], scopeBasis: "in-scope",
  };
  store.upsertFinding("a-1", finding);
  store.setScreenScanStatus("a-1", "s-0001", "finding", { findingIds: ["vf-1"] });
  return store;
}

test("buildReport renders findings, repro, evidence, scope", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-report-"));
  try {
    const store = seedWithFinding(dir);
    const md = buildReport(store.loadAssessment("a-1")!);
    store.close();
    assert.match(md, /# VERDICT Security Assessment Report/);
    assert.match(md, /## Assessment Information/);
    assert.match(md, /1 finding\(s\): 1 high/);
    assert.match(md, /\[HIGH\] Exposed sensitive file/);
    assert.match(md, /GET \/\.git\/config/);
    assert.match(md, /artifacts\/s-0001\/ev-1\//);
    assert.match(md, /## Scope/);
    // Contents: the Contents section + per-section links + explicit anchor/link to the finding.
    assert.match(md, /## Contents/);
    assert.match(md, /- \[Assessment Information\]\(#assessment-information\)/);
    assert.match(md, /- \[Findings\]\(#findings\)/);
    assert.match(md, /\[1\. HIGH — Exposed sensitive file[^\]]*\]\(#finding-1\)/); // the TOC contains no []
    assert.match(md, /<a id="finding-1"><\/a>/); // explicit anchor right before the heading
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// C: the "Suspected (needs manual verification)" list should carry only MEDIUM+ leads; info/low inconclusive items
// (inert reflections, weak-CSP burp~ notes) are demoted to a compact "Low-signal notes" section so they don't bury the
// real leads. Neither is counted in the confirmed total.
test("report splits suspected into medium+ leads vs info/low low-signal notes", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-report-lowsig-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-2",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    const lead: Finding = {
      id: "f-1", screenId: null, title: "[user-enumeration] auth-routing oracle", severity: "medium", verdict: "suspected",
      anomaly: "valid vs invalid accounts return a stable auth_method flip worth manual sign-off",
      source: { kind: "validator", validatorName: "claude-pilot" }, description: "d", reproSteps: "r", evidenceIds: ["ev-9"], scopeBasis: "in-scope",
    };
    const note: Finding = {
      id: "f-2", screenId: null, title: "[burp~] Input returned in response (reflected)", severity: "info", verdict: "suspected",
      source: { kind: "validator", validatorName: "burp" }, description: "inert reflection", reproSteps: "r", evidenceIds: [], scopeBasis: "in-scope",
    };
    store.upsertFinding("a-2", lead);
    store.upsertFinding("a-2", note);
    const md = buildReport(store.loadAssessment("a-2")!);
    store.close();

    assert.match(md, /## Suspected \(needs manual verification\)/);
    assert.match(md, /user-enumeration\] auth-routing oracle/); // the medium lead is here
    assert.match(md, /## Low-signal notes/);
    assert.match(md, /\[INFO\] \[burp~\] Input returned in response/); // the info item is demoted here (compact)
    assert.match(md, /1 suspected lead\(s\) \(medium\+\)/); // summary counts them apart
    assert.match(md, /1 low-signal note\(s\)/);
    // the info note must NOT appear as a full "### N. [SUSPECTED]" heading in the Suspected section
    assert.doesNotMatch(md, /### \d+\. \[SUSPECTED\] \[INFO\]/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// Report bloat: a missing-header finding is proven by the response HEADER block alone, so the HTML body must be
// dropped for "[headers]" findings (the same page body was re-embedded once per header finding — a 45-header run hit
// 1.3MB / 23k lines). Real findings keep their full body.
test("report drops the response BODY for [headers] findings but keeps it for real findings", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-report-hdrstrip-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-h",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    store.upsertScreen("a-h", screen("s-0001", "/"));
    const headerFinding: Finding = {
      id: "f-h", screenId: "s-0001", title: "[headers] Missing Content-Security-Policy header", severity: "low", verdict: "confirmed",
      source: { kind: "validator", validatorName: "claude-pilot" }, description: "no CSP", reproSteps: "GET /", evidenceIds: ["ev-h"], scopeBasis: "in-scope",
    };
    const realFinding: Finding = {
      id: "f-r", screenId: "s-0001", title: "[sqli] boolean SQLi on id", severity: "high", verdict: "confirmed",
      source: { kind: "validator", validatorName: "claude-pilot" }, description: "sqli", reproSteps: "GET /?id=1' OR 1=1", evidenceIds: ["ev-r"], scopeBasis: "in-scope",
    };
    store.upsertFinding("a-h", headerFinding);
    store.upsertFinding("a-h", realFinding);

    const HUGE_BODY = "X".repeat(5000); // the irrelevant HTML body that was inflating the report
    const loadEvidence = (_id: string) => ({ request: "GET / HTTP/1.1", response: `HTTP/1.1 200 OK\r\ncontent-type: text/html\r\n\r\n${HUGE_BODY}`, truncated: false });
    const md = buildReport(store.loadAssessment("a-h")!, new Date(), { loadEvidence });
    store.close();

    // The 5000-char body appears exactly ONCE — kept for the SQLi finding, dropped for the header finding.
    assert.equal(md.split(HUGE_BODY).length - 1, 1);
    // The header finding still shows the status line + headers (that IS its proof).
    assert.match(md, /content-type: text\/html/);
    assert.match(md, /Response \(truncated\)/); // the header evidence is marked truncated
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("evaluateStop trips on budget, coverage, and halt", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-stop-"));
  try {
    const store = seedWithFinding(dir);
    // Not incomplete (s-0001 is finding=terminal, total=1 remaining=0 → coverage complete)
    let state = store.loadAssessment("a-1")!;
    assert.equal(evaluateStop(state).reason, "coverage_complete");

    // budget exceeded (cap requests at 1 and record 2)
    const tight = { ...state.budget, limits: { ...state.budget.limits, maxTotalRequests: 1 } };
    store.updateBudget("a-1", recordRequests(tight, "shop.test", 2));
    state = store.loadAssessment("a-1")!;
    assert.equal(evaluateStop(state).reason, "budget_exceeded");

    // halt
    store.halt("a-1", "human_halt", "operator");
    assert.equal(evaluateStop(store.loadAssessment("a-1")!).stop, true);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("evaluateStop continues when screens remain and budget is ok", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-stop2-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-2",
      target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    store.upsertScreen("a-2", screen("s-0001", "/")); // queued = remaining
    assert.equal(evaluateStop(store.loadAssessment("a-2")!).stop, false);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("excluded screens are not reported as tested in HTML or Markdown", () => {
  const dir = mkdtempSync(join(tmpdir(), "report-excluded-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  try {
    store.createAssessment({ id: "coverage", target: { kind: "single_url", url: "https://shop.test", followLinks: true, maxDepth: 1 }, scope: deriveScopeFromSingleUrl("https://shop.test") });
    for (const [index, status] of (["clean", "suspected", "excluded", "blocked"] as const).entries()) {
      store.upsertScreen("coverage", screen(`s-${index}`, `/page${index}`));
      store.setScreenScanStatus("coverage", `s-${index}`, status);
    }
    const state = store.loadAssessment("coverage")!;
    const model = buildReportModel(state);
    assert.deepEqual(model.stats.screens, { total: 4, scanned: 2, excluded: 1, remaining: 1 });
    assert.match(buildReport(state), /2 tested · 1 excluded · 1 unfinished/);
    assert.match(renderReportHtml(model), /2 tested · 1 excluded · 1 unfinished/);
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});
