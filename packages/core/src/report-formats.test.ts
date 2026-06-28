// レポートの構造化モデル + HTML/CSV/inventory レンダラ。

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, deriveScopeFromSingleUrl, buildReportModel, renderMarkdown, renderReportHtml, renderFindingsCsv, renderScreensCsv, renderInventoryHtml } from "./index.js";
import type { Finding, Screen } from "./index.js";

function screen(id: string, urlTemplate: string): Screen {
  return {
    screenId: id, urlTemplate, observedUrls: [`https://shop.test${urlTemplate}`], authState: "post-login",
    screenType: "detail", description: "", params: [], apis: [], screenshot: `screens/${id}.png`, domSkeletonHash: id, labels: ["idor-candidate"],
  };
}

function seed(dir: string): AssessmentStore {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({
    id: "a-1",
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
  });
  store.upsertScreen("a-1", screen("s-0001", "/orders/{id}"));
  store.upsertScreen("a-1", screen("s-0002", "/profile"));
  const finding: Finding = {
    id: "vf-1", screenId: "s-0001", title: "Exposed sensitive file: /.git/config", severity: "high",
    source: { kind: "validator", validatorName: "exposed_file" }, description: "/.git/config is publicly readable",
    reproSteps: "GET /.git/config → 200 with [core]", evidenceIds: ["ev-1", "ev-2"], scopeBasis: "in-scope",
  };
  store.upsertFinding("a-1", finding);
  store.setScreenScanStatus("a-1", "s-0001", "finding", { findingIds: ["vf-1"] });
  return store;
}

test("buildReportModel projects stats, findings, and screen inventory", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-rm-"));
  try {
    const store = seed(dir);
    const m = buildReportModel(store.loadAssessment("a-1")!);
    store.close();
    assert.equal(m.brand, "AMRAAM");
    assert.equal(m.stats.findings.total, 1);
    assert.equal(m.stats.findings.bySeverity.high, 1);
    assert.equal(m.findings[0]!.sourceName, "exposed_file");
    assert.deepEqual(m.findings[0]!.evidence.map((e) => e.path), ["artifacts/s-0001/ev-1/", "artifacts/s-0001/ev-2/"]);
    assert.equal(m.findings[0]!.evidence[0]!.request, null); // no loader → path only
    // 画面一覧: 2 screens, sorted, with scan status mapped
    assert.equal(m.screens.length, 2);
    assert.equal(m.screens[0]!.screenId, "s-0001");
    assert.equal(m.screens[0]!.scanStatus, "finding");
    assert.equal(m.screens[1]!.scanStatus, "queued"); // s-0002 enrolled but not yet diagnosed
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("loadEvidence embeds full request/response in markdown + html", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-ev-"));
  try {
    const store = seed(dir);
    const state = store.loadAssessment("a-1")!;
    store.close();
    const loader = (evId: string) => ({
      request: `GET /.git/config HTTP/1.1\nHost: shop.test\n[evid ${evId}]`,
      response: `HTTP/1.1 200 OK\nContent-Type: text/plain\n\n[core]\nrepositoryformatversion = 0`,
      truncated: false,
    });
    const m = buildReportModel(state, new Date(), { loadEvidence: loader });
    assert.match(m.findings[0]!.evidence[0]!.request!, /GET \/\.git\/config/);
    const md = renderMarkdown(m);
    assert.match(md, /Request:/);
    assert.match(md, /Response:/);
    assert.match(md, /repositoryformatversion = 0/);
    const html = renderReportHtml(m);
    assert.match(html, /REQUEST<\/div>/);
    assert.match(html, /RESPONSE<\/div>/);
    assert.match(html, /repositoryformatversion = 0/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("renderReportHtml is a self-contained document with the finding", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-html-"));
  try {
    const store = seed(dir);
    const html = renderReportHtml(buildReportModel(store.loadAssessment("a-1")!));
    store.close();
    assert.match(html, /^<!doctype html>/);
    assert.match(html, /<style>/); // inline CSS = self-contained
    assert.match(html, /Exposed sensitive file/);
    assert.match(html, /HIGH<\/span>/);
    assert.ok(!html.includes("<script")); // no script injection surface
    // 目次: nav + 各節 id + finding アンカーへのリンク。
    assert.match(html, /<nav class="toc">/);
    assert.match(html, /<a href="#assessment-information">Assessment Information<\/a>/);
    assert.match(html, /<a href="#finding-1">/);
    assert.match(html, /<h2 id="findings">Findings<\/h2>/);
    assert.match(html, /<div class="f" id="finding-1">/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CSV renderers escape and list rows", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-csv-"));
  try {
    const store = seed(dir);
    const m = buildReportModel(store.loadAssessment("a-1")!);
    store.close();
    const fcsv = renderFindingsCsv(m);
    assert.match(fcsv, /index,severity,title/);
    assert.match(fcsv, /high,Exposed sensitive file/);
    assert.match(fcsv, /artifacts\/s-0001\/ev-1\/ \| artifacts\/s-0001\/ev-2\//);
    const scsv = renderScreensCsv(m);
    assert.match(scsv, /screen_id,url,type/);
    assert.match(scsv, /s-0001,\/orders\/\{id\}/);
    assert.match(scsv, /s-0002,\/profile/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("renderInventoryHtml lists screens with screenshots", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-inv-"));
  try {
    const store = seed(dir);
    const html = renderInventoryHtml(buildReportModel(store.loadAssessment("a-1")!));
    store.close();
    assert.match(html, /Screen Inventory/);
    assert.match(html, /src="artifacts\/screens\/s-0001\.png"/);
    assert.match(html, /s-0002/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CSV cell quoting handles commas, quotes, newlines", () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-csvq-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    store.createAssessment({
      id: "a-2", target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl("https://shop.test/"),
    });
    store.upsertScreen("a-2", screen("s-0001", "/x"));
    store.upsertFinding("a-2", {
      id: "vf-2", screenId: "s-0001", title: 'Weird, "quoted" title', severity: "low",
      source: { kind: "hypothesis", hypothesisId: "h-9" }, description: "d",
      reproSteps: "line1\nline2", evidenceIds: [], scopeBasis: "in-scope",
    });
    const csv = renderFindingsCsv(buildReportModel(store.loadAssessment("a-2")!));
    store.close();
    assert.match(csv, /"Weird, ""quoted"" title"/);
    assert.match(csv, /"line1\nline2"/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
