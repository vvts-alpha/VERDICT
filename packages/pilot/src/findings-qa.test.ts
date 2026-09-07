// Findings QA: the agent's own confirmed High is not a second opinion. Mechanical oracles demote scanner FPs
// (Valero HTML-length SQLi, people-picker IDOR) without asking the same model to agree; remaining High+ can be
// AI-triaged from RAW evidence.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl, findingVerdict } from "@veritas/core";
import type { Finding } from "@veritas/core";
import { EvidenceStore } from "@veritas/scanner";
import { FakeLlmClient } from "@veritas/llm";
import { judgeConfirmedFinding, triagePilotFindings, categoryOfFinding } from "./findings-qa.js";

const BASE = "https://app.test/";

function withDir(fn: (dir: string) => Promise<void> | void): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-qa-"));
  return Promise.resolve(fn(dir)).finally(() => rmSync(dir, { recursive: true, force: true }));
}

function setup(dir: string): { store: AssessmentStore; evidence: EvidenceStore } {
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(BASE) });
  return { store, evidence: new EvidenceStore(join(dir, "artifacts")) };
}

function ev(evidence: EvidenceStore, kind: "negative_control" | "positive_replay", body: string, status = 200, headers: Record<string, string> = {}) {
  return evidence.record({
    screenId: "s-1",
    validator: "test",
    kind,
    request: { method: "GET", url: BASE + "search", headers: {}, body: null },
    response: { status, finalUrl: BASE + "search", durationMs: 3, headers, body },
    note: kind,
  });
}

function finding(partial: Partial<Finding> & Pick<Finding, "id" | "title" | "evidenceIds">): Finding {
  return {
    screenId: "s-1",
    severity: "high",
    verdict: "confirmed",
    source: { kind: "validator", validatorName: "claude-pilot" },
    description: "agent writeup",
    reproSteps: "repro",
    scopeBasis: "authorized",
    ...partial,
  };
}

test("categoryOfFinding reads the [sqli] title prefix", () => {
  assert.equal(categoryOfFinding(finding({ id: "f-001", title: "[sqli] Boolean-based SQL injection in /search", evidenceIds: [] })), "sqli");
});

test("judgeConfirmedFinding: Valero-shaped HTML length SQLi is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const html = (n: number) => `<!DOCTYPE html><html><body>${"z".repeat(n)}</body></html>`;
    const c = ev(evidence, "negative_control", html(32468));
    const p1 = ev(evidence, "positive_replay", html(32348));
    const p2 = ev(evidence, "positive_replay", html(32348));
    const f = finding({ id: "f-001", title: "[sqli] Boolean-based SQL injection in /search", evidenceIds: [c.id, p1.id, p2.id] });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /HTML|length/i);
  });
});

test("judgeConfirmedFinding: JSON extra-row SQLi is kept", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const rows = JSON.stringify({ n: 40, rows: Array.from({ length: 40 }, () => ({ id: 1, name: "juice" })) });
    const empty = JSON.stringify({ n: 0, rows: [] });
    const c = ev(evidence, "negative_control", empty);
    const p1 = ev(evidence, "positive_replay", rows);
    const p2 = ev(evidence, "positive_replay", rows);
    const f = finding({ id: "f-001", title: "[sqli] Boolean-based SQL injection in /rest/products/search", evidenceIds: [c.id, p1.id, p2.id] });
    assert.equal(judgeConfirmedFinding(f, evidence).demote, false);
  });
});

test("judgeConfirmedFinding: public store-locator HTML IDOR is demoted (Valero LocationDetails)", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const page = `<!doctype html><html><head>
      <meta property="og:type" content="place" />
      <meta property="place:location:latitude" content="29.3187">
      <title>12511 SW LOOP 410</title>
      </head><body><a href="/find-station">Find a Station</a></body></html>`;
    const empty = page.replace("29.3187", "0").replace("12511 SW LOOP 410", "/");
    const c = ev(evidence, "negative_control", empty);
    const p1 = ev(evidence, "positive_replay", page);
    const p2 = ev(evidence, "positive_replay", page);
    const f = finding({
      id: "f-003",
      title: "[idor] Unauthenticated enumeration of location records via sequential path ID",
      severity: "medium",
      evidenceIds: [c.id, p1.id, p2.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /directory|locator|catalog/i);
  });
});

test("judgeConfirmedFinding: people-picker IDOR is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const card = JSON.stringify({ id: "u-2", displayName: "Adele Vance", mail: "adele@contoso.com", photo: "https://cdn/p.png", tenantId: "1" });
    const miss = JSON.stringify({ error: "not found" });
    const c = ev(evidence, "negative_control", miss, 404);
    const p1 = ev(evidence, "positive_replay", card);
    const p2 = ev(evidence, "positive_replay", card);
    const f = finding({ id: "f-004", title: "[idor] Cross-user profile access", evidenceIds: [c.id, p1.id, p2.id] });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /people-picker|directory/i);
  });
});

test("judgeConfirmedFinding: Maps JS API key secret-exposure is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const key = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";
    const page = `<script src="https://maps.googleapis.com/maps/api/js?v=weekly&libraries=places&key=${key}"></script>`;
    const c = ev(evidence, "negative_control", "<html>Request Rejected</html>", 403);
    const p1 = ev(evidence, "positive_replay", page);
    const p2 = ev(evidence, "positive_replay", page);
    const f = finding({
      id: "f-001",
      title: "[secret-exposure] Hardcoded Google Maps API Key Exposed in Store Locator HTML",
      severity: "medium",
      evidenceIds: [c.id, p1.id, p2.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /Maps|public by design/i);
  });
});

test("judgeConfirmedFinding: robots.txt Sitemap info-disclosure is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const robots = "User-agent: *\nAllow: /\nSitemap: https://locations.example.com/sitemap.xml\n";
    const waf = "<html><title>Request Rejected</title></html>";
    const c = ev(evidence, "negative_control", waf, 403);
    const p1 = ev(evidence, "positive_replay", robots);
    const p2 = ev(evidence, "positive_replay", robots);
    const f = finding({
      id: "f-002",
      title: "[info-disclosure] robots.txt discloses cross-environment production sitemap reference",
      severity: "info",
      evidenceIds: [c.id, p1.id, p2.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /robots\.txt/i);
  });
});

test("judgeConfirmedFinding: hardcoded AIza in JS (not Maps loader) is kept", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const key = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";
    const js = `const KEY="${key}";`;
    const c = ev(evidence, "negative_control", "404", 404);
    const p1 = ev(evidence, "positive_replay", js);
    const p2 = ev(evidence, "positive_replay", js);
    const f = finding({ id: "f-010", title: "[secret-exposure] Google API key in bundle", evidenceIds: [c.id, p1.id, p2.id] });
    assert.equal(judgeConfirmedFinding(f, evidence).demote, false);
  });
});

test("judgeConfirmedFinding: Firebase web apiKey secret-exposure is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const key = "AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";
    const page = `firebase.initializeApp({apiKey:"${key}",authDomain:"app.firebaseapp.com"});`;
    const c = ev(evidence, "negative_control", "404", 404);
    const p1 = ev(evidence, "positive_replay", page);
    const p2 = ev(evidence, "positive_replay", page);
    const f = finding({
      id: "f-020",
      title: "[secret-exposure] Firebase API key in client JS",
      severity: "medium",
      evidenceIds: [c.id, p1.id, p2.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /public by design|Firebase/i);
  });
});

test("judgeConfirmedFinding: sitemap.xml info-disclosure is demoted", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const sm = `<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://app.test/</loc></url></urlset>`;
    const c = ev(evidence, "negative_control", "404", 404);
    const p1 = ev(evidence, "positive_replay", sm);
    const p2 = ev(evidence, "positive_replay", sm);
    const f = finding({
      id: "f-021",
      title: "[info-disclosure] sitemap.xml lists all paths",
      severity: "info",
      evidenceIds: [c.id, p1.id, p2.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /sitemap|public file/i);
  });
});

test("judgeConfirmedFinding: SharePoint /_layouts/15/ hive is not SharePoint 2013 RCE", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const page = `<link href="/_layouts/15/1033/styles/Themable/corev15.css"/><script src="/_layouts/15/init.js"></script>`;
    const c = ev(evidence, "negative_control", page, 200);
    const p1 = ev(evidence, "positive_replay", page, 200);
    const f = finding({
      id: "f-002",
      title: "[vulnerable-component] Outdated Microsoft SharePoint Server (2013 / v15 hive) — CVE-2019-0604 & CVE-2020-1147 RCE",
      verdict: "suspected",
      severity: "critical",
      description:
        "The /_layouts/15/ hive corresponds to SharePoint Server 2013 (version 15.0). Patch level could not be confirmed because the WAF strips MicrosoftSharePointTeamServices.",
      evidenceIds: [c.id, p1.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /version|product family|A06/i);
  });
});

test("judgeConfirmedFinding: versionless F5 BIG-IP product-family A06 is demoted (even suspected)", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const hdr = { server: "BigIP", "set-cookie": "MRHSHint=x; Path=/" };
    const c = ev(evidence, "negative_control", "", 302, hdr);
    const p1 = ev(evidence, "positive_replay", "", 302, hdr);
    const f = finding({
      id: "f-003",
      title: "[vulnerable-component] F5 BIG-IP internet-exposed with undisclosed version (product family has Critical RCE/auth-bypass CVE history)",
      verdict: "suspected",
      severity: "high",
      description: "The exact BIG-IP version is NOT disclosed by any response header. CVE-2020-5902 may apply depending on the undisclosed version.",
      evidenceIds: [c.id, p1.id],
    });
    const j = judgeConfirmedFinding(f, evidence);
    assert.equal(j.demote, true);
    if (j.demote) assert.match(j.reason, /version|product family|A06/i);
  });
});

test("judgeConfirmedFinding: versioned Apache banner A06 is kept", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const hdr = { server: "Apache/2.4.49 (Unix)" };
    const c = ev(evidence, "negative_control", "ok", 200, hdr);
    const p1 = ev(evidence, "positive_replay", "ok", 200, hdr);
    const f = finding({
      id: "f-011",
      title: "[vulnerable-component] Outdated Apache httpd 2.4.49 — CVE-2021-41773",
      verdict: "suspected",
      evidenceIds: [c.id, p1.id],
    });
    assert.equal(judgeConfirmedFinding(f, evidence).demote, false);
  });
});

test("judgeConfirmedFinding: IDOR with private object fields is kept", () => {
  return withDir((dir) => {
    const { evidence } = setup(dir);
    const order = JSON.stringify({ id: "o-9", orderId: "o-9", total: 4800, items: [{ sku: "x" }] });
    const c = ev(evidence, "negative_control", "{}", 404);
    const p1 = ev(evidence, "positive_replay", order);
    const p2 = ev(evidence, "positive_replay", order);
    const f = finding({ id: "f-002", title: "[idor] Cross-user order", evidenceIds: [c.id, p1.id, p2.id] });
    assert.equal(judgeConfirmedFinding(f, evidence).demote, false);
  });
});

test("triagePilotFindings: demotes Valero SQLi in the store without calling the LLM", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const html = (n: number) => `<!DOCTYPE html><html><body>${"z".repeat(n)}</body></html>`;
    const c = ev(evidence, "negative_control", html(32468));
    const p1 = ev(evidence, "positive_replay", html(32348));
    const p2 = ev(evidence, "positive_replay", html(32348));
    const f = finding({ id: "f-001", title: "[sqli] Boolean-based SQL injection in /search", evidenceIds: [c.id, p1.id, p2.id] });
    store.upsertFinding("a-1", f);
    const llm = new FakeLlmClient('{"verdict":"confirmed","reason":"should not be asked"}');
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(r.demoted, 1);
    assert.equal(llm.calls.length, 0); // mechanical — do not ask the model to rubber-stamp
    assert.equal(findingVerdict(f), "suspected");
    assert.equal(f.severity, "info");
    assert.match(f.title, /^\[qa\?\]/);
    store.close();
  });
});

test("triagePilotFindings: demotes versionless BigIP A06 without calling the LLM", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const hdr = { server: "BigIP" };
    const c = ev(evidence, "negative_control", "", 302, hdr);
    const p1 = ev(evidence, "positive_replay", "", 302, hdr);
    const f = finding({
      id: "f-003",
      title: "[vulnerable-component] F5 BIG-IP internet-exposed with undisclosed version",
      verdict: "suspected",
      evidenceIds: [c.id, p1.id],
    });
    store.upsertFinding("a-1", f);
    const llm = new FakeLlmClient('{"verdict":"confirmed","reason":"should not be asked"}');
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(r.demoted, 1);
    assert.equal(llm.calls.length, 0);
    assert.equal(f.severity, "info");
    assert.match(f.title, /^\[qa\?\]/);
    store.close();
  });
});

test("triagePilotFindings: AI can still demote a High the mechanical oracle kept", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const body = JSON.stringify({ ok: true, n: 1 });
    const c = ev(evidence, "negative_control", body);
    const p1 = ev(evidence, "positive_replay", JSON.stringify({ ok: true, n: 2, extra: "x".repeat(80) }));
    const p2 = ev(evidence, "positive_replay", JSON.stringify({ ok: true, n: 2, extra: "x".repeat(80) }));
    const f = finding({ id: "f-009", title: "[sqli] maybe", evidenceIds: [c.id, p1.id, p2.id] });
    store.upsertFinding("a-1", f);
    const llm = new FakeLlmClient('{"verdict":"false_positive","reason":"same JSON shape, not query control"}');
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(r.demoted, 1);
    assert.equal(llm.calls.length, 3); // adversarial panel = 3 independent lenses
    assert.equal(findingVerdict(f), "suspected");
    assert.doesNotMatch(llm.calls[0]!.prompt, /\btitle:/);
    assert.doesNotMatch(llm.calls[0]!.prompt, /maybe/);
    store.close();
  });
});

test("triagePilotFindings: AI sees leftover suspected High A06 with version banner, not the writeup", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const hdr = { server: "Apache/2.4.49 (Unix)" };
    const c = ev(evidence, "negative_control", "ok", 200, hdr);
    const p1 = ev(evidence, "positive_replay", "ok", 200, hdr);
    const f = finding({
      id: "f-011",
      title: "[vulnerable-component] Outdated Apache httpd 2.4.49 — CVE-2021-41773 — do not show this title to the triager",
      verdict: "suspected",
      evidenceIds: [c.id, p1.id],
    });
    store.upsertFinding("a-1", f);
    const llm = new FakeLlmClient('{"verdict":"confirmed","reason":"Server banner is Apache/2.4.49"}');
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(r.demoted, 0);
    assert.equal(llm.calls.length, 3); // adversarial panel = 3 independent lenses
    assert.match(llm.calls[0]!.prompt, /server: Apache\/2\.4\.49/);
    assert.doesNotMatch(llm.calls[0]!.prompt, /do not show this title/);
    assert.equal(findingVerdict(f), "suspected");
    assert.equal(f.severity, "high");
    store.close();
  });
});

// The panel's defining property: a finding is demoted only on a MAJORITY of skeptics, and a medium weak-oracle class
// (IDOR) is reviewed at all (not just High+). A responder that refutes only on the named lenses lets us script the vote.
function lensResponder(fpLenses: string[]): (req: { system?: string }) => string {
  return (req) => {
    const s = req.system ?? "";
    const isFp = fpLenses.some((m) => s.includes(m));
    return JSON.stringify(isFp ? { verdict: "false_positive", reason: "refuted by this lens" } : { verdict: "confirmed", reason: "held under this lens" });
  };
}

function idorFinding(store: AssessmentStore, evidence: EvidenceStore): Finding {
  const c = ev(evidence, "negative_control", JSON.stringify({ error: "forbidden" }), 403);
  const p1 = ev(evidence, "positive_replay", JSON.stringify({ orderId: 9001, total: 42, customer: "acct-2" }));
  const p2 = ev(evidence, "positive_replay", JSON.stringify({ orderId: 9001, total: 42, customer: "acct-2" }));
  const f = finding({ id: "f-idor", title: "[idor] cross-user order read", severity: "medium", evidenceIds: [c.id, p1.id, p2.id] });
  store.upsertFinding("a-1", f);
  return f;
}

test("adversarial panel: a MAJORITY (2/3) demotes — a medium IDOR is reviewed via the weak-oracle path, not just High+", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const f = idorFinding(store, evidence);
    const llm = new FakeLlmClient(lensResponder(["exploitability", "reproducibility & control"])); // 2 of 3 refute
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(llm.calls.length, 3);
    assert.equal(r.demoted, 1);
    assert.equal(findingVerdict(f), "suspected");
    assert.ok(f.title.startsWith("[qa?]"));
    assert.match(f.anomaly ?? "", /2\/3 skeptics/);
    store.close();
  });
});

test("adversarial panel: a MINORITY (1/3) does NOT demote", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const f = idorFinding(store, evidence);
    const llm = new FakeLlmClient(lensResponder(["known scanner false positives"])); // only 1 of 3 refutes
    const r = await triagePilotFindings({ store, assessmentId: "a-1", evidence, findings: [f], llm });
    assert.equal(llm.calls.length, 3);
    assert.equal(r.demoted, 0);
    assert.equal(findingVerdict(f), "confirmed");
    assert.ok(!f.title.startsWith("[qa?]"));
    store.close();
  });
});

// Regression (found by an e2e run against real Juice Shop): a genuine JSON auth-bypass whose CONTROL is a plain-text 401
// ("Invalid email or password") and whose POSITIVE is 200 JSON with a token must NOT be demoted as an HTML-length FP.
// The old rule required control+positives to ALL be structured; the effect lives in the positives, so judge those.
test("judgeConfirmedFinding: JSON auth-bypass with a plain-text 401 control is kept (not an HTML-length FP)", () =>
  withDir((dir) => {
    const { store, evidence } = setup(dir);
    const c = ev(evidence, "negative_control", "Invalid email or password", 401);
    const tok = JSON.stringify({ authentication: { token: "eyJhbGciOi...", umail: "admin@juice-sh.op" } });
    const p1 = ev(evidence, "positive_replay", tok, 200);
    const p2 = ev(evidence, "positive_replay", tok, 200);
    const f = finding({ id: "f-authbypass", title: "[sqli] auth-bypass ' OR 1=1--", severity: "critical", evidenceIds: [c.id, p1.id, p2.id] });
    assert.equal(judgeConfirmedFinding(f, evidence).demote, false);
    store.close();
  }));

test("final QA retains duplicate audit rows while exports and reloads count one canonical finding", async () => {
  await withDir(async (dir) => {
    const { store, evidence } = setup(dir);
    const c = ev(evidence, "negative_control", '{"rows":[]}');
    const p1 = ev(evidence, "positive_replay", '{"rows":[{"id":1}]}');
    const p2 = ev(evidence, "positive_replay", '{"rows":[{"id":1}]}');
    for (const r of [p1,p2]) r.request.url = BASE + "search?q=' OR 1=1--";
    const a = finding({ id: "f-001", title: "[sqli] Query injection", evidenceIds: [c.id,p1.id,p2.id], dedupKey: "sqli::/search::q" });
    const b = finding({ id: "f-009", title: "[sqli] Same query on another screen", evidenceIds: [c.id,p1.id,p2.id] });
    store.upsertFinding("a-1", a);
    store.upsertFinding("a-1", b);
    const result = await triagePilotFindings({ store, assessmentId: "a-1", evidence });
    assert.equal(result.merged, 1);
    assert.equal(store.loadAssessment("a-1")!.findings.length, 1);
    const audit = store.loadAssessment("a-1", { includeDuplicates: true })!;
    assert.equal(audit.findings.length, 2);
    assert.equal(audit.findings[1]!.duplicateOf, "f-001");
    assert.equal(audit.findings[0]!.dedupKey, "sqli::/search::q");
    const { buildReportModel } = await import("@veritas/core");
    assert.equal(buildReportModel(audit).stats.findings.total, 1);
    assert.equal((await triagePilotFindings({ store, assessmentId: "a-1", evidence })).merged, 0);
    store.close();
  });
});
