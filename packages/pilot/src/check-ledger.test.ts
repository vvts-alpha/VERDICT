// Unit-level acceptance for the check-ledger gates (no network): bounded plan slots must be satisfied
// by REAL execution rows (or honest gap declarations) — a coverage array alone can never mark a class
// clean, and one input's probe never answers for another input/class/role. Also covers the per-role
// survey_done gate (role A's visits don't satisfy role B).
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { recordCheck } from "./checks.js";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { InventoryBuilder } from "@veritas/crawler";
import { AssessmentStore, deriveScopeFromSingleUrl, screenChecks } from "@veritas/core";
import type { Finding } from "@veritas/core";

const TARGET = "http://127.0.0.1:9/"; // never contacted — these tests exercise gates, not probes
let dir = "";
let dbN = 0;
const fixtureStores: AssessmentStore[] = [];

before(() => {
  dir = mkdtempSync(join(tmpdir(), "veritas-checkledger-"));
});
after(() => {
  for (const s of fixtureStores) try { s.close(); } catch { /* already closed */ }
  rmSync(dir, { recursive: true, force: true });
});

/** A session with a real InventoryBuilder carrying one screen at /search?q=&id=&uid= . */
function session(opts: { roles?: string[] } = {}): PilotSession {
  const store = AssessmentStore.open(join(dir, `s${dbN++}.sqlite`));
  fixtureStores.push(store);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: TARGET, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(TARGET) });
  const inv = new InventoryBuilder();
  const obs = {
    requestedUrl: `${TARGET}search?q=x&id=1&uid=7`,
    finalUrl: `${TARGET}search?q=x&id=1&uid=7`,
    status: 200,
    title: "search",
    domSkeleton: "<html><body></body></html>",
    visibleText: "search",
    forms: [],
    links: [],
    virtualRoutes: [],
    apiCalls: [],
    scripts: [],
  };
  const screenId = inv.ingest(obs as never).screen.screenId;
  const roleCreds = new Map<string, never>();
  for (const r of opts.roles ?? []) roleCreds.set(r, { username: r, password: "x" } as never);
  return {
    http: new FetchHttpClient({ allow: () => false }),
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, `art-${dbN}`)), inv,
    scope: deriveScopeFromSingleUrl(TARGET), targetUrl: TARGET, currentScreenId: screenId,
    currentCookie: "", currentBearer: "", currentRole: opts.roles?.[0] ?? "userA",
    roleSessions: undefined, roleCookieFiles: new Map(), roleCreds, roleDescriptions: new Map(),
    roleIdentityUrls: new Map(), rolePrincipals: new Map(), roleTenants: new Map(), expectedAccess: [],
    sessionPrincipals: new Map(), visitedByRole: new Map(), roleSurveyBlocked: new Map(),
    findings: [], findingsByKey: new Map(), findCounter: 0, accessVerdicts: new Map(),
    httpProbes: 0, screenProbes: 1, httpAuthWall: 0, httpThrough: 0,
    plans: new Map(), visited: new Set(), frontier: new Set(), refererGated: new Set(), ignorePaths: [],
  } as unknown as PilotSession;
}

async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<Record<string, unknown>> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  const out = (await t.handler(args, {})).content[0]!.text;
  try { return JSON.parse(out) as Record<string, unknown>; } catch { return { raw: out }; }
}

const METHODOLOGY = (s: PilotSession, classes: string[]) => ({
  screenId: s.currentScreenId,
  vulnClasses: classes,
  plan: `classes=[${classes.join(",")}] attack the surface`,
});

test("bounded plan slots expand per param/object and screen_done refuses coverage-only claims", async () => {
  const s = session();
  await run(s, "record_methodology", METHODOLOGY(s, ["sqli", "idor"]));
  const planned = s.store.checks("a-1").filter((c) => c.status === "planned");
  // sqli is input-bound: one slot per param (q, id, uid). idor is object-bound: id-bearing params only (id, uid).
  assert.equal(planned.filter((c) => c.checkClass === "sqli").length, 3, JSON.stringify(planned.map((p) => [p.checkClass, p.param])));
  assert.ok(planned.filter((c) => c.checkClass === "idor").length >= 1);
  // A coverage array claiming tested-clean cannot close the screen — no execution rows exist.
  const r = await run(s, "screen_done", {
    verdict: "clean",
    coverage: [
      { class: "sqli", result: "tested-clean" },
      { class: "idor", result: "tested-clean" },
    ],
  });
  assert.match(String(r.raw ?? JSON.stringify(r)), /NOT DONE — plan slot .* is UNFULFILLED/);
  assert.ok(!s.screenDone);
});

test("one input's execution never satisfies another input or class", async () => {
  const s = session();
  await run(s, "record_methodology", METHODOLOGY(s, ["sqli", "idor"]));
  // Only param 'q' was actually exercised for sqli (a trusted-path execution row).
  recordCheck(s, { tool: "probe_sqli", checkClass: "sqli", target: "GET /search", param: "q", status: "tested-clean", reason: "no differential" });
  const r = await run(s, "screen_done", {
    verdict: "clean",
    coverage: [
      { class: "sqli", result: "tested-clean" },
      { class: "idor", result: "tested-clean" },
    ],
  });
  const msg = String(r.raw ?? JSON.stringify(r));
  assert.match(msg, /NOT DONE/);
  assert.match(msg, /param:(id|uid)/, "the unexercised param slot is the one refusing the close");
  assert.ok(!s.screenDone);
});

test("honest gap declarations (unverified/blocked/not-applicable) close the screen and stay visible", async () => {
  const s = session();
  await run(s, "record_methodology", METHODOLOGY(s, ["sqli", "idor"]));
  recordCheck(s, { tool: "probe_sqli", checkClass: "sqli", target: "GET /search", param: "q", status: "tested-clean", reason: "no differential" });
  const r = await run(s, "screen_done", {
    verdict: "clean",
    coverage: [
      { class: "sqli", result: "unverified", note: "WAF reset the connection on id/uid payloads" },
      { class: "idor", result: "blocked", note: "second role session expired" },
    ],
  });
  assert.match(String(r.raw ?? JSON.stringify(r)), /^screen s-0001/);
  assert.ok(s.screenDone);
  const view = screenChecks({ checkExecutions: s.store.checks("a-1") }, s.currentScreenId ?? "");
  assert.equal(view.unstarted.length, 0, "all slots bound");
  assert.ok(view.gaps.length >= 2, "the honest gaps are preserved in the ledger");
  assert.ok(!view.classes.every((c) => c.conclusive), "a screen with gaps is not 'conclusive'");
});

test("a recorded finding satisfies its own slot via the ledger (not via note text)", async () => {
  const s = session();
  await run(s, "record_methodology", METHODOLOGY(s, ["sqli"]));
  // A real recorded finding on this screen, titled [sqli] like record_finding produces.
  const f = { id: "f-1", title: "[sqli] boolean differential on q", severity: "high", screenId: s.currentScreenId, verdict: "confirmed", evidenceIds: ["e-1", "e-2", "e-3"] } as unknown as Finding;
  s.findings.push(f);
  // Slot q gets the finding; slots id/uid still need accounting — declare them honestly.
  recordCheck(s, { tool: "probe_sqli", checkClass: "sqli", target: "GET /search", param: "q", status: "found", reason: "confirmed", findingIds: ["f-1"], evidenceIds: ["e-1"] });
  const r = await run(s, "screen_done", {
    verdict: "finding",
    coverage: [
      { class: "sqli", result: "found" },
    ],
  });
  const msg = String(r.raw ?? JSON.stringify(r));
  assert.match(msg, /NOT DONE/, `remaining slots still gate: ${msg}`);
  const r2 = await run(s, "screen_done", {
    verdict: "finding",
    coverage: [
      { class: "sqli", result: "found" },
      { class: "sqli", result: "not-applicable", note: "q was the only injectable param; id/uid are pure numeric routing" },
      // Deterministic floor slots (idor on the id/uid object refs) hold the same gate as plan slots.
      { class: "idor", result: "not-applicable", note: "id/uid are single-tenant routing ids — no secondary principal exists to cross-check" },
    ],
  });
  // id/uid get honest gap rows → close succeeds, finding row preserved.
  assert.match(String(r2.raw ?? JSON.stringify(r2)), /^screen s-0001/);
  const rows = s.store.checks("a-1");
  assert.ok(rows.some((c) => c.status === "found" && c.checkClass === "sqli"));
  assert.ok(rows.some((c) => c.status === "not-applicable" && c.checkClass === "sqli"), "gap rows written for the untouched params");
});

test("legacy plan (no slot rows) materializes on demand at screen_done", async () => {
  const s = session();
  s.plans.set(s.currentScreenId ?? "", "classes=[sqli] legacy plan text without slots");
  const r = await run(s, "screen_done", { verdict: "clean", coverage: [{ class: "sqli", result: "tested-clean" }] });
  assert.match(String(r.raw ?? JSON.stringify(r)), /NOT DONE/);
  assert.ok(s.store.checks("a-1").some((c) => c.status === "planned"), "slots materialized from the legacy plan");
});

test("survey_done refuses until EVERY configured role mapped under its own session (or blocked)", async () => {
  const s = session({ roles: ["userA", "userB"] });
  s.frontier.clear();
  // Only role A navigated.
  s.visitedByRole.set("userA", new Set([`${TARGET}search`]));
  const r1 = await run(s, "survey_done", { summary: "done" });
  assert.match(String(r1.raw ?? JSON.stringify(r1)), /survey_done REFUSED.*userB/);
  assert.ok(!s.surveyDone);
  // An explicit block reason lets the gate pass — the gap stays on record.
  s.roleSurveyBlocked.set("userB", "login failed: invalid credentials");
  const r2 = await run(s, "survey_done", { summary: "done" });
  assert.match(String(r2.raw ?? JSON.stringify(r2)), /survey complete/);
  assert.ok(s.surveyDone);
});

test("A/B rows for different principals/resources never collapse into one key", async () => {
  const s = session();
  recordCheck(s, { tool: "probe_authz", checkClass: "idor", target: "GET /api/orders/{id}", subject: "userB", resource: "k-o-a1", status: "unverified", reason: "x" });
  recordCheck(s, { tool: "probe_authz", checkClass: "idor", target: "GET /api/orders/{id}", subject: "userC", resource: "k-o-a1", status: "tested-clean", reason: "y" });
  recordCheck(s, { tool: "probe_authz", checkClass: "idor", target: "GET /api/orders/{id}", subject: "userB", resource: "k-o-b1", status: "found", reason: "z" });
  const rows = s.store.checks("a-1");
  const keys = new Set(rows.map((c) => c.id));
  assert.equal(keys.size, rows.length, "distinct (subject,resource) rows — no key collapse");
  assert.ok(rows.some((c) => c.status === "unverified") && rows.some((c) => c.status === "found"), "one object's unverified does not erase another's finding");
});
