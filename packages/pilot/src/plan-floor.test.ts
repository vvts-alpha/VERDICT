// Deterministic plan floor: signal-derived minimum attack classes are injected as bounded plan slots
// regardless of what the LLM methodology wrote, carry tool "plan-floor" provenance, and hold the
// screen_done ledger gate exactly like plan slots — a screen can't close on "the plan didn't name it".
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildTools, floorRowsFor } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { recordCheck } from "./checks.js";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { InventoryBuilder } from "@veritas/crawler";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { ApiCall, Param, Screen } from "@veritas/core";

const TARGET = "http://127.0.0.1:9/"; // never contacted — gates only

const P = (name: string, loc: Param["in"], example = "x", guessedType: Param["guessedType"] = "unknown"): Param => ({
  name,
  in: loc,
  example,
  guessedType,
});
const screen = (params: Param[], apis: ApiCall[] = []): Screen => ({
  screenId: "s-0001",
  urlTemplate: "/x",
  observedUrls: [],
  authState: "unauth",
  screenType: "form",
  description: "",
  params,
  apis,
  screenshot: "",
  domSkeletonHash: "",
  labels: [],
});
const stub = { targetUrl: TARGET } as PilotSession;
const classes = (sc: Screen) => floorRowsFor(stub, sc).map((r) => r.checkClass);

test("floor: id-bearing params produce idor slots; write needs a mutating api", () => {
  const get = { method: "GET", urlTemplate: "/api/o/{id}", auth: "none", reqSchema: null, resSchema: null } as ApiCall;
  const post = { ...get, method: "POST" };

  const sc = screen([P("orderId", "query", "o10", "object_ref")], [get]);
  const rows = floorRowsFor(stub, sc);
  assert.equal(rows.length, 1);
  assert.equal(rows[0]!.checkClass, "idor");
  assert.equal(rows[0]!.param, "orderId");
  assert.equal(rows[0]!.tool, "plan-floor");
  assert.equal(rows[0]!.status, "planned");

  // A mutating surface upgrades the same reference to idor-write coverage too.
  const rowsW = floorRowsFor(stub, screen([P("orderId", "query", "o10", "object_ref")], [post]));
  assert.deepEqual(rowsW.map((r) => r.checkClass).sort(), ["idor", "idor-write"]);
});

test("floor: GraphQL id-bearing variable leaves become target-scoped idor slots", () => {
  const api = {
    method: "POST",
    urlTemplate: "/graphql",
    auth: "bearer",
    reqSchema: null,
    resSchema: null,
    graphql: { operationKey: "name:GetOrder", variablesExample: { input: { orderId: "o1" } } },
  } as unknown as ApiCall;
  const rows = floorRowsFor(stub, screen([], [api]));
  assert.equal(rows.length, 2); // idor + idor-write (POST mutates)
  assert.ok(rows.every((r) => r.target.includes("GetOrder")));
  assert.ok(rows.every((r) => r.param === "variables.input.orderId"));
});

test("floor: signal-named params bind redirect / ssrf / enum / logic / upload classes", () => {
  const post = { method: "POST", urlTemplate: "/x", auth: "cookie", reqSchema: null, resSchema: null } as ApiCall;
  const sc = screen(
    [
      P("next", "query"),
      P("callback_url", "query", "https://cb", "free_text"),
      P("username", "body", "x", "free_text"),
      P("price", "body", "9.99", "price"),
      P("qty", "body", "1", "qty"),
      P("file", "body", "x", "file"),
      P("sort", "query", "asc", "enum"), // no signal — must NOT produce a slot
    ],
    [post],
  );
  const got = classes(sc).sort();
  assert.deepEqual(got, ["open-redirect", "price-tampering", "qty-tampering", "ssrf", "upload", "user-enumeration"]);
});

test("floor: jwt-shaped values and xml endpoints get session / xxe slots; static screens get nothing", () => {
  const jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc";
  const api = { method: "POST", urlTemplate: "/soap/service.asmx", auth: "cookie", reqSchema: null, resSchema: null } as ApiCall;
  const got = classes(screen([P("token", "body", jwt)], [api])).sort();
  assert.deepEqual(got, ["session", "xxe"]);

  // JWT example on a plain param → session slot.
  const got2 = classes(screen([P("auth", "query", jwt)])).sort();
  assert.ok(got2.includes("session"));
  assert.deepEqual(classes(screen([P("q", "query")], [])), []);
});

// ── store-backed: floor rows land in the ledger, are skipped when the plan covers the slot,
//    never clobber a real outcome, and hold the screen_done gate ──
let dir = "";
let dbN = 0;
const stores: AssessmentStore[] = [];
before(() => {
  dir = mkdtempSync(join(tmpdir(), "veritas-planfloor-"));
});
after(() => {
  for (const s of stores) try { s.close(); } catch { /* closed */ }
  rmSync(dir, { recursive: true, force: true });
});

function session(): PilotSession {
  const store = AssessmentStore.open(join(dir, `f${dbN++}.sqlite`));
  stores.push(store);
  store.createAssessment({ id: "a-1", target: { kind: "single_url", url: TARGET, followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl(TARGET) });
  const inv = new InventoryBuilder();
  const screenId = inv.ingest({
    requestedUrl: `${TARGET}order?uid=7&next=/home`,
    finalUrl: `${TARGET}order?uid=7&next=/home`,
    status: 200,
    title: "order",
    domSkeleton: "<html><body></body></html>",
    visibleText: "order",
    forms: [],
    links: [],
    virtualRoutes: [],
    apiCalls: [],
    scripts: [],
  } as never).screen.screenId;
  return {
    http: new FetchHttpClient({ allow: () => false }),
    store, assessmentId: "a-1", evidence: new EvidenceStore(join(dir, `art-${dbN}`)), inv,
    scope: deriveScopeFromSingleUrl(TARGET), targetUrl: TARGET, currentScreenId: screenId,
    currentCookie: "", currentBearer: "", currentRole: "userA",
    roleSessions: undefined, roleCookieFiles: new Map(), roleCreds: new Map(), roleDescriptions: new Map(),
    roleIdentityUrls: new Map(), rolePrincipals: new Map(), roleTenants: new Map(), expectedAccess: [],
    sessionPrincipals: new Map(), visitedByRole: new Map(), roleSurveyBlocked: new Map(),
    findings: [], findingsByKey: new Map(), findCounter: 0, accessVerdicts: new Map(),
    httpProbes: 0, screenProbes: 1, httpAuthWall: 0, httpThrough: 0,
    plans: new Map(), visited: new Set(), frontier: new Set(), refererGated: new Set(), ignorePaths: [],
  } as unknown as PilotSession;
}

async function run(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const t = buildTools(s).find((x) => (x as { name: string }).name === name) as { handler: (a: unknown, e: unknown) => Promise<{ content: { text: string }[] }> };
  return (await t.handler(args, {})).content[0]!.text;
}

test("floor: plan covering the slot wins provenance; an empty plan still gets the floor", async () => {
  const s = session();
  // Methodology plans idor only — the floor's open-redirect slot on `next` is still owed.
  const out = await run(s, "record_methodology", { screenId: s.currentScreenId, vulnClasses: ["idor"], plan: "swap uid" });
  assert.match(out, /floor slot/);
  const checks = s.store.checks(s.assessmentId).filter((c) => c.status === "planned");
  const byKey = new Map(checks.map((c) => [c.id, c]));
  // uid object_ref → methodology's own idor slot keeps tool "methodology" (floor skips covered keys)
  const idor = checks.find((c) => c.checkClass === "idor");
  assert.ok(idor);
  assert.equal(idor!.tool, "methodology");
  // `next` redirect param → floor-only slot
  const redirect = checks.find((c) => c.checkClass === "open-redirect");
  assert.ok(redirect);
  assert.equal(redirect!.tool, "plan-floor");
  assert.equal(redirect!.param, "next");
  assert.ok(byKey.size >= 2);
});

test("floor: unfulfilled floor slot blocks screen_done; an honest-gap entry satisfies it", async () => {
  const s = session();
  await run(s, "record_methodology", { screenId: s.currentScreenId, vulnClasses: ["idor"], plan: "swap uid" });
  // Plan's idor slot is satisfied by a REAL execution row (a probe on param uid); the floor's
  // open-redirect slot still has nothing — screen_done must reject.
  recordCheck(s, { tool: "probe_idor", checkClass: "idor", target: "GET /order", param: "uid", status: "tested-clean", reason: "same 404 for other ids" });
  const rej = await run(s, "screen_done", {
    verdict: "clean",
    coverage: [
      { class: "idor", result: "tested-clean" },
      { class: "open-redirect", result: "tested-clean" },
    ],
  });
  assert.match(rej, /NOT DONE/);
  assert.match(rej, /open-redirect/);
  // Honest gap declaration satisfies the slot without fabricating an execution.
  const ok = await run(s, "screen_done", {
    verdict: "clean",
    coverage: [
      { class: "idor", result: "tested-clean" },
      { class: "open-redirect", result: "not-applicable", note: "next only accepts relative paths (validated allowlist)" },
    ],
  });
  assert.doesNotMatch(ok, /NOT DONE/);
});

test("floor: idempotent across ensurePlanSlots; an execution row is never clobbered", async () => {
  const s = session();
  await run(s, "record_methodology", { screenId: s.currentScreenId, vulnClasses: [], plan: "hygiene only" });
  const before1 = s.store.checks(s.assessmentId).filter((c) => c.tool === "plan-floor").length;
  assert.ok(before1 > 0); // empty plan still got floor rows (idor on uid, open-redirect on next)
  // Simulate a real execution row sharing the slot key (subject "" context): floor must not overwrite it.
  const row = s.store.checks(s.assessmentId).find((c) => c.checkClass === "open-redirect")!;
  s.store.upsertCheck(s.assessmentId, { ...row, status: "tested-clean", updatedAt: new Date().toISOString() });
  await run(s, "screen_done", { verdict: "clean", coverage: [{ class: "idor", result: "not-applicable", note: "no secondary role" }, { class: "open-redirect", result: "tested-clean" }] });
  const after1 = s.store.checks(s.assessmentId).find((c) => c.id === row.id)!;
  assert.equal(after1.status, "tested-clean"); // still the execution outcome — floor didn't rewrite it
});
