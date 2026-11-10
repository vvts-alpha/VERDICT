import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import type { CheckExecution } from "@veritas/core";
import { InventoryBuilder } from "@veritas/crawler";
import { EvidenceStore, FetchHttpClient } from "@veritas/scanner";
import { extractProbeOutcome, recordCheck, sessionRefOf, subjectCtx } from "./checks.js";
import { buildTools } from "./tools.js";
import type { PilotSession } from "./tools.js";

const URL = "https://app.test/account";

function session(t: { after(fn: () => void): void }, responseStatus = 200, acao = ""): PilotSession {
  const dir = mkdtempSync(join(tmpdir(), "verdict-check-outcome-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  t.after(() => {
    store.close();
    rmSync(dir, { recursive: true, force: true });
  });
  const scope = deriveScopeFromSingleUrl(URL);
  store.createAssessment({ id: "a", target: { kind: "single_url", url: URL, followLinks: true, maxDepth: 2 }, scope });
  const http = new FetchHttpClient({ allow: () => true });
  // No network: the real tool and evidence instrumentation see a deterministic fake sender.
  http.send = async (req) => ({
    status: responseStatus,
    headers: req.headers?.origin && acao ? { "access-control-allow-origin": acao } : {} as Record<string, string>,
    body: "normal body (password / login / proxy are just words)",
    finalUrl: req.url,
    durationMs: 1,
  });
  return {
    http, store, assessmentId: "a", evidence: new EvidenceStore(join(dir, "artifacts")),
    inv: new InventoryBuilder(),
    scope, targetUrl: URL, currentScreenId: "s-1", currentRole: "user",
    currentCookie: "", currentBearer: "", roleCreds: new Map(),
    roleCookieFiles: new Map(), roleDescriptions: new Map(), visitedByRole: new Map(),
    httpProbes: 0, screenProbes: 0, httpAuthWall: 0, httpThrough: 0,
  } as unknown as PilotSession;
}

function evidence(s: PilotSession, status: number, kind: "negative_control" | "positive_replay" = "negative_control", finalUrl = URL): string {
  return s.evidence.record({
    screenId: "s-1", validator: "fake", kind, note: "fake response",
    request: { method: "GET", url: URL, headers: {}, body: null },
    response: { status, headers: {}, body: "contains login/password/proxy words", finalUrl, durationMs: 1 },
  }).id;
}

function responseEvidence(
  s: PilotSession, body: string, headers: Record<string, string> = {},
  kind: "negative_control" | "positive_replay" = "negative_control", finalUrl = URL,
): string {
  return s.evidence.record({
    screenId: "s-1", validator: "fake", kind, note: "response validity",
    request: { method: "GET", url: URL, headers: {}, body: null },
    response: { status: 200, headers, body, finalUrl, durationMs: 1 },
  }).id;
}

async function invoke(s: PilotSession, name: string, args: Record<string, unknown>): Promise<string> {
  const d = buildTools(s).find((item) => (item as { name: string }).name === name) as {
    handler: (a: Record<string, unknown>, e: unknown) => Promise<{ content: { text: string }[] }>;
  };
  assert.ok(d, `missing tool ${name}`);
  return (await d.handler(args, {})).content[0]!.text;
}

test("recordCheck persists an optional typed reason code and remains compatible with old rows", (t) => {
  const s = session(t);
  s.currentBearer = "secret-credential";
  const code: NonNullable<CheckExecution["reasonCode"]> = "missing-prerequisite";
  recordCheck(s, { tool: "probe_jwt", checkClass: "session", target: "GET /account", status: "blocked", reason: "missing replay material", reasonCode: code });
  const current = s.store.checks("a")[0]!;
  assert.equal(current.reasonCode, code);
  const recorded = s.store.loadAssessment("a")!.events.filter((e) => e.type === "check_recorded");
  assert.equal((recorded.at(-1)?.payload as { check: CheckExecution }).check.reasonCode, code);
  assert.doesNotMatch(JSON.stringify(recorded), /secret-credential/);

  const legacy: CheckExecution = {
    id: "old-shape", screenId: "s-1", target: "GET /account", subject: "user",
    checkClass: "legacy", status: "unverified", reason: "legacy gap",
    evidenceIds: [], findingIds: [], updatedAt: new Date().toISOString(),
  };
  s.store.upsertCheck("a", legacy);
  const restored = s.store.checks("a").find((row) => row.id === legacy.id)!;
  assert.equal(restored.reasonCode, undefined);
  assert.equal(restored.reason, "legacy gap");
});

test("clean and confirmed require a recorded usable baseline; no body-word auth inference", (t) => {
  const s = session(t);
  assert.deepEqual(
    [extractProbeOutcome(s, JSON.stringify({ result: "clean", verdict: "login succeeded" })).status,
      extractProbeOutcome(s, JSON.stringify({ result: "clean" })).reasonCode],
    ["unverified", "missing-evidence"],
  );
  const rejected = evidence(s, 403);
  const invalid = extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: rejected, verdict: "safe password" }));
  assert.equal(invalid.status, "unverified");
  assert.equal(invalid.reasonCode, "invalid-baseline");
  assert.equal(invalid.baselineOk, false);

  const valid = evidence(s, 200);
  const clean = extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: valid, verdict: "proxy login password" }));
  assert.equal(clean.status, "tested-clean");
  assert.equal(clean.baselineOk, true);
  assert.deepEqual(clean.evidenceIds, [valid]);
  assert.equal(clean.reasonCode, undefined);
  const bounced = evidence(s, 200, "negative_control", "https://app.test/login");
  const redirected = extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: bounced }));
  assert.equal(redirected.status, "unverified", "a 200 after an actual login redirect is not an app baseline");
  assert.equal(redirected.reasonCode, "invalid-baseline");
  const missing = extractProbeOutcome(s, JSON.stringify({ result: "confirmed", negativeControl: valid, positiveReplays: ["ev-not-recorded", "ev-other"] }));
  assert.equal(missing.status, "unverified");
  assert.equal(missing.reasonCode, "missing-evidence");
  assert.deepEqual(missing.evidenceIds, [valid], "unknown ids must not be persisted as evidence");
  const missingExtra = extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: valid, evidenceIds: ["ev-not-recorded"] }));
  assert.equal(missingExtra.status, "unverified");
  assert.equal(missingExtra.reasonCode, "missing-evidence");
});

test("confirmed uses the existing distinct control + two replay floor with real evidence", (t) => {
  const s = session(t);
  const baseline = evidence(s, 200);
  const control = evidence(s, 404);
  const p1 = evidence(s, 200, "positive_replay");
  const p2 = evidence(s, 200, "positive_replay");
  const shape = { result: "confirmed", baselineEvidenceId: baseline, negativeControl: control, positiveReplays: [p1, p2] };
  const found = extractProbeOutcome(s, JSON.stringify(shape));
  assert.equal(found.status, "found");
  assert.equal(found.reasonCode, undefined);
  assert.equal(found.baselineOk, true);
  assert.deepEqual(new Set(found.evidenceIds), new Set([baseline, control, p1, p2]));
  const duplicate = extractProbeOutcome(s, JSON.stringify({ ...shape, positiveReplays: [p1, p1] }));
  assert.equal(duplicate.status, "unverified");
  assert.equal(duplicate.reasonCode, "missing-evidence");
  const badBase = extractProbeOutcome(s, JSON.stringify({ ...shape, baselineEvidenceId: control }));
  assert.equal(badBase.status, "unverified");
  assert.equal(badBase.reasonCode, "invalid-baseline");
  const absentBase = extractProbeOutcome(s, JSON.stringify({ ...shape, baselineEvidenceId: "ev-does-not-exist" }));
  assert.equal(absentBase.status, "unverified");
  assert.equal(absentBase.reasonCode, "missing-evidence");
});

test("200 proxy/WAF interstitials and inline login forms cannot be app baselines or confirmed replays", (t) => {
  const s = session(t);
  const normal = responseEvidence(s, "<article>Our login, password and proxy documentation is here.</article>");
  const interstitials = [
    responseEvidence(s, "<html><title>Burp Suite</title><h1>Error</h1>SOCKS: Host unreachable</html>"),
    responseEvidence(s, "<html><title>Just a moment...</title>Checking your browser — Cloudflare challenge</html>"),
    responseEvidence(s, "<html><title>Access Denied</title><h1>Request blocked by WAF</h1></html>"),
    responseEvidence(s, "<html><form action='/login'><input name='username'><input name='password' type='password'></form></html>", { "content-type": "text/html" }),
    responseEvidence(s, '{"error":"unauthorized","data":null}', { "content-type": "application/json" }),
    responseEvidence(s, "{\"message\":\"try later\"}", { "cf-mitigated": "challenge" }),
    responseEvidence(s, "<div>Sorry, proxy unavailable</div>", {}, "negative_control", "https://app.test/error"),
    responseEvidence(s, ""),
  ];
  for (const id of interstitials) {
    for (const result of ["clean", "confirmed"]) {
      const outcome = extractProbeOutcome(s, JSON.stringify({ result, negativeControl: id, positiveReplays: [normal, responseEvidence(s, "ok", {}, "positive_replay")] }));
      assert.equal(outcome.status, "unverified", `${result} under ${id}`);
      assert.equal(outcome.reasonCode, "invalid-baseline");
      assert.equal(outcome.baselineOk, false);
    }
  }
  assert.equal(extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: normal })).status, "tested-clean");
  const control = evidence(s, 404);
  const benign = responseEvidence(s, "ordinary response", {}, "positive_replay");
  const found = extractProbeOutcome(s, JSON.stringify({ result: "confirmed", baselineEvidenceId: normal, negativeControl: control, positiveReplays: [benign, interstitials[0]] }));
  assert.equal(found.status, "unverified", "a confirmed probe's replay cannot be a proxy 200");
  assert.equal(found.reasonCode, "unstable-response");
  const deniedResource = evidence(s, 403);
  const denied = extractProbeOutcome(s, JSON.stringify({ result: "clean", negativeControl: deniedResource }));
  assert.equal(denied.status, "unverified", "resource denial is not a clean baseline or evidence that a role is dead");
  assert.equal(denied.reasonCode, "invalid-baseline");
});

test("a principal belongs only to the effective cookie that established it, including explicit row headers", (t) => {
  const s = session(t);
  s.rolePrincipals = new Map([["user", "operator-declared-alice"]]);
  s.roleIdentityUrls = new Map([["user", "https://app.test/me"]]);
  s.currentCookie = "sid=alice";
  const aliceHeaders = s.http.effectiveHeaders({ cookie: "sid=alice" }, true);
  const bobHeaders = s.http.effectiveHeaders({ cookie: "sid=bob" }, true);
  s.sessionPrincipals = new Map([["user", { principal: "alice", sessionRef: sessionRefOf(aliceHeaders) }]]);
  recordCheck(s, { tool: "probe_cors", checkClass: "cors-misconfig", target: "GET /account", status: "unverified", reason: "old", startedAt: new Date(0).toISOString() });
  const alice = s.store.checks("a")[0]!;
  assert.equal(alice.principal, "alice");
  assert.ok(alice.startedAt);

  s.currentCookie = "sid=bob"; // no whoami for this material
  assert.equal(subjectCtx(s, "user").principal, undefined);
  recordCheck(s, { tool: "probe_cors", checkClass: "cors-misconfig", target: "GET /account", status: "unverified", reason: "rotated" });
  const bob = s.store.checks("a").find((r) => r.session === sessionRefOf(bobHeaders))!;
  assert.ok(bob);
  assert.equal(bob.principal, undefined);
  assert.notEqual(bob.id, alice.id);
  recordCheck(s, { tool: "probe_cors", checkClass: "cors-misconfig", target: "GET /account", status: "blocked", reason: "sent old headers", sessionHeaders: aliceHeaders });
  assert.equal(s.store.checks("a").find((r) => r.session === sessionRefOf(aliceHeaders))?.principal, "alice");
  recordCheck(s, { tool: "probe_cors", checkClass: "cors-misconfig", target: "GET /account", status: "blocked", reason: "sent Bob's headers", sessionHeaders: bobHeaders });
  assert.equal(s.store.checks("a").find((r) => r.session === sessionRefOf(bobHeaders))?.principal, undefined);
  recordCheck(s, { tool: "probe_cors", checkClass: "cors-misconfig", target: "GET /account", status: "blocked", reason: "claimed old ref but sent new headers", session: sessionRefOf(aliceHeaders), sessionHeaders: bobHeaders });
  assert.equal(s.store.checks("a").find((r) => r.session === sessionRefOf(bobHeaders))?.principal, undefined);

  s.roleIdentityUrls.clear(); // declaration is permitted only without a configured identity probe
  assert.equal(subjectCtx(s, "user").principal, "operator-declared-alice");
});

test("no result contract, explicit blocked/unverified, and unknown codes stay distinct and secret-free", (t) => {
  const s = session(t);
  const secret = "Bearer secret-credential";
  for (const text of [`CONFIRMED: ${secret}`, JSON.stringify({ verdict: `clean ${secret}` }), JSON.stringify({ result: "maybe", reasonCode: secret })]) {
    const outcome = extractProbeOutcome(s, text);
    assert.equal(outcome.status, "unverified");
    assert.equal(outcome.reasonCode, "missing-result-contract");
    assert.doesNotMatch(JSON.stringify(outcome), /secret-credential/);
  }
  assert.deepEqual(
    [extractProbeOutcome(s, `BLOCKED: ${secret}`).status, extractProbeOutcome(s, `BLOCKED: ${secret}`).reasonCode],
    ["blocked", "missing-result-contract"],
  );
  const blocked = extractProbeOutcome(s, JSON.stringify({ result: "blocked", reasonCode: "missing-prerequisite", verdict: secret }));
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.reasonCode, "missing-prerequisite");
  assert.doesNotMatch(JSON.stringify(blocked), /secret-credential/);
  const deniedControl = evidence(s, 403);
  assert.equal(extractProbeOutcome(s, JSON.stringify({ result: "unverified", negativeControl: deniedControl })).reasonCode, "unknown", "a denied negative control may be intentional; only an explicit baseline is checked");
  assert.equal(extractProbeOutcome(s, JSON.stringify({ result: "unverified", unstableResponse: true })).reasonCode, "unstable-response");
  assert.equal(extractProbeOutcome(s, JSON.stringify({ result: "unverified", verdict: "password", reasonCode: secret })).reasonCode, "unknown");
  const invalidBase = evidence(s, 500);
  assert.equal(extractProbeOutcome(s, JSON.stringify({ result: "unverified", baselineEvidenceId: invalidBase })).reasonCode, "invalid-baseline");
});

test("generic probe wrapper propagates evidence-based outcomes into check rows without HTTP", async (t) => {
  const s = session(t);
  await invoke(s, "probe_cors", { url: URL });
  const clean = s.store.checks("a").find((r) => r.tool === "probe_cors")!;
  assert.equal(clean.status, "tested-clean");
  assert.equal(clean.reasonCode, undefined);
  assert.ok(clean.startedAt && clean.finishedAt && Date.parse(clean.startedAt) <= Date.parse(clean.finishedAt));
  assert.equal(clean.evidenceIds.length, 1);
  assert.ok(s.evidence.records.some((r) => r.id === clean.evidenceIds[0]));

  // Same row key, new attempt: a failed baseline must not retain the old clean result.
  s.http.send = async (req) => ({ status: 403, headers: {}, body: "", finalUrl: req.url, durationMs: 1 });
  const retry = await invoke(s, "probe_cors", { url: URL });
  assert.match(retry, /"result":"unverified"/, retry);
  const invalid = s.store.checks("a").find((r) => r.tool === "probe_cors")!;
  assert.equal(invalid.status, "unverified");
  assert.equal(invalid.reasonCode, "invalid-baseline", "the tool named its baseline evidence; HTTP 403, not prose, explains the gap");
});

test("generic probe wrapper persists confirmed and missing-prerequisite tool contracts", async (t) => {
  const s = session(t, 200, "https://evil.verdict-oob.example");
  await invoke(s, "probe_cors", { url: URL });
  const found = s.store.checks("a").find((r) => r.tool === "probe_cors")!;
  assert.equal(found.status, "found");
  assert.equal(found.evidenceIds.length, 3);
  assert.equal(found.reasonCode, undefined);

  await invoke(s, "probe_jwt", { url: URL });
  const blocked = s.store.checks("a").find((r) => r.tool === "probe_jwt")!;
  assert.equal(blocked.status, "blocked");
  assert.equal(blocked.reasonCode, "missing-prerequisite");
});

test("probe_authz's explicit blocked comparison records its invocation start without sending traffic", async (t) => {
  const s = session(t);
  await invoke(s, "probe_authz", { url: URL, objectId: "o-1", ownerRole: "user", compareRole: "user" });
  const row = s.store.checks("a").find((r) => r.tool === "probe_authz")!;
  assert.equal(row.status, "unverified");
  assert.ok(row.startedAt && row.finishedAt && Date.parse(row.startedAt) <= Date.parse(row.finishedAt));
  assert.equal(s.httpProbes, 0);
});

test("probe_cors does not turn a 200 intermediary page into a clean ledger row", async (t) => {
  const s = session(t);
  const intermediaryPages: Array<[string, Record<string, string>]> = [
    ["<title>Burp Suite</title><h1>Error</h1>SOCKS: Host unreachable", {}],
    ["<title>Just a moment...</title>Cloudflare challenge", { "cf-mitigated": "challenge" }],
    ["<form><input type=email><input type=password></form>", { "content-type": "text/html" }],
  ];
  for (const [body, headers] of intermediaryPages) {
    s.http.send = async (req) => ({ status: 200, headers, body, finalUrl: req.url, durationMs: 1 });
    await invoke(s, "probe_cors", { url: URL });
    const row = s.store.checks("a").find((r) => r.tool === "probe_cors")!;
    assert.equal(row.status, "unverified", body);
    assert.equal(row.reasonCode, "invalid-baseline", body);
    assert.equal(row.baselineOk, false, body);
  }
  s.http.send = async (req) => ({
    status: 200, headers: {}, body: "Application help: login and password via proxy are supported.",
    finalUrl: req.url, durationMs: 1,
  });
  await invoke(s, "probe_cors", { url: URL });
  assert.equal(s.store.checks("a").find((r) => r.tool === "probe_cors")?.status, "tested-clean");
});

test("overlapping generic tool invocations retain their own invocation starts in the append-only log", async (t) => {
  const s = session(t);
  let release!: () => void;
  let entered!: () => void;
  const waiting = new Promise<void>((resolve) => { release = resolve; });
  const firstEntered = new Promise<void>((resolve) => { entered = resolve; });
  let firstRequest = true;
  s.http.send = async (req) => {
    if (firstRequest) {
      firstRequest = false;
      entered();
      await waiting;
    }
    return { status: 200, headers: {}, body: "app content", finalUrl: req.url, durationMs: 1 };
  };
  const first = invoke(s, "probe_cors", { url: URL });
  await firstEntered;
  await new Promise<void>((resolve) => setTimeout(resolve, 20));
  await invoke(s, "probe_cors", { url: URL });
  release();
  await first;
  const rows = s.store.loadAssessment("a")!.events
    .filter((e) => e.type === "check_recorded")
    .map((e) => (e.payload as { check: CheckExecution }).check);
  assert.equal(rows.length, 2);
  assert.ok(Date.parse(rows[1]!.startedAt!) < Date.parse(rows[0]!.startedAt!),
    "the first invocation must retain the earlier start despite finishing after the second");
  assert.ok(rows.every((r) => r.startedAt && r.finishedAt && Date.parse(r.startedAt) <= Date.parse(r.finishedAt)));
});
