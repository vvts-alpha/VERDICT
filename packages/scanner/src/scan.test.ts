// Verify the real validators (exposed_file / auth_required / cors) + scanInventory's store integration with FakeHttpClient.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { AssessmentStore, coverage, deriveScopeFromSingleUrl } from "@veritas/core";
import type { ApiCall, Screen } from "@veritas/core";
import { EvidenceStore, FakeHttpClient, scanInventory, scanScreen } from "./index.js";
import type { FakeResponder } from "./index.js";

function screen(over: Partial<Screen> = {}): Screen {
  return {
    screenId: over.screenId ?? "s-0001",
    urlTemplate: over.urlTemplate ?? "/products/{id}",
    observedUrls: over.observedUrls ?? ["https://shop.test/products/1"],
    authState: "unauth",
    screenType: over.screenType ?? "detail",
    description: "",
    params: over.params ?? [{ name: "id", in: "path", example: "1", guessedType: "object_ref" }],
    apis: over.apis ?? [],
    screenshot: "",
    domSkeletonHash: over.screenId ?? "s-0001",
    labels: [],
  };
}

const cookieApi: ApiCall = { method: "GET", urlTemplate: "/api/products/{id}", auth: "cookie", reqSchema: null, resSchema: null };
const bearerApi: ApiCall = { method: "GET", urlTemplate: "/api/products/{id}", auth: "bearer", reqSchema: null, resSchema: null };

function byPath(routes: Record<string, () => { status: number; body?: string; headers?: Record<string, string> }>): FakeResponder {
  return (req) => {
    const path = new URL(req.url).pathname;
    const handler = routes[path];
    return handler ? handler() : { status: 404, body: "not found" };
  };
}

function freshEvidence(): { ev: EvidenceStore; dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "veritas-scan-"));
  return { ev: new EvidenceStore(join(dir, "artifacts")), dir };
}

test("exposed_file + auth_required confirm and land in the store + coverage ledger", async () => {
  const { ev, dir } = freshEvidence();
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  store.createAssessment({
    id: "a-1",
    target: { kind: "single_url", url: "https://shop.test/", followLinks: true, maxDepth: 2 },
    scope: deriveScopeFromSingleUrl("https://shop.test/"),
  });
  const s = screen({ apis: [bearerApi] }); // Bearer API returning data unauth = a real auth_required bypass (cookie APIs are excluded — cookies auto-send)
  store.upsertScreen("a-1", s);

  const http = new FakeHttpClient(
    byPath({
      "/.git/config": () => ({ status: 200, body: "[core]\n\trepositoryformatversion = 0\n" }),
      "/api/products/1": () => ({ status: 200, body: '{"id":1,"name":"Widget","secret":"s3cr3t-token"}' }),
    }),
  );

  try {
    const result = await scanInventory(store.loadAssessment("a-1")!.screens, http, ev, { store, assessmentId: "a-1" });
    assert.equal(result.confirmed, 2, "exposed_file(git-config) + auth_required(api)");

    const state = store.loadAssessment("a-1");
    assert.ok(state);
    assert.equal(state.phase, "phase2_scan");
    assert.equal(state.findings.length, 2);
    assert.ok(state.findings.some((f) => f.source.kind === "validator" && f.source.validatorName === "exposed_file"));
    assert.ok(state.findings.some((f) => f.title.includes("Unauthenticated access")));
    // each finding = negative control + 2 positives = 3 evidence records
    for (const f of state.findings) assert.equal(f.evidenceIds.length, 3);

    const scan = state.screenScans.find((x) => x.screenId === "s-0001");
    assert.equal(scan?.status, "finding");
    assert.equal(coverage(state).byStatus.finding, 1);
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("0-byte 200 does not count (guard)", async () => {
  const { ev, dir } = freshEvidence();
  try {
    const http = new FakeHttpClient(byPath({ "/.git/config": () => ({ status: 200, body: "" }) }));
    const r = await scanScreen(screen(), http, ev, new Set());
    assert.equal(r.findings.length, 0);
    assert.ok(r.outcomes.find((o) => o.validator === "exposed_file" && o.probeId === "git-config")?.status === "negative");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("catch-all server is refuted, not confirmed", async () => {
  const { ev, dir } = freshEvidence();
  try {
    // every path returns 200 + git-config-like body (passes the 0-byte guard, but the negative control is also positive → catch-all)
    const http = new FakeHttpClient(() => ({ status: 200, body: "[core]\n\trepositoryformatversion = 0\n" }));
    const r = await scanScreen(screen(), http, ev, new Set());
    const git = r.outcomes.find((o) => o.validator === "exposed_file" && o.probeId === "git-config");
    assert.equal(git?.status, "refuted");
    assert.equal(r.findings.length, 0);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("cors_misconfig confirms only when an arbitrary Origin is reflected", async () => {
  const { ev, dir } = freshEvidence();
  try {
    const http = new FakeHttpClient((req) => {
      if (new URL(req.url).pathname !== "/api/products/1") return { status: 404, body: "" };
      const origin = req.headers?.["origin"];
      // If an Origin arrives, reflect it as-is (vulnerable). If not, don't reflect.
      return origin
        ? { status: 200, body: "{}", headers: { "access-control-allow-origin": origin, "access-control-allow-credentials": "true" } }
        : { status: 200, body: "{}" };
    });
    const r = await scanScreen(screen({ apis: [cookieApi] }), http, ev, new Set());
    const cors = r.outcomes.find((o) => o.validator === "cors_misconfig");
    assert.equal(cors?.status, "confirmed");
    assert.ok(r.findings.some((f) => f.title.startsWith("CORS")));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// A1: auth_required is BEARER-only. A cookie is auto-sent by the browser to every same-origin request, so detectAuth
// labels public GETs as auth:"cookie" — probing those unauthenticated yields a 200 and a false "unauthenticated access".
test("auth_required is BEARER-only: a cookie-authed API returning data unauth is NOT flagged", async () => {
  const { ev, dir } = freshEvidence();
  try {
    const http = new FakeHttpClient(byPath({ "/api/products/1": () => ({ status: 200, body: '{"id":1,"name":"Widget","price":9}' }) }));
    const cookieRun = await scanScreen(screen({ apis: [cookieApi] }), http, ev, new Set());
    assert.ok(!cookieRun.outcomes.some((o) => o.validator === "auth_required"), "cookie API is not an auth_required target (would be a false positive)");
    const bearerRun = await scanScreen(screen({ apis: [bearerApi] }), http, ev, new Set());
    assert.ok(bearerRun.outcomes.some((o) => o.validator === "auth_required" && o.status === "confirmed"), "the same endpoint as a Bearer API returning data unauth IS a real bypass");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
