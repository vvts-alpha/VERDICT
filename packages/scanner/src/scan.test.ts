// 実 validator(exposed_file / auth_required / cors)+ scanInventory の store 連携を FakeHttpClient で検証。

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
  const s = screen({ apis: [cookieApi] });
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
    // 各 finding は negative control + 2 positive = 3 証拠
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
    // 全パスが 200 + git config 風 body(0-byte ガードは通るが negative control も陽性 → catch-all)
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
      // Origin が来たらそのまま反映(脆弱)。来なければ反映しない。
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
