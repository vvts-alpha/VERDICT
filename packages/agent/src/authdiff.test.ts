import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Screen } from "@veritas/core";
import { EvidenceStore, FakeHttpClient } from "@veritas/scanner";
import { authDiffScreen } from "./index.js";

function screen(): Screen {
  return {
    screenId: "s-0001", urlTemplate: "/orders/{id}", observedUrls: ["https://shop.test/orders/5"], authState: "post-login",
    screenType: "detail", description: "", params: [{ name: "id", in: "path", example: "5", guessedType: "object_ref" }],
    apis: [{ method: "GET", urlTemplate: "/api/orders/{id}", auth: "cookie", reqSchema: null, resSchema: null }],
    screenshot: "", domSkeletonHash: "x", labels: [],
  };
}

const HIGH = { name: "admin", headers: { cookie: "role=admin" } };
const LOW = { name: "user", headers: { cookie: "role=user" } };

function withEvidence<T>(fn: (ev: EvidenceStore) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-ad-"));
  return fn(new EvidenceStore(join(dir, "artifacts"))).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("authDiff confirms when low-priv role gets identical data (boundary crossed)", async () => {
  await withEvidence(async (ev) => {
    // Every role returns the same entity = no authorization boundary
    const http = new FakeHttpClient(() => ({ status: 200, body: '{"order":5,"owner":"victim","total":99}' }));
    const outcome = await authDiffScreen(screen(), http, ev, HIGH, LOW);
    assert.equal(outcome.status, "confirmed");
    assert.equal(outcome.evidenceIds.length, 3, "high baseline + 2 low replays");
  });
});

// A self-scoped endpoint (/api/me, /api/orders) returns a 200 to BOTH roles but DIFFERENT data (each caller its own).
// That is NOT a boundary crossing. Before the body-match requirement this fabricated a HIGH "boundary crossed" finding on
// every such endpoint (the deterministic over-confirm the audit flagged).
test("authDiff refutes a self-scoped endpoint (each role its OWN data, not a crossing)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) =>
      (req.headers?.["cookie"] ?? "").includes("admin")
        ? { status: 200, body: '{"order":5,"owner":"admin","total":500}' }
        : { status: 200, body: '{"order":9,"owner":"user","total":12}' },
    );
    const outcome = await authDiffScreen(screen(), http, ev, HIGH, LOW);
    assert.equal(outcome.status, "refuted", "different content per role = self-scoped, not a boundary crossing");
  });
});

test("authDiff refutes when low-priv role is blocked", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) =>
      (req.headers?.["cookie"] ?? "").includes("admin")
        ? { status: 200, body: '{"order":5,"owner":"victim"}' }
        : { status: 403, body: "forbidden" },
    );
    const outcome = await authDiffScreen(screen(), http, ev, HIGH, LOW);
    assert.equal(outcome.status, "refuted");
  });
});

function pageScreen(): Screen {
  return {
    screenId: "s-0002", urlTemplate: "/orders/{id}", observedUrls: ["https://shop.test/orders/12"], authState: "post-login",
    screenType: "detail", description: "", params: [{ name: "id", in: "path", example: "12", guessedType: "object_ref" }],
    apis: [], screenshot: "", domSkeletonHash: "x", labels: [],
  };
}

test("authDiff confirms on a post-login PAGE (no API) when low-priv can access it (P2)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(() => ({ status: 200, body: "<h1>Order 12</h1><p>total 99</p>" }));
    const outcome = await authDiffScreen(pageScreen(), http, ev, HIGH, LOW);
    assert.equal(outcome.status, "confirmed");
    assert.equal(outcome.evidenceIds.length, 3);
  });
});

test("authDiff refutes a page when low-priv gets a login wall", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) =>
      (req.headers?.["cookie"] ?? "").includes("admin")
        ? { status: 200, body: "<h1>Order 12</h1>" }
        : { status: 200, body: "<form>Please log in to continue</form>" },
    );
    const outcome = await authDiffScreen(pageScreen(), http, ev, HIGH, LOW);
    assert.equal(outcome.status, "refuted");
  });
});
