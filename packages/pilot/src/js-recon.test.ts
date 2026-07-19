// analyzePageJs: the first-party JS recon core (used by the analyze_js tool AND the deterministic post-survey pass).
// Fakes the http client; uses a real store + InventoryBuilder to assert it enrolls a discovered endpoint, flags a secret,
// records a js_analyzed event, and dedups by URL.

import { strict as assert } from "node:assert";
import { test } from "node:test";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzePageJs } from "./tools.js";
import type { PilotSession } from "./tools.js";
import { InventoryBuilder } from "@veritas/crawler";
import { AssessmentStore, deriveScopeFromSingleUrl, defaultBudget } from "@veritas/core";

const BASE = "https://app.test/";
const RESPONSES: Record<string, { status: number; body: string; ct?: string }> = {
  "https://app.test/": { status: 200, ct: "text/html", body: '<html><head><script src="/static/main.js"></script><script src="https://cdn.other.test/jquery.min.js"></script></head></html>' },
  // first-party bundle: a hidden admin endpoint + a hardcoded Google API key
  "https://app.test/static/main.js": { status: 200, ct: "application/javascript", body: 'const api=()=>fetch("/api/admin/secrets");const KEY="AIzaSyAifmNrsDrUE-nYVrnETY1QAg8NeioXQh4";' },
};

function fakeSession(store: AssessmentStore, id: string): PilotSession {
  const http = {
    send: async (req: { url: string }) => {
      const r = RESPONSES[req.url] ?? { status: 404, body: "nf" };
      return { status: r.status, finalUrl: req.url, durationMs: 1, headers: { "content-type": r.ct ?? "text/plain" }, body: r.body };
    },
  };
  return {
    http,
    store,
    assessmentId: id,
    scope: deriveScopeFromSingleUrl(BASE),
    targetUrl: BASE,
    inv: new InventoryBuilder(),
    currentCookie: "",
    currentBearer: "",
    httpProbes: 0,
    screenProbes: 0,
    httpAuthWall: 0,
    httpThrough: 0,
  } as unknown as PilotSession;
}

test("analyzePageJs: mines a first-party bundle → enrolls endpoint, flags secret, records + dedups; skips third-party CDN", async () => {
  const dir = mkdtempSync(join(tmpdir(), "veritas-jsrecon-"));
  try {
    const store = AssessmentStore.open(join(dir, "state.sqlite"));
    const { id } = store.createAssessment({
      target: { kind: "single_url", url: BASE, followLinks: true, maxDepth: 2 },
      scope: deriveScopeFromSingleUrl(BASE),
      budget: defaultBudget(),
    });
    const session = fakeSession(store, id);

    const res = await analyzePageJs(session, BASE);
    // the third-party cdn.other.test/jquery.min.js is out of scope → not analyzed; only the first-party bundle is
    assert.equal(res.analyzed, 1, "only the first-party bundle analyzed (CDN lib skipped by the scope gate)");
    assert.equal(res.endpointsEnrolled, 1, "the hidden /api/admin/secrets endpoint enrolled");
    assert.ok(res.secretsFound >= 1, "the Google API key flagged");
    assert.ok(session.inv.screens().some((sc) => sc.urlTemplate === "/api/admin/secrets"), "enrolled screen is in the diagnosable inventory");
    assert.ok(store.analyzedJsUrls(id).has("https://app.test/static/main.js"), "recorded for dedup");

    // second run is a no-op: the bundle is already recorded (dedup)
    const again = await analyzePageJs(fakeSession(store, id), BASE);
    assert.equal(again.analyzed, 0, "already-analyzed bundle skipped on re-run");
    store.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
