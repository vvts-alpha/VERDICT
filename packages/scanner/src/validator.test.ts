// Evidence-discipline invariant: confirmed = 2 positives + negative control negative. catch-all/unstable → refuted.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import type { Screen } from "@veritas/core";
import { EvidenceStore, FakeHttpClient, makeTarget, runValidator } from "./index.js";
import type { Validator } from "./index.js";

function targetOf(): NonNullable<ReturnType<typeof makeTarget>> {
  const screen: Screen = {
    screenId: "s-0001", urlTemplate: "/", observedUrls: ["https://t.test/"], authState: "unauth",
    screenType: "other", description: "", params: [], apis: [], screenshot: "", domSkeletonHash: "x", labels: [],
  };
  const t = makeTarget(screen);
  assert.ok(t);
  return t;
}

const synthetic: Validator = {
  name: "synthetic",
  severity: "high",
  applicable: () => true,
  probes: () => [{ id: "p", request: { method: "GET", url: "https://t.test/hit" } }],
  negativeControl: () => ({ method: "GET", url: "https://t.test/miss" }),
  evaluate: (res) => ({ positive: res.body.includes("HIT"), reason: res.body.slice(0, 12) }),
  title: () => "synthetic finding",
  describe: () => "synthetic",
};

function withEvidence<T>(fn: (ev: EvidenceStore) => Promise<T>): Promise<T> {
  const dir = mkdtempSync(join(tmpdir(), "veritas-ev-"));
  const ev = new EvidenceStore(dir);
  return fn(ev).finally(() => rmSync(dir, { recursive: true, force: true }));
}

test("confirmed requires negative control + 2 positive replays (3 evidence records)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) =>
      req.url.endsWith("/hit") ? { status: 200, body: "HIT-data" } : { status: 404, body: "" },
    );
    const outcomes = await runValidator(synthetic, targetOf(), http, ev, new Set());
    assert.equal(outcomes.length, 1);
    assert.equal(outcomes[0]?.status, "confirmed");
    assert.equal(outcomes[0]?.evidenceIds.length, 3, "1 negative control + 2 positive replays");
    assert.equal(ev.records.length, 3);
    assert.equal(ev.records.filter((r) => r.kind === "positive_replay").length, 2);
    assert.equal(ev.records.filter((r) => r.kind === "negative_control").length, 1);
    // /hit ×2 + /miss ×1 = 3 requests
    assert.equal(http.sent.length, 3);
  });
});

test("catch-all is refuted: negative control also positive", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(() => ({ status: 200, body: "HIT everywhere" }));
    const outcomes = await runValidator(synthetic, targetOf(), http, ev, new Set());
    assert.equal(outcomes[0]?.status, "refuted");
    assert.match(outcomes[0]?.reason ?? "", /catch-all/);
    assert.equal(ev.records.length, 0, "no evidence recorded for refuted");
  });
});

test("no signal → negative (no finding)", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient(() => ({ status: 404, body: "nope" }));
    const outcomes = await runValidator(synthetic, targetOf(), http, ev, new Set());
    assert.equal(outcomes[0]?.status, "negative");
  });
});

test("unstable positive is refuted", async () => {
  await withEvidence(async (ev) => {
    let hits = 0;
    const http = new FakeHttpClient((req) => {
      if (req.url.endsWith("/hit")) {
        hits += 1;
        return { status: 200, body: hits === 1 ? "HIT" : "flake" };
      }
      return { status: 404, body: "" };
    });
    const outcomes = await runValidator(synthetic, targetOf(), http, ev, new Set());
    assert.equal(outcomes[0]?.status, "refuted");
    assert.match(outcomes[0]?.reason ?? "", /not stable/);
  });
});

test("seen-set dedups identical probes across runs", async () => {
  await withEvidence(async (ev) => {
    const http = new FakeHttpClient((req) => (req.url.endsWith("/hit") ? { status: 200, body: "HIT" } : { status: 404, body: "" }));
    const seen = new Set<string>();
    const first = await runValidator(synthetic, targetOf(), http, ev, seen);
    const second = await runValidator(synthetic, targetOf(), http, ev, seen);
    assert.equal(first.length, 1);
    assert.equal(second.length, 0, "same probe url skipped on the second run");
  });
});
