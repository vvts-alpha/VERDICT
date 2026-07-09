import { test } from "node:test";
import assert from "node:assert/strict";

import { FakeLlmClient } from "@veritas/llm";

import { triageAsset, buildTriagePrompt } from "./index.js";
import type { Asset } from "@veritas/core";

const mk = (o: Partial<Asset>): Asset => ({
    host: "admin.example.com",
    source: "crt.sh",
    resolved: ["1.2.3.4"],
    alive: true,
    scheme: "https",
    status: 200,
    title: "Admin Login",
    tech: ["nginx"],
    screenshot: null,
    inScope: true,
    score: { total: 44, band: "medium", components: { sensitivity: 34, exposure: 10, weakness: 0, breadth: 0, anomaly: 0 }, autoEscalate: [] },
    ...o,
});

test("triageAsset: parses a JSON triage; the host bundle reaches the model", async () => {
    const llm = new FakeLlmClient('{"category":"admin","band":"high","rationale":"exposed admin login","angle":"try default creds / auth bypass"}');
    const t = await triageAsset(mk({}), llm);
    assert.equal(t?.category, "admin");
    assert.equal(t?.band, "high");
    assert.match(t?.angle ?? "", /default creds/);
    assert.match(llm.calls[0]?.prompt ?? "", /admin\.example\.com/);
});

test("triageAsset: tolerates a fenced ```json block", async () => {
    const llm = new FakeLlmClient('```json\n{"category":"api","band":"low","rationale":"x","angle":""}\n```');
    assert.equal((await triageAsset(mk({}), llm))?.category, "api");
});

test("triageAsset: an invalid band coerces to the deterministic band; non-JSON → null", async () => {
    const good = new FakeLlmClient('{"category":"x","band":"NONSENSE","rationale":"r","angle":"a"}');
    assert.equal((await triageAsset(mk({}), good))?.band, "medium"); // falls back to score.band
    const bad = new FakeLlmClient("sorry, I can't help with that");
    assert.equal(await triageAsset(mk({}), bad), null);
});

test("buildTriagePrompt: includes the deterministic score + notable paths", () => {
    const p = buildTriagePrompt(mk({ notablePaths: [{ path: "/.git/HEAD", status: 200, note: "readable .git", escalate: true }] }));
    assert.match(p, /\.git\/HEAD/);
    assert.match(p, /deterministic score: 44/);
});
