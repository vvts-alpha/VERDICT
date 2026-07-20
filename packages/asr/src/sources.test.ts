// S1 — merge provenance-tagged candidates: dedupe by host, keep the passive-authoritative (crt.sh) primary origin,
// retain an import's liveness hint even when crt.sh is primary.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeCandidates } from "./index.js";

test("mergeCandidates: dedupes by host; crt.sh is the primary origin; the import hint is retained", () => {
    const crt = [
        { host: "a.example.com", source: "crt.sh" as const },
        { host: "b.example.com", source: "crt.sh" as const },
    ];
    const imp = [
        { host: "a.example.com", source: "import" as const, hint: { alive: true, title: "A" } },
        { host: "c.example.com", source: "import" as const, hint: { alive: false } },
    ];
    const merged = mergeCandidates(crt, imp);
    assert.deepEqual(merged.map((c) => c.host), ["a.example.com", "b.example.com", "c.example.com"]);

    const a = merged.find((c) => c.host === "a.example.com")!;
    assert.equal(a.source, "crt.sh", "higher-priority origin wins");
    assert.equal(a.hint?.title, "A", "but the import's liveness hint is retained");

    const c = merged.find((c) => c.host === "c.example.com")!;
    assert.equal(c.source, "import");
    assert.equal(c.hint?.alive, false);
});
