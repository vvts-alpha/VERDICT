// S1 — merge provenance-tagged candidates: dedupe by host, keep the passive-authoritative (crt.sh) primary origin,
// retain an import's liveness hint even when crt.sh is primary.

import { test } from "node:test";
import assert from "node:assert/strict";
import { mergeCandidates, probePriority, orderCandidatesForProbe } from "./index.js";

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

test("probePriority: named/shallow hosts rank ahead of deep ephemeral ones; dictionary labels not penalized", () => {
    // real shapes from the *.sophos.com run: a named host must beat a CT-log ephemeral cloud host
    assert.ok(probePriority("portal.sophos.com") < probePriority("1jwqo068-cloudhub-eu-west-1.qa.hydra.sophos.com"));
    assert.ok(probePriority("api.sophos.com") < probePriority("2f91ghz5.cloudstation.eu-west-1.inf.hydra.sophos.com"));
    // dictionary subdomains (dev/qa) at normal depth are NOT penalized (same floor as any other 3-label host)
    assert.equal(probePriority("dev.example.com"), 0);
    assert.equal(probePriority("qa.example.com"), probePriority("www.example.com"));
});

test("orderCandidatesForProbe: keeps every candidate; named hosts move to the front", () => {
    const cands = [
        { host: "1blpn5y1.cloudstation.us-west-2.qa.hydra.sophos.com", source: "crt.sh" as const },
        { host: "portal.sophos.com", source: "active" as const },
        { host: "api.sophos.com", source: "active" as const },
        { host: "16b9zslm.cloudhub.eu-central-1.qa.hydra.sophos.com", source: "crt.sh" as const },
    ];
    const ordered = orderCandidatesForProbe(cands);
    assert.equal(ordered.length, cands.length, "no candidate dropped");
    assert.deepEqual(ordered.slice(0, 2).map((c) => c.host), ["api.sophos.com", "portal.sophos.com"], "named hosts first (then alphabetical)");
});
