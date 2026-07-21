import { test } from "node:test";
import assert from "node:assert/strict";

import { crtShUrl, parseCrtSh, discoverCrtSh, filterInScope, primarySourceFailureAction } from "./index.js";

// A crt.sh (primary-source) outage must DEGRADE the map but keep a run other sources populated — aborting only when
// the whole result is empty. This locks the corrected policy after an over-strict version discarded a 2564-host run.
test("primarySourceFailureAction: crt.sh outage degrades but keeps a populated run; aborts only when empty", () => {
    // primary healthy → nothing special.
    assert.deepEqual(primarySourceFailureAction({ primaryFailed: false, otherHostCount: 0, allowDegraded: false }), { degraded: false, abort: false });
    // primary failed but subfinder/import/brute found hosts → DEGRADE + KEEP (the 2564-host case). No abort.
    assert.deepEqual(primarySourceFailureAction({ primaryFailed: true, otherHostCount: 2564, allowDegraded: false }), { degraded: true, abort: false });
    // primary failed AND nothing else found → abort (the genuine "it didn't work").
    assert.deepEqual(primarySourceFailureAction({ primaryFailed: true, otherHostCount: 0, allowDegraded: false }), { degraded: true, abort: true });
    // --allow-degraded accepts even an empty result → no abort.
    assert.deepEqual(primarySourceFailureAction({ primaryFailed: true, otherHostCount: 0, allowDegraded: true }), { degraded: true, abort: false });
});

// filterInScope is the ONE scope filter every source (crt.sh, import, brute) funnels through (S1). Lock its admission rules.
test("filterInScope: admits apex + subdomains, strips *., drops carve-outs / foreign / invalid", () => {
    const scope = { domain: "example.com", outOfScope: ["secret.example.com"] };
    assert.deepEqual(
        filterInScope(
            ["example.com", "api.example.com", "*.cdn.example.com", "secret.example.com", "sub.secret.example.com", "evil.com", "a.example.com.evil.com", "not_a_host"],
            scope,
        ),
        ["api.example.com", "cdn.example.com", "example.com"],
    );
});

const ROWS = [
    { name_value: "*.example.com\nexample.com", common_name: "example.com" },
    { name_value: "www.example.com\napi.example.com" },
    { name_value: "admin.staging.example.com", common_name: "admin.staging.example.com" },
    { name_value: "blog.example.com" }, // a carve-out in the test below
    { name_value: "evil.com\nnot-example.com.attacker.net" }, // foreign domains
    { common_name: "*.dev.example.com" }, // wildcard -> dev.example.com
];

test("parseCrtSh: keeps in-scope hosts, strips wildcards, dedups, drops foreign domains + carve-outs", () => {
    const hosts = parseCrtSh(ROWS, { domain: "*.example.com", outOfScope: ["blog.example.com"] });
    assert.deepEqual(hosts, [
        "admin.staging.example.com",
        "api.example.com",
        "dev.example.com",
        "example.com",
        "www.example.com",
    ]);
    assert.ok(!hosts.includes("blog.example.com"), "carve-out excluded");
    assert.ok(!hosts.some((h) => h.includes("attacker") || h === "evil.com"), "foreign domains excluded");
});

test("parseCrtSh: a carve-out also excludes its subdomains", () => {
    const hosts = parseCrtSh([{ name_value: "x.blog.example.com\nblog.example.com\nkeep.example.com" }], {
        domain: "example.com",
        outOfScope: ["blog.example.com"],
    });
    assert.deepEqual(hosts, ["keep.example.com"]);
});

test("crtShUrl: url-encodes the CT wildcard search and normalizes a wildcard apex", () => {
    assert.equal(crtShUrl("*.example.com"), "https://crt.sh/?q=%25.example.com&output=json");
});

test("discoverCrtSh: parses an injected crt.sh JSON body (offline)", async () => {
    const fakeGet = async (url: string): Promise<string> => {
        assert.match(url, /crt\.sh/);
        assert.match(url, /%25\.example\.com/); // url-encoded "%.example.com"
        return JSON.stringify([{ name_value: "a.example.com\nb.example.com" }]);
    };
    const hosts = await discoverCrtSh({ domain: "example.com" }, fakeGet);
    assert.deepEqual(hosts, ["a.example.com", "b.example.com"]);
});

test("discoverCrtSh: returns [] on a non-JSON body (crt.sh rate-limit HTML)", async () => {
    const hosts = await discoverCrtSh({ domain: "example.com" }, async () => "<html>rate limited</html>");
    assert.deepEqual(hosts, []);
});

test("discoverCrtSh: retries a transient crt.sh failure (502) then succeeds", async () => {
    let calls = 0;
    const flaky = async (): Promise<string> => {
        calls += 1;
        if (calls < 3) throw new Error("crt.sh returned HTTP 502");
        return JSON.stringify([{ name_value: "a.example.com" }]);
    };
    const hosts = await discoverCrtSh({ domain: "example.com" }, flaky, { attempts: 3, backoffMs: 0 });
    assert.equal(calls, 3);
    assert.deepEqual(hosts, ["a.example.com"]);
});

test("discoverCrtSh: throws the last error when every attempt fails", async () => {
    await assert.rejects(
        discoverCrtSh({ domain: "example.com" }, async () => {
            throw new Error("crt.sh 503");
        }, { attempts: 2, backoffMs: 0 }),
        /503/,
    );
});

test("discoverCrtSh: a CONNECTION failure (fetch failed = unreachable) fails FAST — no retry/backoff", async () => {
    let calls = 0;
    await assert.rejects(
        discoverCrtSh({ domain: "example.com" }, async () => {
            calls++;
            throw new TypeError("fetch failed"); // node fetch's connection-failure error
        }, { attempts: 3, backoffMs: 9999 }), // big backoff: if it retried, the test would hang — it must NOT
        /fetch failed/,
    );
    assert.equal(calls, 1, "an unreachable crt.sh must not be retried (retrying won't help + wastes ~12s of backoff)");
});

test("discoverCrtSh: a 502 IS still retried (transient server error)", async () => {
    let calls = 0;
    const hosts = await discoverCrtSh(
        { domain: "example.com" },
        async () => {
            calls++;
            if (calls < 2) throw new Error("crt.sh returned HTTP 502");
            return JSON.stringify([{ name_value: "a.example.com" }]);
        },
        { attempts: 3, backoffMs: 0 },
    );
    assert.deepEqual(hosts, ["a.example.com"]);
    assert.equal(calls, 2);
});
