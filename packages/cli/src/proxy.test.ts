import { strict as assert } from "node:assert";
import { test } from "node:test";
import { resolveUpstreamProxy, proxyFlagGivenButEmpty, type OptValueFlag } from "./proxy.js";

const OFF: OptValueFlag = { present: false };
const BARE: OptValueFlag = { present: true };
const val = (value: string): OptValueFlag => ({ present: true, value });

test("opt-in invariant: no flag + no manifest = undefined even when both proxy envs are set", () => {
    // The critical byte-identical-when-off guarantee: env alone must NEVER activate the proxy.
    const r = resolveUpstreamProxy({
        proxyFlag: OFF,
        burpFlag: OFF,
        env: { VERDICT_PROXY: "http://env-verdict:8080", BURP_PROXY: "http://env-burp:8080" },
    });
    assert.equal(r, undefined);
});

test("manifest proxy activates the proxy with no flag (explicit operator config)", () => {
    const r = resolveUpstreamProxy({ proxyFlag: OFF, burpFlag: OFF, manifestProxy: "http://mani:8080" });
    assert.equal(r, "http://mani:8080");
});

test("--proxy <url> wins over everything (burp flag, manifest, env)", () => {
    const r = resolveUpstreamProxy({
        proxyFlag: val("http://cli:8080"),
        burpFlag: val("http://burp:8080"),
        manifestProxy: "http://mani:8080",
        env: { VERDICT_PROXY: "http://env-verdict:8080", BURP_PROXY: "http://env-burp:8080" },
    });
    assert.equal(r, "http://cli:8080");
});

test("bare --proxy reads VERDICT_PROXY, then falls back to BURP_PROXY", () => {
    assert.equal(
        resolveUpstreamProxy({ proxyFlag: BARE, burpFlag: OFF, env: { VERDICT_PROXY: "http://v:8080", BURP_PROXY: "http://b:8080" } }),
        "http://v:8080",
    );
    assert.equal(
        resolveUpstreamProxy({ proxyFlag: BARE, burpFlag: OFF, env: { BURP_PROXY: "http://b:8080" } }),
        "http://b:8080",
    );
});

test("--burp-proxy is the compat alias: value used; bare reads BURP_PROXY only (not VERDICT_PROXY)", () => {
    assert.equal(resolveUpstreamProxy({ proxyFlag: OFF, burpFlag: val("http://burp:8080") }), "http://burp:8080");
    assert.equal(resolveUpstreamProxy({ proxyFlag: OFF, burpFlag: BARE, env: { BURP_PROXY: "http://b:8080" } }), "http://b:8080");
    // bare --burp-proxy must NOT pick up VERDICT_PROXY (compat exactness) → nothing resolves
    assert.equal(resolveUpstreamProxy({ proxyFlag: OFF, burpFlag: BARE, env: { VERDICT_PROXY: "http://v:8080" } }), undefined);
});

test("--proxy takes precedence over --burp-proxy when both are given", () => {
    assert.equal(
        resolveUpstreamProxy({ proxyFlag: val("http://cli:8080"), burpFlag: val("http://burp:8080") }),
        "http://cli:8080",
    );
});

test("bare --proxy with no env falls through to the manifest proxy", () => {
    const r = resolveUpstreamProxy({ proxyFlag: BARE, burpFlag: OFF, manifestProxy: "http://mani:8080", env: {} });
    assert.equal(r, "http://mani:8080");
});

test("proxyFlagGivenButEmpty: true only when a flag was given AND nothing resolved", () => {
    // flag present, resolved to nothing → warn
    assert.equal(proxyFlagGivenButEmpty(BARE, OFF, undefined), true);
    assert.equal(proxyFlagGivenButEmpty(OFF, BARE, undefined), true);
    // flag present but the manifest supplied a proxy → no warning (it IS using one)
    assert.equal(proxyFlagGivenButEmpty(BARE, OFF, "http://mani:8080"), false);
    // no flag at all → never warn (even though nothing resolved)
    assert.equal(proxyFlagGivenButEmpty(OFF, OFF, undefined), false);
});
