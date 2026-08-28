import { test } from "node:test";
import assert from "node:assert/strict";
import { FakeLlmClient } from "@veritas/llm";
import { scanJsSinks, analyzeJsSinks, aiRefineSinks } from "./jssinks.js";

// A DOM-XSS: the search route reads location.hash and writes it into innerHTML unsanitized.
const VULN = `function render(){var q=location.hash.split("q=")[1];document.getElementById("out").innerHTML="Results for "+q;}`;
// A benign innerHTML with no taint source near it (framework-style constant write) — should be treated as noise.
const BENIGN = `function init(){el.innerHTML="<span>loading…</span>";return el;}`;
// A high-danger sink with no obvious source — still surfaced (eval is inherently suspicious).
const EVAL = `function run(code){return eval(code);}`;

test("scanJsSinks: innerHTML with a nearby location.hash source is a hit (nearSource set)", () => {
    const hits = scanJsSinks(VULN);
    const h = hits.find((x) => x.sink === "innerHTML");
    assert.ok(h, "innerHTML sink found");
    assert.equal(h?.nearSource, "location.hash");
});

test("scanJsSinks: a source-less innerHTML (framework noise) is dropped", () => {
    const hits = scanJsSinks(BENIGN);
    assert.equal(hits.length, 0, "no candidate without a taint source near a noisy sink");
});

test("scanJsSinks: eval is high-danger and surfaces even without a proven source", () => {
    const hits = scanJsSinks(EVAL);
    assert.ok(hits.some((x) => x.sink === "eval"), "eval surfaced");
});

test("analyzeJsSinks: no LLM → regex-only leads (ai=false), source→sink is medium", async () => {
    const sinks = await analyzeJsSinks(undefined, "https://x/app.js", VULN);
    const s = sinks.find((k) => k.sink === "innerHTML");
    assert.ok(s, "innerHTML lead present");
    assert.equal(s?.ai, false);
    assert.equal(s?.confidence, "medium");
    assert.equal(s?.source, "location.hash");
});

test("aiRefineSinks: the LLM promotes a real candidate and clears a false one", async () => {
    // hit #0 = innerHTML (real), and the model marks it a high candidate with a route hint;
    // any other hit index the model says isCandidate:false is dropped.
    const llm = new FakeLlmClient(
        JSON.stringify({
            candidates: [
                { index: 0, isCandidate: true, source: "location.hash", confidence: "high", rationale: "hash flows into innerHTML unescaped", routeHint: "#/search?q={{XSS}}" },
            ],
        }),
    );
    const hits = scanJsSinks(VULN);
    const sinks = await aiRefineSinks(llm, "https://x/app.js", hits);
    const s = sinks.find((k) => k.sink === "innerHTML");
    assert.ok(s, "candidate kept");
    assert.equal(s?.ai, true);
    assert.equal(s?.confidence, "high");
    assert.equal(s?.routeHint, "#/search?q={{XSS}}");
});

test("aiRefineSinks: malformed model output falls back to the regex leads (never throws)", async () => {
    const llm = new FakeLlmClient("not json at all");
    const hits = scanJsSinks(VULN);
    const sinks = await aiRefineSinks(llm, "https://x/app.js", hits);
    assert.ok(sinks.length > 0, "fell back to regex leads");
    assert.ok(sinks.every((k) => k.ai === false), "fallback leads are marked regex-only");
});
