// screen_done coverage gate: structurally forbids "find one and stop".
// Every planned attack class must be accounted for in coverage, and claiming tested-clean requires at least one probe.
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { plannedClassesFor, checkScreenCoverage } from "./tools.js";

test("plannedClassesFor parses the classes=[...] prefix and canonicalizes", () => {
  assert.deepEqual(
    plannedClassesFor("classes=[IDOR/BOLA,SQL-injection,stored-XSS] 1. test ... 2. ...").sort(),
    ["idor", "sqli", "xss-stored"].sort(),
  );
  // info-disclosure / headers / free-text other are exempt from coverage enforcement
  assert.deepEqual(plannedClassesFor("classes=[info-disclosure,headers] ..."), []);
  assert.deepEqual(plannedClassesFor("(no recorded plan — use judgement)"), []);
  assert.deepEqual(plannedClassesFor(undefined), []);
});

test("gate: a plan class with no coverage entry is rejected (the core 'find-one-move-on' fix)", () => {
  const planned = ["idor", "sqli", "xss-stored"];
  // find only SQLi and immediately done → remaining idor/xss-stored unaccounted → rejected
  const g = checkScreenCoverage(planned, [{ class: "sqli", result: "found" }], 5);
  assert.equal(g.ok, false);
  if (!g.ok) {
    assert.match(g.reason, /idor/);
    assert.match(g.reason, /xss-stored/);
  }
});

test("gate: every planned class accounted for → passes", () => {
  const planned = ["idor", "sqli"];
  const g = checkScreenCoverage(
    planned,
    [
      { class: "sqli", result: "found" },
      { class: "idor", result: "tested-clean" },
    ],
    7,
  );
  assert.equal(g.ok, true);
});

test("gate: claims tested but fired zero probes → rejected (anti self-report)", () => {
  const planned = ["idor"];
  const g = checkScreenCoverage(planned, [{ class: "idor", result: "tested-clean" }], 0);
  assert.equal(g.ok, false);
  if (!g.ok) assert.match(g.reason, /no probe/i);
});

test("gate: a 'suspected' coverage result accounts for the class AND counts as actually-tested", () => {
  const planned = ["idor", "ssti"];
  // 'suspected' satisfies planned and also counts on the claimsTested side (= requires at least 1 probe).
  const ok = checkScreenCoverage(planned, [{ class: "idor", result: "suspected" }, { class: "ssti", result: "tested-clean" }], 4);
  assert.equal(ok.ok, true);
  const noProbe = checkScreenCoverage(["idor"], [{ class: "idor", result: "suspected" }], 0);
  assert.equal(noProbe.ok, false); // if you claim suspected you must have fired a probe
  if (!noProbe.ok) assert.match(noProbe.reason, /no probe/i);
});

test("gate: not-applicable counts as accounted (escape hatch), and no-plan screens pass freely", () => {
  // all not-applicable can close with 0 probes (a legitimate close for a non-applicable screen)
  assert.deepEqual(checkScreenCoverage(["csrf"], [{ class: "csrf", result: "not-applicable" }], 0), { ok: true });
  // screens with no classes in the plan are exempt from the gate
  assert.deepEqual(checkScreenCoverage([], [], 0), { ok: true });
});
