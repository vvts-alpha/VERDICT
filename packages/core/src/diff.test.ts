import { strict as assert } from "node:assert";
import { test } from "node:test";
import { diffStateViews, renderDiffMarkdown } from "./diff.js";
import type { StateView } from "./view.js";
import type { CheckExecution, Finding, Screen, ScreenScan, ScreenScanStatus } from "./types/index.js";

const scr = (id: string, tpl: string): Screen => ({ screenId: id, urlTemplate: tpl }) as unknown as Screen;
const scan = (id: string, status: ScreenScanStatus): ScreenScan => ({ screenId: id, status } as ScreenScan);
const finding = (id: string, title: string, opts: Partial<Finding> = {}): Finding => ({
  id, screenId: opts.screenId ?? "s-a", title, severity: opts.severity ?? "medium",
  anomaly: opts.anomaly ?? "x", source: "agent", description: "", reproSteps: [],
  evidenceIds: [], scopeBasis: "", ...opts,
} as unknown as Finding);
const check = (id: string, cls: string, target: string, status: CheckExecution["status"], role = "user"): CheckExecution =>
  ({ id, checkClass: cls, target, status, role } as unknown as CheckExecution);

function view(id: string, v: Partial<StateView>): StateView {
  return {
    id, phase: "done" as StateView["phase"], target: { kind: "single_url", url: "https://x/" } as StateView["target"],
    budget: {} as StateView["budget"], coverage: {} as StateView["coverage"], tree: [],
    screens: [], screenScans: [], hypotheses: [], findings: [], handoffs: [], jsAssets: [],
    checkExecutions: [], authzObjects: [], authzComparisons: [], roleProgress: [], events: [], ...v,
  } as StateView;
}

test("diffStateViews reports screen adds/removes/status flips and finding deltas", () => {
  const a = view("a-1", {
    screens: [scr("s-1", "/login"), scr("s-2", "/orders/{id}")],
    screenScans: [scan("s-1", "clean"), scan("s-2", "finding")],
    findings: [finding("f-1", "IDOR on orders", { screenId: "s-2", verdict: "confirmed" })],
  });
  const b = view("b-1", {
    screens: [scr("x-1", "/login"), scr("x-3", "/admin")], // different ids, same/diff templates
    screenScans: [scan("x-1", "unverified"), scan("x-3", "clean")],
    findings: [
      finding("f-9", "IDOR on orders", { screenId: "x-3", verdict: "suspected" }),
      finding("f-10", "SSTI on admin", { screenId: "x-3" }),
    ],
  });
  const d = diffStateViews(a, b);
  assert.deepEqual(d.screens.added, ["/admin"]);
  assert.deepEqual(d.screens.removed, ["/orders/{id}"]);
  assert.deepEqual(d.screens.statusChanges, [{ key: "/login", from: "clean", to: "unverified" }]);
  assert.deepEqual(d.findings.added, ["SSTI on admin"]);
  assert.equal(d.findings.resolved.length, 0);
  assert.deepEqual(d.findings.verdictChanges, [{ key: "IDOR on orders", from: "confirmed", to: "suspected" }]);
  assert.ok(d.summary.some((s) => /NEW finding/.test(s)));
});

test("diffStateViews uses dedupKey identity, tracks check/role transitions", () => {
  const a = view("a-1", {
    findings: [finding("f-1", "title-changed-later", { dedupKey: "idor|/o/{id}|id" })],
    checkExecutions: [check("sqli|/q|q|user", "sqli", "/q", "tested-clean"), check("xss|/q|q|user", "xss", "/q", "planned")],
    roleProgress: [{ role: "auditor", state: "blocked", visited: 3, pending: 0, reason: "login denied" } as unknown as StateView["roleProgress"][number]],
  });
  const b = view("b-1", {
    findings: [finding("f-7", "renamed display", { dedupKey: "idor|/o/{id}|id" })], // same dedupKey → same finding
    checkExecutions: [check("sqli|/q|q|user", "sqli", "/q", "found"), check("csrf|/q||user", "csrf", "/q", "tested-clean")],
    roleProgress: [{ role: "auditor", state: "running", visited: 8, pending: 2 } as unknown as StateView["roleProgress"][number]],
  });
  const d = diffStateViews(a, b);
  assert.equal(d.findings.added.length, 0, "dedupKey match → not counted as new");
  assert.equal(d.findings.resolved.length, 0);
  assert.equal(d.checks.added, 1);
  assert.equal(d.checks.removed, 1);
  assert.ok(d.checks.transitions.some((t) => /sqli/.test(t.key) && t.to === "found"));
  assert.equal(d.roles.transitions.length, 1);
  assert.match(d.roles.transitions[0]!.to, /running/);
});

test("renderDiffMarkdown emits sections only when populated", () => {
  const d = diffStateViews(view("a", {}), view("b", {}));
  const md = renderDiffMarkdown(d);
  assert.match(md, /no differences/);
  assert.ok(!/## Findings/.test(md));
});
