import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AssessmentStore, deriveScopeFromSingleUrl } from "@veritas/core";
import { restoreMethodologyPlans } from "./methodology.js";
import { resumeStageState } from "./run.js";
import { buildTools, plannedClassesFor, checkScreenCoverage } from "./tools.js";
import type { PilotSession } from "./tools.js";

const note = (message: string) => ({ type: "note", payload: { message } });
test("legacy plans retain the same coverage gate after resume", () => {
  for (const prefix of ["", "classes="]) {
    const plans = restoreMethodologyPlans([note(`📋 PLAN s-0001: ${prefix}[idor,sqli] verify controls`)]);
    const classes = plannedClassesFor(plans.get("s-0001"));
    assert.deepEqual(classes, ["idor", "sqli"]);
    assert.equal(checkScreenCoverage(classes, [], 0).ok, false);
    assert.equal(checkScreenCoverage(classes, [{ class: "idor", result: "tested-clean" }, { class: "sqli", result: "tested-clean" }], 0).ok, false);
  }
});

test("planning completion requires an explicit marker and a plan for every saved screen", () => {
  const state = { phase: "phase1_label", screens: [{ screenId: "s-0001" }, { screenId: "s-0002" }], events: [note("📋 PLAN s-0001: [idor] check access")] };
  assert.equal(resumeStageState(state).methodologyDone, false);
  state.events.push(note("📋 METHODOLOGY done: partial old run"));
  assert.equal(resumeStageState(state).methodologyDone, false);
  state.events.push(note("📋 PLAN s-0002: [] static page"));
  assert.equal(resumeStageState(state).methodologyDone, true);
});

test("methodology tools persist full plans and refuse premature completion", async () => {
  const dir = mkdtempSync(join(tmpdir(), "verdict-plan-"));
  const store = AssessmentStore.open(join(dir, "state.sqlite"));
  try {
    store.createAssessment({ id: "a-1", target: { kind: "single_url", url: "https://app.test/", followLinks: true, maxDepth: 2 }, scope: deriveScopeFromSingleUrl("https://app.test/") });
    const screens = [{ screenId: "s-0001" }, { screenId: "s-0002" }];
    const session = { store, assessmentId: "a-1", inv: { screens: () => screens }, plans: new Map(), methodologyDone: false } as unknown as PilotSession;
    const invoke = async (name: string, args: unknown) => {
      const tool = buildTools(session).find((t) => t.name === name)!;
      return tool.handler(args as never, {} as never);
    };
    const plan = "Full attack sequence. ".repeat(60);
    await invoke("record_methodology", { screenId: "s-0001", vulnClasses: ["idor", "sqli"], plan });
    await invoke("methodology_done", { summary: "premature" });
    assert.equal(session.methodologyDone, false);
    await invoke("record_methodology", { screenId: "s-0002", vulnClasses: [], plan: "static" });
    await invoke("methodology_done", { summary: "complete" });
    assert.equal(session.methodologyDone, true);
    const events = store.loadAssessment("a-1")!.events;
    const restored = restoreMethodologyPlans(events);
    assert.equal(restored.get("s-0001"), `classes=[idor,sqli] ${plan}`);
    assert.deepEqual(restored, session.plans);
    assert.equal(resumeStageState({ phase: "phase1_label", screens, events }).methodologyDone, true);
    assert.equal(events.filter((e) => e.type === "methodology_completed").length, 1);
  } finally { store.close(); rmSync(dir, { recursive: true, force: true }); }
});
