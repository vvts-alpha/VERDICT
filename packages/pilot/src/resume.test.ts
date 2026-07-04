import { test } from "node:test";
import assert from "node:assert/strict";

import { resumeStageState } from "./run.js";

const note = (message: string) => ({ type: "note", payload: { message } });

test("crashed mid-recon (phase1_recon, no methodology, no marker) → survey NOT done", () => {
  const s = resumeStageState({ phase: "phase1_recon", events: [note("🤖 mapping..."), note("+ screen s-0001")] });
  assert.equal(s.surveyDone, false, "resume should restart from recon here (not jump to scan)");
  assert.equal(s.methodologyDone, false);
});

test("survey ended without a survey_done marker but methodology ran → survey done (phase + PLAN)", () => {
  // real data a-mqbm5fn5: phase=report, 80 screens, no survey_done marker
  const s = resumeStageState({ phase: "report", events: [note("📋 PLAN s-0001: test idor on /users/{id}")] });
  assert.equal(s.surveyDone, true);
  assert.equal(s.methodologyDone, true);
});

test("survey-only completion marker → survey done, methodology not yet", () => {
  const s = resumeStageState({ phase: "phase1_recon", events: [note("🗺  SURVEY done (survey-only): 12 screens")] });
  assert.equal(s.surveyDone, true, "a clean survey-only finish counts as done → resume goes to diagnosis");
  assert.equal(s.methodologyDone, false);
});

test("mid-diagnosis crash (phase2_scan) → survey done", () => {
  const s = resumeStageState({ phase: "phase2_scan", events: [] });
  assert.equal(s.surveyDone, true);
});

test("no prior run → nothing done", () => {
  const s = resumeStageState(null);
  assert.deepEqual(s, { surveyDone: false, methodologyDone: false });
});
