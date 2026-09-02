// The QA reviewer must see the DISCRIMINATING slice of a large body, not the boilerplate head. evidenceView centers a
// window on the signal (an impact marker, or the first divergence from the control) so the proof stays in frame even
// when it sits 20KB deep — a plain slice(0, N) would only ever show <head>/nav and miss it.
import { test } from "node:test";
import assert from "node:assert/strict";
import { evidenceView } from "./findings-qa.js";

test("evidenceView keeps a marker buried deep in a large body in frame", () => {
  const body = "A".repeat(20000) + "LEAKED_SECRET_ABC123" + "B".repeat(20000);
  const v = evidenceView(body, { marker: "LEAKED_SECRET_ABC123" });
  assert.ok(v.includes("LEAKED_SECRET_ABC123"), "deep marker must be windowed in");
  assert.ok(v.length < 5000, "still bounded, not the whole 40KB");
});

test("evidenceView centers on the first divergence from the control when there is no marker (length-based classes)", () => {
  const control = "X".repeat(10000) + "COMMON_TAIL";
  const positive = "X".repeat(5000) + "DIVERGENCE_POINT_ZZZ" + "X".repeat(5000) + "COMMON_TAIL";
  const v = evidenceView(positive, { control });
  assert.ok(v.includes("DIVERGENCE_POINT_ZZZ"), "the changed region must be windowed in, not the identical head");
});

test("evidenceView returns a small body whole (whitespace-collapsed)", () => {
  assert.equal(evidenceView("small   body\n here"), "small body here");
});

test("evidenceView falls back to head+tail when a big body has no marker and no control", () => {
  const body = "H".repeat(50) + "M".repeat(9000) + "T".repeat(50);
  const v = evidenceView(body);
  assert.ok(v.includes("omitted"), "shows an omission marker for the middle");
  assert.ok(v.length < 3000);
});
