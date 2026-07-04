// survey_done auth gate: if roles are configured but no auth session is active, don't let survey close.
// Without it, the model can call survey_done just by emptying the unauthenticated frontier,
// leaving the entire post-login surface un-mapped and silently halving the screen count (the real 60→32 bug).
import { strict as assert } from "node:assert";
import { test } from "node:test";
import { surveyAuthGate } from "./tools.js";

test("gate: roles configured but no active session → refused (the 60→32 anonymous-survey bug)", () => {
  // in attended mode the primary's currentRole is set but cookie/bearer are empty = effectively anonymous → authActive=false
  assert.equal(surveyAuthGate(3, false).ok, false);
  assert.equal(surveyAuthGate(1, false).ok, false);
});

test("gate: roles configured and a session is active → passes", () => {
  // after login() has set a cookie or Bearer
  assert.equal(surveyAuthGate(3, true).ok, true);
});

test("gate: no roles configured (auth-less target) → passes regardless", () => {
  assert.equal(surveyAuthGate(0, false).ok, true);
  assert.equal(surveyAuthGate(0, true).ok, true);
});
