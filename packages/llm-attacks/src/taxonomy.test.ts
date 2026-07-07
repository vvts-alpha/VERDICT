import { test } from "node:test";
import assert from "node:assert/strict";

import { LLM_CATEGORIES, OWASP_LLM_2025 } from "./index.js";

test("every category maps to an OWASP LLM 2025 entry", () => {
  for (const cat of LLM_CATEGORIES) {
    const ref = OWASP_LLM_2025[cat];
    assert.ok(ref, `missing OWASP ref for ${cat}`);
    assert.match(ref.id, /^LLM(0[1-9]|10)$/);
    assert.ok(ref.title.length > 0);
  }
});

test("taxonomy covers ten distinct red-team categories", () => {
  assert.equal(LLM_CATEGORIES.length, 10);
  assert.equal(new Set(LLM_CATEGORIES).size, 10);
});
