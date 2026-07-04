import { test } from "node:test";
import assert from "node:assert/strict";

import { hashDomSkeleton } from "./dom.js";

// Pages that are "the same template, only the repeated item count differs" hash the same (= same screen).
// Without this, a blog /post?id=N multiplies into a separate screen per article (the skeleton changes with the comment count).
test("hashDomSkeleton: repeated-sibling run-length is ignored", () => {
  const few = hashDomSkeleton("html>(body>(ul>(li,li,li)))");
  const many = hashDomSkeleton("html>(body>(ul>(li,li,li,li,li,li,li,li)))");
  assert.equal(few, many, "3 vs 8 list items must hash the same");
});

test("hashDomSkeleton: blog posts with different comment/paragraph counts collapse", () => {
  // postId=1: heading + 2 paragraphs + 5 comments
  const p1 = hashDomSkeleton("body>(article>(h1,p,p,section>(cdiv,cdiv,cdiv,cdiv,cdiv)))");
  // postId=2: heading + 3 paragraphs + 1 comment (= only the item count differs)
  const p2 = hashDomSkeleton("body>(article>(h1,p,p,p,section>(cdiv)))");
  assert.equal(p1, p2, "same template, only item counts differ → one screen");
});

// Pages with different structure (child type/order) still hash differently = separate screens (no over-merging).
test("hashDomSkeleton: different child TYPE stays distinct (SPA separation preserved)", () => {
  assert.notEqual(hashDomSkeleton("html>(body>(div))"), hashDomSkeleton("html>(body>(table))"));
});

test("hashDomSkeleton: different sibling ORDER stays distinct", () => {
  assert.notEqual(hashDomSkeleton("x>(a,b)"), hashDomSkeleton("x>(b,a)"));
});

test("hashDomSkeleton: heterogeneous run is not over-collapsed", () => {
  // a,b,a isn't a consecutive run, so it's not collapsed (distinct from a,a,a).
  assert.notEqual(hashDomSkeleton("x>(a,b,a)"), hashDomSkeleton("x>(a)"));
});

// Unexpected/degenerate input still returns hex deterministically without throwing (fail-safe: never stall the crawl).
test("hashDomSkeleton: malformed/degenerate input is safe and deterministic", () => {
  for (const s of ["", "empty", "html>(body", "x>()", ")))", "a,b,c"]) {
    const h = hashDomSkeleton(s);
    assert.match(h, /^[0-9a-f]{16}$/);
    assert.equal(h, hashDomSkeleton(s), "deterministic");
  }
});
