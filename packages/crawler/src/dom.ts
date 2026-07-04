// DESIGN §6.4 — DOM skeleton hash (part of the dedup key that separates SPA "same URL but different screen").

import { createHash } from "node:crypto";

/** At each level of the skeleton string, collapse "consecutive identical sibling subtrees" to one.
 *  This makes pages that are "the same template, only the item count differs" (blog posts /post?id=N,
 *  product catalogs, comment lists, table rows) hash the same, preventing them from multiplying into a
 *  separate screen per item (also stops self-duplication where revisiting the same URL grows the comments → a different hash).
 *  It preserves the child *type* and *order* and drops only the repetition *length*, so structurally
 *  different screens (a row of divs vs a table, a form vs an article) still hash differently.
 *  walk() grammar: node := tag [ ">(" node {"," node} ")" ]. tag never contains > ( ) , . */
function collapseSkeletonRuns(s: string): string {
  let i = 0;
  const parseNode = (): string => {
    let tag = "";
    while (i < s.length) {
      const c = s[i]!;
      if (c === ">" || c === "(" || c === ")" || c === ",") break;
      tag += c;
      i += 1;
    }
    if (s[i] === ">" && s[i + 1] === "(") {
      i += 2; // skip ">("
      const kids: string[] = [];
      let prev: string | null = null;
      if (s[i] !== ")") {
        for (;;) {
          const k = parseNode();
          if (k !== prev) {
            kids.push(k); // collapse only consecutive identical subtrees (order and type preserved)
            prev = k;
          }
          if (s[i] === ",") {
            i += 1;
            continue;
          }
          break;
        }
      }
      if (s[i] === ")") i += 1; // skip ")"
      return `${tag}>(${kids.join(",")})`;
    }
    return tag;
  };
  const root = parseNode();
  // If the parser can't consume everything (unexpected shape), don't collapse — use the raw string (fail-safe fallback).
  return i === s.length ? root : s;
}

/** Normalize the tag-structure string to a 16-digit hex. Collapse consecutive identical siblings before hashing (item-count-independent). */
export function hashDomSkeleton(skeleton: string): string {
  const normalized = skeleton.replace(/\s+/g, " ").trim().toLowerCase();
  let key = normalized;
  try {
    key = collapseSkeletonRuns(normalized);
  } catch {
    key = normalized; // on parse failure, behave as before (don't stall the crawl)
  }
  return createHash("sha256").update(key).digest("hex").slice(0, 16);
}
