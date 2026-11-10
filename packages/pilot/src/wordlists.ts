// probe_paths wordlist resolution.
// Bundled lists live in packages/pilot/wordlists/ — the same relative depth below the module file works
// for both src/ (tsx dev) and dist/ (built), and ships inside node_modules/@veritas/pilot/wordlists/ in
// the desktop bundle (asar off). A spec is a bundled id ("standard" | "extended") or a filesystem path
// to a custom list; unknown specs are treated as paths and fail fast so a typo can't silently downgrade
// the run to a smaller list.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const WORDLIST_IDS = ["standard", "extended"] as const;
export type WordlistId = (typeof WORDLIST_IDS)[number];

const WORDLISTS_DIR = fileURLToPath(new URL("../wordlists/", import.meta.url));

/** The bundled list ids (minus "standard", which is the in-code PATH_WORDLIST). */
export function bundledWordlistPath(id: Exclude<WordlistId, "standard">): string {
  return `${WORDLISTS_DIR}${id}.txt`;
}

/** Normalize wordlist lines to probe paths: strip comments/blanks, force a leading "/". */
export function parseWordlist(text: string): string[] {
  const out = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    out.add(line.startsWith("/") ? line : `/${line}`);
    if (out.size >= 60_000) break; // absurd file → bound the request storm anyway
  }
  return [...out];
}

/** Resolve a --wordlist spec to candidate paths.
 *  "standard" (or unset) → undefined = the in-code PATH_WORDLIST default.
 *  "extended"             → the bundled SecLists common.txt (~4.7k entries).
 *  anything else          → read as a filesystem path; ENOENT etc. throws with context. */
export function loadWordlist(spec: string | undefined): string[] | undefined {
  if (!spec || spec === "standard") return undefined;
  if (spec === "extended") return parseWordlist(readFileSync(bundledWordlistPath("extended"), "utf8"));
  let text: string;
  try {
    text = readFileSync(spec, "utf8");
  } catch (e) {
    throw new Error(`--wordlist: ${spec} is not a bundled id (${WORDLIST_IDS.join("|")}) and cannot be read as a file: ${e instanceof Error ? e.message : e}`);
  }
  return parseWordlist(text);
}
