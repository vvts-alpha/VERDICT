// Minimal dependency-free .env loader. On CLI startup, reads .env from cwd and applies only the
// environment variables that aren't set yet (values already exported in the shell take precedence).
// Lets BURP_API / BURP_PROXY etc. be kept in a file.

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** .env text -> KEY/VALUE. Allows an `export` prefix, `#` comments, and surrounding quotes. Splits on the first `=`. */
export function parseDotEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m || !m[1]) continue;
    let val = (m[2] ?? "").trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[m[1]] = val;
  }
  return out;
}

/** Reads .env from cwd and applies only the unset environment variables to process.env. Returns the loaded key names. */
export function loadDotEnv(dir: string = process.cwd(), file = ".env"): string[] {
  const path = join(dir, file);
  if (!existsSync(path)) return [];
  let parsed: Record<string, string>;
  try {
    parsed = parseDotEnv(readFileSync(path, "utf8"));
  } catch {
    return [];
  }
  const loaded: string[] = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (process.env[k] === undefined) {
      process.env[k] = v;
      loaded.push(k);
    }
  }
  return loaded;
}
