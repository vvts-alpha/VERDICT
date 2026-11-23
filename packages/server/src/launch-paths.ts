import { existsSync, readFileSync, realpathSync } from "node:fs";
import { isAbsolute, join, relative, sep } from "node:path";

/** Bundled probe_paths wordlist ids (mirrors @veritas/pilot WORDLIST_IDS; the server does not depend on pilot). */
export const BUNDLED_WORDLISTS = ["standard", "extended"] as const;

const COOKIE_KEYS = ["cookieFile", "cookie_file", "cookie_file_path"] as const;

export class LaunchPathError extends Error {}

export interface LaunchPathPolicy {
  runsDir: string;
  /** Trusted same-user desktop session (per-launch token): local file paths are the operator's own. */
  allowLocalPaths: boolean;
  /** Whether the caller may read files of this run directory. */
  canUseRun(runId: string): boolean;
}

/** Resolve a server-supplied file path to its realpath, which must lie inside a run directory the caller can use. */
export function resolveRunFile(path: string, policy: Pick<LaunchPathPolicy, "runsDir" | "canUseRun">): string {
  let root: string;
  let file: string;
  try {
    root = realpathSync(policy.runsDir);
    file = realpathSync(path);
  } catch {
    throw new LaunchPathError("Session file must be inside one of your assessment directories");
  }
  const rel = relative(root, file);
  const runId = rel.split(sep)[0] ?? "";
  if (!rel || rel.startsWith("..") || isAbsolute(rel) || runId === rel || !policy.canUseRun(runId)) {
    throw new LaunchPathError("Session file must be inside one of your assessment directories");
  }
  return file;
}

/** Reject launch inputs that would make the child CLI read arbitrary server files. Rewrites accepted cookie paths
 *  to their realpath so the child reads exactly the file that was checked. */
export function enforceLaunchPaths(manifest: unknown, options: { wordlist?: unknown } | undefined, policy: LaunchPathPolicy): void {
  if (policy.allowLocalPaths) return;
  const wordlist = options?.wordlist;
  if (wordlist !== undefined && wordlist !== "" && !(BUNDLED_WORDLISTS as readonly unknown[]).includes(wordlist)) {
    throw new LaunchPathError(`wordlist must be one of: ${BUNDLED_WORDLISTS.join(", ")}`);
  }
  const roles = (manifest as { auth?: { roles?: unknown } } | null)?.auth?.roles;
  if (!Array.isArray(roles)) return;
  for (const role of roles) {
    if (!role || typeof role !== "object") continue;
    const r = role as Record<string, unknown>;
    for (const key of COOKIE_KEYS) {
      const value = r[key];
      if (value === undefined || value === "") continue;
      if (typeof value !== "string") throw new LaunchPathError(`${key} must be a path`);
      r[key] = resolveRunFile(value, policy);
    }
  }
}

/** Re-check a saved run's manifest/options before respawning it (runs saved before this check may hold paths). */
export function enforceSavedRunPaths(runsDir: string, id: string, policy: LaunchPathPolicy): void {
  if (policy.allowLocalPaths) return;
  const read = (name: string): unknown => {
    const path = join(runsDir, id, name);
    if (!existsSync(path)) return undefined;
    try {
      return JSON.parse(readFileSync(path, "utf8"));
    } catch {
      throw new LaunchPathError(`Saved ${name} is unreadable`);
    }
  };
  const run = read("run.json") as { options?: { wordlist?: unknown } } | undefined;
  enforceLaunchPaths(read("manifest.json"), run?.options, policy);
}
