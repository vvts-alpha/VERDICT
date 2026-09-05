import { existsSync, readFileSync, realpathSync, renameSync, writeFileSync } from "node:fs";
import { join, relative, isAbsolute } from "node:path";
import type { AssessmentStore } from "@veritas/core";

export class SessionContinuationError extends Error {
  constructor(message: string, readonly roles?: string[]) { super(message); }
}

/** Keep fresh auth in the saved manifest before restarting; resume ignores old queued controls. */
export function continueSession(
  runsDir: string, id: string, input: { cookieFile: string; handoffId?: string; role?: string },
  store: AssessmentStore, supervisor: { isRunning(id: string): boolean; resume(id: string): void },
): { action: "injected" | "restarted" } {
  const root = realpathSync(runsDir);
  const file = realpathSync(input.cookieFile);
  const rel = relative(root, file);
  if (!rel || rel.startsWith("..") || isAbsolute(rel)) throw new SessionContinuationError("Session file must be inside the runs directory");
  const capture = JSON.parse(readFileSync(file, "utf8")) as { cookies?: unknown[]; origins?: unknown[] };
  if (!(Array.isArray(capture.cookies) && capture.cookies.length) && !(Array.isArray(capture.origins) && capture.origins.length)) {
    throw new SessionContinuationError("Capture a non-empty browser session first");
  }
  const state = store.loadAssessment(id);
  if (!state) throw new SessionContinuationError("Assessment not found");
  const handoff = input.handoffId ? state.handoffs.find((h) => h.id === input.handoffId) : undefined;
  if (input.handoffId && (!handoff || !["auth", "captcha"].includes(handoff.reason))) {
    throw new SessionContinuationError("This is not a login handoff");
  }
  const running = supervisor.isRunning(id);
  if (!running) {
    const path = join(runsDir, id, "manifest.json");
    const manifest = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : {
      target: "url" in state.target ? state.target.url : "", scope: state.scope,
    };
    const auth = manifest.auth ?? {};
    const roles: Array<Record<string, unknown> & { name: string }> = auth.roles ?? [];
    const role = input.role || (roles.length === 1 ? roles[0]!.name : roles.length === 0 ? "primary" : undefined);
    if (!role) throw new SessionContinuationError("Select the account role used for this login", roles.map((r) => r.name));
    if (roles.length && !roles.some((r) => r.name === role)) throw new SessionContinuationError("Unknown account role");
    manifest.auth = { ...auth, roles: roles.length ? roles.map((r) => r.name === role ? { ...r, cookieFile: file } : r) : [{ name: role, cookieFile: file }] };
    writeFileSync(path + ".tmp", JSON.stringify(manifest, null, 2));
    renameSync(path + ".tmp", path);
  } else {
    store.appendControlCommand(id, { injectCookieFile: file, note: "operator supplied a captured login session" });
  }
  if (handoff) store.upsertHandoff(id, { ...handoff, status: "resolved", resolvedAt: new Date().toISOString() });
  store.setPaused(id, false, "continue after manual login");
  if (!running) supervisor.resume(id);
  store.appendEvent(id, { type: "note", payload: { message: running ? "Login session queued for the active diagnosis" : "Diagnosis restarted with captured login session" } });
  return { action: running ? "injected" : "restarted" };
}
