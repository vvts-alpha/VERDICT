// @veritas/server — state API + WebSocket (WebUI backend).

export { startServer } from "./server.js";
export { isSupportedRun } from "./supervisor.js";
export type { ServerOptions, RunningServer } from "./server.js";
export type { RunLauncherConfig, StartRunInput } from "./supervisor.js";
export { checkReadiness } from "./preflight.js";
export { UsersDb, usersDbPath } from "./users-db.js";
export type { AuditRow, SessionRow, UserRole, UserRow } from "./users-db.js";
export { hashPassword, passwordPolicyError, verifyPassword } from "./passwords.js";
