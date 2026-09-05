// @veritas/server — state API + WebSocket (WebUI backend).

export { startServer } from "./server.js";
export type { ServerOptions, RunningServer } from "./server.js";
export type { RunLauncherConfig, StartRunInput } from "./supervisor.js";
export { checkReadiness } from "./preflight.js";
