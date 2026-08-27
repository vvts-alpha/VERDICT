// Reusable entry for the web UI. The `serve` web build mounts this via src/main.tsx; the desktop renderer
// (apps/desktop) imports App from here and wraps it in its own desktop chrome — shared view components, separate builds.
export { App } from "./App";
