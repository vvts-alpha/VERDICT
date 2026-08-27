import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url)); // apps/desktop

// The desktop renderer build — separate from the web (@veritas/webui) build. Source lives in renderer/,
// output goes to dist-renderer/, which the Electron main serves via the in-process @veritas/server (so the
// UI reaches the server over the same relative /api + /ws URLs the web UI uses). base "./" for path-agnostic serving.
export default defineConfig({
    root: "renderer",
    plugins: [react()],
    base: "./",
    // Share webui's brand assets (verdict-title.png / favicon.png the components reference as /…) — no binary copy.
    publicDir: resolve(here, "../../packages/webui/public"),
    build: {
        outDir: "../dist-renderer",
        emptyOutDir: true,
        target: "es2022",
    },
    server: {
        port: 5318,
        proxy: {
            "/api": "http://127.0.0.1:4317",
            "/ws": { target: "ws://127.0.0.1:4317", ws: true },
        },
    },
});
