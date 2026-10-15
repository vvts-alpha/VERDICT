import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

// base "./" で相対パス出力 → @veritas/server がどの root から配信しても動く。
// dev 時は別ポートの veritas server(既定 4317)へ API/WS をプロキシ。
export default defineConfig({
  plugins: [react(), tailwindcss()],
  resolve: { alias: { "@": resolve(here, "src") } },
  base: "./",
  build: { outDir: "dist", emptyOutDir: true, target: "es2022" },
  server: {
    port: 5317,
    proxy: {
      "/api": "http://127.0.0.1:4317",
      "/ws": { target: "ws://127.0.0.1:4317", ws: true },
    },
  },
});
