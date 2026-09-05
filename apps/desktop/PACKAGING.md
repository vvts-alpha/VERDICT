# Packaging the VERDICT desktop app

The app is a pnpm-workspace Electron app: the Electron main hosts `@veritas/server` in-process and spawns the
`@veritas/cli` as a child to run assessments. There are **no native modules** (the store uses Node's builtin
`node:sqlite`; `playwright-core` drives an external chromium), so packaging needs no node-gyp rebuild.

## 1. Self-contained bundle (verified, the simplest distributable)

`pnpm deploy` materializes the app + every workspace dependency (`@veritas/*`, `playwright-core`, `zod`, …) into
one self-contained folder with its own `node_modules` — no symlinks into the repo:

```bash
pnpm -r build                                   # all dist/ (tsc + the desktop renderer via Vite)
pnpm --filter @veritas/desktop deploy ./bundle  # → ./bundle, self-contained
cd bundle && electron .                          # runs: window + in-process server + can launch assessments
```

Verified end-to-end: the deployed app renders the UI and its spawned child resolves `playwright-core` + all
`@veritas/*` from the bundle and runs a headless assessment. `node:sqlite` works (the packaged Electron 38.0.0 runtime was checked with Node 22.18.0).

The only external dependency is a **Chromium for automation** — set its path in the app's **Settings**
(`VERDICT_BROWSER_PATH`). The LLM provider (OpenCodeGo / OpenAI / Claude) is also configured in Settings.

## 2. Native installer (AppImage / nsis / dmg)

electron-builder does not follow pnpm's symlinked `node_modules`, so run it against the **materialized bundle**:

```bash
pnpm -r build
pnpm --filter @veritas/desktop deploy ./bundle
cd bundle && npx electron-builder --config electron-builder.yml   # → bundle/dist-installer/
```

`asar` is off (the app spawns the CLI child as a real process; spawning/`require.resolve` inside an asar archive
is unsupported and there are no native modules to hide). Build per-platform on that platform (or via CI).

### Bundling Chromium (optional)

To ship a fully self-contained installer, drop a Playwright chromium build under `resources/chromium`, enable the
`extraResources` block in `electron-builder.yml`, and set `VERDICT_BROWSER_PATH` to that path at runtime
(`process.resourcesPath`). It adds ~150MB per platform, so it's opt-in.
