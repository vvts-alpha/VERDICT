# Packaging the VERDICT desktop app

The Electron main process hosts the local server and spawns the packaged CLI. OpenAI-compatible providers run without a Claude subprocess; the optional Claude path requires its platform-specific executable. Automation uses installed Chrome/Edge or an explicit browser path.

## Build a production bundle

Run on the destination operating system with Node 24+ and pnpm 9.15.4:

```bash
pnpm install --frozen-lockfile
pnpm -r build
node tools/package-desktop.cjs prepare /path/to/fresh-production /path/to/fresh-bundle
pnpm --dir /path/to/fresh-production install --frozen-lockfile --prod --node-linker=hoisted --ignore-scripts
node tools/package-desktop.cjs materialize /path/to/fresh-production /path/to/fresh-bundle
```

Staging retains the original lockfile. Materialization copies runtime files and native optional dependencies into a flat directory. Do not substitute an unfrozen deploy or copy a Linux dependency tree into a Windows release.

## Package and validate

From the bundle directory:

```bash
npx --yes electron-builder@26.15.3 --config electron-builder.yml --win --x64 --publish never
```

The builder infers the pinned Electron version. Its Windows hook verifies the native SDK executable and removes foreign platforms/architectures. `asar` remains disabled so CLI and native executables are accessible as real files.

CI runs `tools/check-desktop-bundle.cjs` using Node 24+ and 7-Zip. It binds the tested directory to installer contents, checks size and private-file exclusions, starts packaged CLI/SDK executables, launches the GUI in an isolated profile, and checks authenticated API access plus rejection of external unauthenticated requests. It emits an artifact manifest and checksum file.

Follow [the release procedure](../../docs/RELEASING.md) to run live checks and promote the exact CI artifact. Packaging success alone is not release readiness.
