# Repository Guidelines

## Project Structure & Module Organization

VERDICT is a TypeScript/pnpm monorepo for web/API security assessments. `packages/*/src/` contains shared contracts and SQLite state (`core`), assessment logic (`crawler`, `scanner`, `agent`, `pilot`, `llm-attacks`), LLM providers (`llm`), and interfaces (`cli`, `server`, React `webui`). `apps/desktop/` is the primary Electron interface. Tests live beside source as `*.test.ts`. `assets/` holds screenshots and branding; `templates/` contains example manifests; `tools/burp-audit-ext/` contains the Java extension. Consult `DESIGN.md` and `docs/WEBUI_CONVENTIONS.md` for architecture and UI rules. Benchmark reports and tooling belong in https://github.com/vvts-alpha/verdict-pub. Keep internal plans and handoff notes local; do not commit them.

## Build, Test, and Development Commands

Use Node.js 24+ and pinned pnpm 9.15.4 (`corepack enable pnpm`).

- `pnpm install --frozen-lockfile`: install workspace dependencies reproducibly.
- `pnpm -r build`: build packages in dependency order, including Vite renderers.
- `pnpm -r typecheck`: run package TypeScript checks.
- `pnpm -r test`: run all package test suites.
- `pnpm --filter @veritas/desktop dev`: build and launch Electron.
- `pnpm --filter @veritas/cli dev serve`: start the local server/WebUI at `127.0.0.1:4317`.

Build before testing dependent packages; workspace imports commonly resolve to `dist/`.

## Coding Style & Naming Conventions

Use strict TypeScript, ESM, explicit `import type`, and `.js` extensions for NodeNext relative imports. Match surrounding indentation (two or four spaces), double quotes, and semicolons. Use kebab-case module filenames, PascalCase types/components, and camelCase functions. Write new comments in English. No linter or formatter is configured. Preserve internal `@veritas/*` names; operator-facing branding is VERDICT.

## Testing Guidelines

Tests use `node:test`, `node:assert/strict`, and `tsx`. Add behavior-focused regression tests using `FakeDriver`, `FakeHttpClient`, or `FakeLlmClient`; avoid real LLM calls. Run one suite with `pnpm --filter @veritas/core test`. CI builds and tests; no numeric coverage threshold is configured. For UI changes, build, serve, and visually verify against the WebUI conventions.

## Commit & Pull Request Guidelines

Follow the history's Conventional Commit style: `feat(desktop): ...`, `fix(pilot): ...`, or `docs: ...`. Keep commits focused. PRs should describe the problem, resulting behavior, validation commands, and relevant issues; include screenshots for UI changes.

## Security & Architecture Rules

Keep shared contracts in `core` and WebUI imports from core type-only. Preserve scope gates and append-only state events. Confirmation requires a failing negative control and at least two successful positive replays. Never commit `.env`, credentials, cookies, or private run artifacts; use authorized targets only.
