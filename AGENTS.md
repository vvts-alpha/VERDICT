# Repository Guidelines

## Project Structure & Module Organization

VERDICT is a TypeScript/pnpm monorepo for web/API security assessments. `packages/*/src/` contains shared contracts and SQLite state (`core`), assessment logic (`crawler`, `scanner`, `agent`, `pilot`, `llm-attacks`), LLM providers (`llm`), and interfaces (`cli`, `server`, React `webui`). `apps/desktop/` is the primary Electron interface. Tests live beside source as `*.test.ts`. `assets/` holds screenshots and branding; `templates/` contains example manifests; `tools/burp-audit-ext/` contains the Java extension. Consult `DESIGN.md` and `docs/WEBUI_CONVENTIONS.md` for architecture and UI rules. Benchmark reports and tooling belong in https://github.com/vvts-alpha/verdict-pub. Keep internal plans and handoff notes local; do not commit them.

## Build, Test, and Development Commands

Use Node.js 24+ and pinned pnpm 9.15.4 (`corepack enable pnpm`).

- `pnpm install --frozen-lockfile`: install workspace dependencies reproducibly.
- `pnpm -r build`: build packages in dependency order, including Vite renderers.
- `pnpm -r typecheck`: run package TypeScript checks.
- `pnpm -r test`: run all package test suites.
- `pnpm test:browser`: real-browser crawler tests in `packages/crawler/test/`; needs Chromium (`pnpm --filter @veritas/crawler exec playwright-core install --with-deps chromium`).
- `pnpm --filter @veritas/desktop dev`: build and launch Electron.
- `pnpm --filter @veritas/cli dev serve`: start the local server/WebUI at `127.0.0.1:4317`.

Build before testing dependent packages; workspace imports commonly resolve to `dist/`.

## Design Before Implementation

Settle the design before writing code — for every feature, fix, or mechanism:

- **State the invariants** and identify the *single authoritative source* for every piece of state. No duplicated state that can silently diverge (e.g. a per-worker copy of shared session material). If state must exist twice, make one side a read-through of the other.
- **Enumerate the failure modes up front**: startup, resume/replay, teardown, reconnect, concurrent callers. Write down what the mechanism does in each — a path that "usually works" is a bug queue, not a design.
- **Prefer structural or behavioral evidence over heuristics.** Never classify security/liveness state from message strings, body keywords, or error text — those produce false-positive cascades. Use protocol/structural signals (HTTP status, redirect targets, DOM structure, context-liveness probes) and explicit state transitions.
- **Distinguish observation from verdict.** A probe result (401, a login-looking page) is data; a state declaration (blocked, dead, done) must come from an authoritative event — an explicit attempt's outcome or a direct liveness check — never inferred from ambiguous observations.
- **Don't patch symptoms with more heuristics.** When a mechanism misfires, re-examine the design before adding another marker/threshold/regex. If the design can't express the truth, change the design.

For non-trivial mechanisms, write the design down first (in the PR description or a short note) and list the edge cases it must survive. Review the edge cases before implementing.

## Coding Style & Naming Conventions

Use strict TypeScript, ESM, explicit `import type`, and `.js` extensions for NodeNext relative imports. Match surrounding indentation (two or four spaces), double quotes, and semicolons. Use kebab-case module filenames, PascalCase types/components, and camelCase functions. Write new comments in English. No linter or formatter is configured. Preserve internal `@veritas/*` names; operator-facing branding is VERDICT.

## Testing Guidelines

Tests use `node:test`, `node:assert/strict`, and `tsx`. Add behavior-focused regression tests using `FakeDriver`, `FakeHttpClient`, or `FakeLlmClient`; avoid real LLM calls. Run one suite with `pnpm --filter @veritas/core test`. CI audits dependencies (`pnpm audit --audit-level low`), builds, typechecks, runs all suites, then the browser and release-tooling tests; no numeric coverage threshold is configured. For UI changes, build, serve, and visually verify against the WebUI conventions.

## Commit & Pull Request Guidelines

Follow the history's Conventional Commit style: `feat(desktop): ...`, `fix(pilot): ...`, or `docs: ...`. Keep commits focused. PRs should describe the problem, resulting behavior, validation commands, and relevant issues; include screenshots for UI changes.

## Security & Architecture Rules

Keep shared contracts in `core` and WebUI imports from core type-only. Preserve scope gates and append-only state events. Confirmation requires a failing negative control and at least two successful positive replays. Never commit `.env`, credentials, cookies, or private run artifacts; use authorized targets only.

## Release Gates

Follow `docs/RELEASING.md`. Release only the exact CI installer tested on Windows, with successful CI and Windows workflow runs for the same source commit. Use `tools/promote-release.cjs`; do not substitute a local rebuild, bypass a failing gate, or mutate published assets. Run `pnpm test:release` after changing release tooling. Record actual checks and limitations using the shared templates. Existing release authorization is sufficient; do not add repeated permission questions.
