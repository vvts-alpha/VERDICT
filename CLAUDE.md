# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

NewAgent is a **ground-up TypeScript rewrite** of the **VERDICT** (formerly AMRAAM, originally VERITAS) autonomous web/API pentest agent. It shares only *principles* with the older `CrowSong/` + `HungrySong/` pipeline documented in the parent `/home/sophos/BugBounty/CLAUDE.md` — **no code is reused**. When working under `NewAgent/`, this file governs; the parent file describes a different (Python) codebase.

- **Design source of truth:** `DESIGN.md` (Japanese). `README.md` is the operator guide (commands, pilot modes, WebUI, Burp/header-audit workflows). The richest running log of decisions is in memory (`newagent_claude_pilot_2026_06_09`).
- **Picking up work / cross-machine handoff:** read `docs/NEXT_STEPS.md` first — it carries the current TODOs (attended manual-auth mode, diagnosis parallelization), the agreed design defaults, and new-box setup. (CLI sessions/memory are machine-local; that doc is the portable channel.)
- **Authorized targets only.** Every network action passes the scope gate (`isInScope`); out-of-scope is denied. `--url` derives scope as same-origin + path-prefix; a manifest gives explicit scope.

## Setup & requirements

- **Node.js >= 24** is mandatory — the state store uses the builtin `node:sqlite` (no native dependency). `nvm use 24` if needed.
- **pnpm** via corepack: `corepack enable pnpm` (pinned `pnpm@9.15.4`).
- Playwright uses **`playwright-core`** and needs a chromium binary you supply: `npx playwright install chromium`, or pass `--browser-path <bin>` / set `VERITAS_BROWSER_PATH`. Add `--no-sandbox` in containers.
- LLM calls shell out to the **`claude` CLI** (subscription auth) — see invariants. No `ANTHROPIC_API_KEY` is used.

```bash
pnpm install
pnpm -r build        # tsc per package (+ Vite build for webui)
```

## Commands

```bash
pnpm -r build           # build all packages (respects workspace dep order)
pnpm -r typecheck       # tsc --noEmit across packages
pnpm -r test            # node:test via tsx across packages
pnpm -r clean

pnpm --filter @veritas/core build      # one package
pnpm --filter @veritas/crawler test    # one package's whole suite
```

**Run a single test file** — must be run *from inside the package directory* (the test script globs `src/**/*.test.ts` relative to the package; invoking with a root-relative path fails):

```bash
cd packages/core
node --import tsx --disable-warning=ExperimentalWarning --test src/tree.test.ts
```

**Build before testing dependent packages.** Workspace deps resolve through `main: ./dist/index.js`, so a package that imports `@veritas/core` (crawler, scanner, agent, server, cli, pilot) needs core (and its other deps: llm, scanner) **built** first. Run `pnpm -r build` before a fresh `test`/`typecheck` of dependents. Tests have no external network/LLM needs — they use `FakeDriver` / `FakeHttpClient` / `FakeLlmClient`.

### CLI

Two invocation forms — built JS, or `tsx` dev (resolves `src` directly, no build):

```bash
node packages/cli/dist/main.js <command> [opts]            # after pnpm -r build
pnpm --filter @veritas/cli dev <command> [opts]            # tsx, src-resolved
```

| Command | Purpose |
|---|---|
| `manifest` (alias `init`) | Interactive scope-manifest generator (`node:readline` line-queue, no deps): prompts for target / in·out-of-scope hosts+paths / rate / crawl / model / auth roles → writes the `AssessManifest` JSON that `pilot`/`assess` read. `--out <file>` / `--force`; passwords are read with echo masked. Default name `scope_manifest_<host>.json` is gitignored. |
| `pilot` | **Claude-led, staged** assessment (survey → methodology → diagnosis). `--manifest`/`--url`, `--model` (deep) + `--fast-model` (model tiering), `--max-turns`, `--headed`, `--burp-proxy <url>` (route all traffic through Burp; off by default = unchanged), `--keepalive-min <n>` (touch the top page between screens to keep an authed session warm; default 4, `0` = off). |
| `pilot --survey-only` | Map only (screens + screenshots + APIs); no methodology/diagnosis/findings. Cheap recon → resume later. |
| `pilot --resume --id <id>` | Continue an existing run: skip survey/methodology, diagnose only non-terminal (queued) screens. Reuses the run's browser-profile for auth. |
| `assess` | **Deterministic** one-shot: crawl → label → scan → logic → report (`--login-url`/`--login-wait` for headed login). |
| `serve` | Observability WebUI + state API/WS (default `127.0.0.1:4317`; `--host 0.0.0.0` to expose). |
| `shots --id <id>` | Backfill per-screen screenshots into an existing run (reuses its browser-profile; navigate-only). |
| `header-audit --id <id>` | Deterministic Info-level header checks (`--headers csp,hsts,…`). Toggle = run it or not. |
| `burp-import --id <id> --report <xml>` | Parse a Burp Pro XML report, merge **net-new** issues (deduped vs agent findings). |
| `run` / `crawl` / `label` / `scan` / `logic` | Deterministic pipeline steps (the internals of `assess`). |
| `report` / `status` / `list` | report.md; phase/coverage/stop-condition; list `runs/`. |

## Architecture (big picture)

**Two execution modes over one shared substrate.** The repo currently carries both; pilot is the newer direction (see `README` / memory), the deterministic pipeline is the granular/inspectable path.

1. **`pilot` — Claude-led, staged** (`packages/pilot`): `run.ts` is a **3-stage orchestrator** that calls `query()` (`@anthropic-ai/claude-agent-sdk`) **once per stage** (and once per screen in diagnosis) against an in-process MCP tool server (`createSdkMcpServer`) — deliberately bounded so the model can't elide work. Stages: **survey** (map: `browser_navigate/fill/click`, `probe_paths`, `login`, `survey_status/done` → persists `Screen`s + screenshots) → **methodology** (`get_inventory`, `record_methodology` → per-screen plan) → **diagnosis** (per screen, bounded: `get_screen`, `http_request`, `probe_params`, `analyze_session`, `record_finding`, `screen_done`). `STAGE_TOOLS` gates the tools per stage via `allowedTools`. Findings are **deduped** by `(category, endpoint, param)` (`dedupKey` in `tools.ts`). Model tiering: `screenIsHighValue` routes high-value screens to `--model` (deep), the rest + survey/methodology to `--fast-model`. Modes: `surveyOnly` / `resume` skip stages. `--burp-proxy` routes the driver + http client through Burp. Built-in tools (Bash/Read/Write/WebFetch…) are disallowed.
2. **Deterministic pipeline** (`assess` / `crawl`→`label`→`scan`→`logic`→`report`): fixed orchestration in `packages/cli/src/main.ts` calling crawler → scanner → agent.

**Two phases joined by one contract.** Phase 1 (recon + labeling) writes **`screen_inventory.json`** (the `Screen` schema in `core/types/screen.ts`); Phase 2 (scan + business logic) and the WebUI only read it. This is the sole coupling point — keep it stable.

**Cross-cutting substrate = `@veritas/core`.** `AssessmentStore` (`state.sqlite`) is simultaneously the agent's working memory *and* the WebUI data source. It holds normalized tables (`assessments`/`screens`/`hypotheses`/`findings`/`handoffs`) plus an **append-only `events`** log; the server polls `events.seq` to push diffs to the WebUI over WS. Core also owns the scope gate, coverage ledger, budget/stop logic, site-tree/state-view projections, and `buildReport`.

**Package layering** (deps flow downward; `@veritas/core` is the only home for shared contract types):

```
cli ── orchestrates everything
pilot ─ agent ─ scanner ─┐
crawler ─ llm ───────────┤
server   webui ──────────┴── core  (types + store + scope + evidence-of-record contracts)
```

- `crawler` — Playwright `PlaywrightDriver` (persistent context, XHR/fetch intercept, SPA virtual routes) + a pure pipeline (URL normalize, API shape inference, DOM-skeleton-hash dedup, rule+LLM labeling, `smartLogin`, `detectStuck`). `FakeDriver` for browserless tests.
- `scanner` — `EvidenceStore`, `FetchHttpClient` (scope-gated, conservative rate, optional `proxy` for Burp), the validator runner + catalog (`exposed_file`/`auth_required`/`cors_misconfig`), Info-level header audit (`headers.ts`/`passive.ts`), and Burp XML report parsing (`burp.ts`). **This is where evidence discipline lives.**
- `agent` — business-logic: `generateHypotheses` (LLM + rule fallback), the IDOR verifier, `authDiffScreen` (multi-role authz comparison). Reuses `scanner`'s evidence discipline.
- `llm` — `ClaudeCliClient` (subprocess) + `FakeLlmClient` + zod-validated structured-output helpers.
- `server`/`webui` — React 3-pane observer; webui imports `core` **types only**, built by Vite.

**Data layout** (`runs/` is gitignored): `runs/<assessment_id>/` → `state.sqlite`, `screen_inventory.json`, `artifacts/screens/<screen_id>.png` (per-screen screenshots), `artifacts/<screen_id>/<evidence_id>/` (req/resp), `report.md`, `browser-profile/` (persistent userDataDir — auth state lives here). The WebUI (`serve`) is one page per target: SITE TREE + progress bar + tabs (Screen / Findings / APIs / 診断ログ) with an inline evidence viewer.

## Invariants (don't break these)

- **Contract types live only in `@veritas/core`.** Don't redeclare `Screen`/`Hypothesis`/`Finding`/`ScopePolicy` etc. elsewhere; import them. `webui` must stay **types-only** on core (it's bundled by Vite, not Node).
- **Evidence discipline** (`scanner`): a finding is `confirmed` only with a **negative control that fails + ≥2 positive replays that succeed**; catch-all / 0-byte-200 / unstable responses → `refuted`. `agent` and `pilot` both route confirmations through this — never mark `confirmed` by hand.
- **Scope gate on every network action.** `isInScope(url, scope)` (core `scope-check.ts`) guards crawler navigation, `FetchHttpClient` (via its `allow` callback), and pilot tools. Out-of-scope returns blocked, not an exception.
- **LLM = `claude` CLI subscription, not the metered API.** `ClaudeCliClient` runs `claude -p --output-format json --model <m>` and parses the JSON envelope. Keep it that way (Max subscription, no per-token billing). Use `FakeLlmClient` in tests — never hit the real CLI in `node:test`.
- **State is append-only + replayable.** Every state transition appends a `StateEvent` in the same transaction as the row write. The WebUI is a pure projection (`buildStateView`/`buildSiteTree`); don't mutate UI state out-of-band.
- **Auth = operator-provided material (creds OR a pre-captured cookie file).** A role is either credentials (`{name, pass}` → `smartLogin` auto-discovers the login form) OR a cookie file (`{name, cookieFile}` → `loadCookieFile` reads a raw `Cookie:` header or a Playwright `storageState` JSON, and the `login` tool injects it into the browser + http session). The cookie path is for walls the agent can't auto-login (Arkose/MFA). **The agent never fabricates or steals cookies — it only uses material the operator explicitly supplies; cookie files are secrets (gitignored).** MFA/CAPTCHA without a cookie file → `detectStuck` raises a non-blocking `HumanHandoff` (headed browser, human logs in the live profile). `roles[0]` = primary; multiple roles drive `authDiffScreen`.
- **Brand is "VERDICT" but code-internal names are intentionally kept (VERITAS→AMRAAM→VERDICT lineage).** Everything an operator sees is VERDICT: display brand, the traffic marker (`x-verdict`), the scanner UA (`verdict-scanner`), the session cookie (`verdict_session`), and the env vars **`VERDICT_WEB_PASSWORD[_VIEWER]`** / **`VERDICT_BROWSER_PATH`** (the old `AMRAAM_WEB_PASSWORD*` / `VERITAS_BROWSER_PATH` names are still accepted as **fallbacks** so existing `.env` files don't break — see `cmdServe` and the browser-path resolution in `packages/cli/src/main.ts`). But the **truly invisible code namespaces stay VERITAS/AMRAAM-era**: the package scope **`@veritas/*`**, the MCP namespace **`mcp__veritas__`** (tool prefix in `STAGE_TOOLS`/`allowedTools`), the in-page globals **`__veritasRoutes`/`__verdict_xss`**, and only the Burp extension's Java **package + maven group `com.amraam.burpaudit`** (the package path & group stay AMRAAM-era; everything else about the extension is VERDICT — display name "VERDICT Audit REST", jar `verdict-burp-audit.jar`, config `verdict-audit.properties`, env `VERDICT_AUDIT_*`). Renaming those namespaces is churn across every import/package.json/gradle with zero user benefit — don't "fix" the inconsistency.
- **Burp integration is opt-in and additive.** `--burp-proxy` and `burp-import` only act when invoked; with the flag off, behaviour is byte-identical (the `undici` ProxyAgent is lazy-imported only when a proxy is set). Keep it that way.

## TypeScript strictness gotchas

`tsconfig.base.json` is strict in ways that bite: `verbatimModuleSyntax` (type-only imports **must** use `import type`), `noUncheckedIndexedAccess` (array/record access is `T | undefined` — narrow it), `isolatedModules`, `noUnusedLocals`/`noUnusedParameters`, `noFallthroughCasesInSwitch`. ESM `NodeNext` resolution → relative imports need the **`.js`** extension even from `.ts` sources.

No linter/formatter is configured. Match nearby code: ESM, 4-space-ish existing style, kebab-case filenames, PascalCase types, camelCase functions. Comments and code are English (the codebase was historically bilingual with Japanese comments — that has been translated to English; keep new comments English). Note: some LLM-facing prompt/tool-`description:` strings in `packages/pilot/src` (`system.ts`, `tools.ts`) may still be Japanese by design — those are model inputs, not on-screen text; leave them unless asked.
