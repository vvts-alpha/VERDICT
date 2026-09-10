# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

VERDICT is a TypeScript/pnpm monorepo for web/API security assessments. The primary interface is the Electron desktop app.

- **Contributor guidance:** follow `AGENTS.md`; see `DESIGN.md` for architecture and `docs/WEBUI_CONVENTIONS.md` for UI rules.
- **Public documentation:** `README.md` is the desktop quickstart; `docs/USAGE.md` covers CLI/operator workflows. Internal plans, handoff notes, and private run artifacts stay local and must not be committed.
- **Benchmark publications:** reports and benchmark tooling belong in https://github.com/vvts-alpha/verdict-pub, not this source repository.
- **Authorized targets only.** Every network action passes the scope gate (`isInScope`); out-of-scope is denied. `--url` derives scope as same-origin + path-prefix; a manifest gives explicit scope.

## Setup & requirements

- **Node.js >= 24** is mandatory — the state store uses the builtin `node:sqlite` (no native dependency). `nvm use 24` if needed.
- **pnpm** via corepack: `corepack enable pnpm` (pinned `pnpm@9.15.4`).
- Playwright uses **`playwright-core`** and needs a chromium binary you supply: `npx playwright install chromium`, or pass `--browser-path <bin>` / `--browser-channel <name>` / set `VERDICT_BROWSER_PATH` (old `VERITAS_BROWSER_PATH` still accepted). Add `--no-sandbox` in containers.
- LLM calls default to the **`claude` CLI** (subscription auth, no `ANTHROPIC_API_KEY`) — see invariants; an OpenAI-compatible provider is opt-in via `VERDICT_LLM_*`.
- **Env vars** (all optional): `VERDICT_BROWSER_PATH` / `VERDICT_BROWSER_CHANNEL` (automation chromium); `VERDICT_LLM_PROVIDER` (`claude-cli`|`openai`) + `VERDICT_LLM_BASE_URL`/`_API_KEY`/`_MODEL`/`_FAST_MODEL`; `VERDICT_OOB` (`none`|`interactsh`|`burp`) + `INTERACTSH_SERVER`/`INTERACTSH_TOKEN`; `BURP_AUDIT_API`/`BURP_AUDIT_TOKEN` (drives both `burp-scan` and Burp-Collaborator OOB); `VERDICT_PROXY` (upstream proxy); `VERDICT_WEB_PASSWORD[_VIEWER]` (`serve` auth). `--flag`s override the env where both exist.

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
| `pilot` | **AI-led, staged** assessment: **6 LLM stages** — survey → reconGuess → methodology → diagnosis (per-screen) → scenario (A04 cross-screen logic) → fingerprint (A06 tech/CVE) — plus a post-diagnosis **findings-QA** gate. `--manifest`/`--url`, `--model` (deep) + `--fast-model` (tiering), `--max-turns`, `--max-screens`/`--max-survey-screens`, `--rate <ms>`, `--headed`, `--focus "<obj>"` (scenario-stage objective), `--context "<facts>"` (standing target facts appended to EVERY stage prompt), `--oob interactsh\|burp\|none` (blind-vuln callback provider for `probe_oob`), `--no-scenario`/`--no-fingerprint`/`--cve-lookup`, `--burp-proxy <url>` (off by default = byte-identical), `--keepalive-min <n>` (default 4, `0`=off). |
| `pilot --survey-only` | Map only (screens + screenshots + APIs); no methodology/diagnosis/findings. Cheap recon → resume later. |
| `pilot --resume --id <id>` | Continue an existing run: skip survey/methodology, diagnose only non-terminal (queued) screens. Reuses the run's browser-profile for auth. |
| `redteam` (alias `assistant`) | **LLM/AI-assistant red-team (`@veritas/llm-attacks`)**: drives a deployed chatbot's chat UI via Playwright and confirms **canary leaks** — a high-entropy token the operator plants OOB in the assistant's protected context (system prompt / RAG / tenant data). `--url <chat-ui>` `--canary <token>` `[--headed] [--max-replays]`; `--control-url` for attended screencast into the WebUI. |
| `burp-scan --id <id>` | Launch a Burp Pro **active scan** via the Audit REST API → poll → import → AI re-verify High+ (no XML export). Needs `BURP_AUDIT_API`. |
| `spec-import --spec <openapi.json> --url <base>` | Ingest an OpenAPI 3.x / Swagger 2.0 spec to seed `screen_inventory.json` for a **browser-free pure-API** scan (`--id` overlays onto an existing crawl). |
| `assess` | **Deterministic** one-shot: crawl → label → scan → logic → report (`--login-url`/`--login-wait` for headed login). |
| `serve` | Observability WebUI + state API/WS (default `127.0.0.1:4317`; `--host 0.0.0.0` to expose). |
| `shots --id <id>` | Backfill per-screen screenshots into an existing run (reuses its browser-profile; navigate-only). |
| `header-audit --id <id>` | Deterministic Info-level header checks (`--headers csp,hsts,…`). Toggle = run it or not. |
| `burp-import --id <id> --report <xml>` | Parse a Burp Pro XML report, merge **net-new** issues (deduped vs agent findings). |
| `run` / `crawl` / `label` / `scan` / `logic` | Deterministic pipeline steps (the internals of `assess`). |
| `report` / `status` / `list` | `report --format md,html,csv,pdf` (the `pdf` path prints `renderReportHtml` output through `crawler/pdf.ts`'s Chromium `page.pdf()`, so it needs a browser binary); phase/coverage/stop-condition; list `runs/`. |
| `inventory` / `openapi` | Dump/derive the screen inventory (the deterministic-pipeline internals). |

## Architecture (big picture)

**Three execution modes over one shared substrate**. pilot is the newer/primary direction (see `README` / memory); the deterministic pipeline is the granular/inspectable path; `redteam` is the LLM-assistant mode.

1. **`pilot` — AI-led, staged** (`packages/pilot`): `run.ts` is a **6-LLM-stage orchestrator** that calls `query()` (`@anthropic-ai/claude-agent-sdk`) **once per stage** (and once per screen in diagnosis) against an in-process MCP tool server (`createSdkMcpServer`) — deliberately bounded so the model can't elide work. Stages: **survey** (map: `browser_navigate/fill/click`, `probe_paths`, `login` → persists `Screen`s + screenshots) → **reconGuess** (predict likely routes) → **methodology** (`get_inventory`, `record_methodology` → per-screen plan) → **diagnosis** (per screen, bounded: `get_screen`, `http_request`, `analyze_session`, `record_finding`, `screen_done`, and the ~35-tool **probe catalog** — `probe_sqli`/`probe_nosql`/`probe_ssti`/`probe_cmdi`/`probe_traversal`/`probe_ssrf`/`probe_oob` (blind, via OOB provider)/`probe_xss`/`probe_dom_xss`/`probe_redirect`/`probe_cors`/`probe_proto`/`probe_jwt`/`probe_idor`/`probe_upload`/`probe_user_enum`/…) → **scenario** (A04 cross-screen logic via `probe_scenario`) → **fingerprint** (A06 tech/version → CVE). A post-diagnosis **findings-QA** pass (`findings-qa.ts` `triagePilotFindings`) is an independent second opinion — deterministic FP oracles + an **adversarial Deep-model review panel** (3 lenses, majority-demote) that demotes the agent's own weak confirmations to `[qa?]`/suspected before report. `STAGE_TOOLS` (tools.ts) gates the tools per stage via `allowedTools`. Findings **dedup** by `(category, endpoint, param)` (`dedupKey`). Model tiering: `screenIsHighValue` → `--model` (deep), the rest → `--fast-model`. **LLM backend forks** on `VERDICT_LLM_PROVIDER`: default Claude (agent SDK), or an OpenAI-compatible provider (`agent-loop.ts`, native function-calling + text-ReAct fallback). `surveyOnly`/`resume` skip stages; `--burp-proxy` routes traffic through Burp; built-in tools (Bash/Read/Write/WebFetch…) are disallowed.
2. **Deterministic pipeline** (`assess` / `crawl`→`label`→`scan`→`logic`→`report`): fixed orchestration in `packages/cli/src/main.ts` calling crawler → scanner → agent.
3. **`redteam` — LLM-assistant red-team** (`packages/llm-attacks`): drives a deployed chatbot's chat UI and confirms **canary leaks** from its protected context; re-implements the evidence discipline for stateful chat (fresh-conversation controls + replays).

**Phases joined by contract artifacts.** The main coupling point: Phase 1 (recon + labeling) writes **`screen_inventory.json`** (the `Screen` schema in `core/types/screen.ts`); Phase 2 (scan + business logic) and the WebUI only read it — keep it stable.

**Cross-cutting substrate = `@veritas/core`.** `AssessmentStore` (`state.sqlite`) is simultaneously the agent's working memory *and* the WebUI data source. It holds normalized tables (`assessments`/`screens`/`hypotheses`/`findings`/`handoffs`) plus an **append-only `events`** log; the server polls `events.seq` to push diffs to the WebUI over WS. Core also owns the scope gate, coverage ledger, budget/stop logic, site-tree/state-view projections, and `buildReport`.

**Package layering** (deps flow downward; `@veritas/core` is the only home for shared contract types):

```
apps/desktop ── Electron shell — hosts @veritas/server in-process; the PRIMARY operator entry
cli ── orchestrates everything (pilot / assess / redteam / serve …)
pilot ─ agent ─ scanner ─┐
llm-attacks ────────────┤   (llm-attacks → core+scanner)
crawler ─ llm ───────────┤
server   webui ──────────┴── core  (types + store + scope + evidence-of-record contracts)
```

- `crawler` — Playwright `PlaywrightDriver` (persistent context, XHR/fetch intercept, SPA virtual routes) + a pure pipeline (URL normalize, API shape inference, DOM-skeleton-hash dedup, rule+LLM labeling, `smartLogin`, `detectStuck`) + `pdf.ts` (report HTML→PDF **output** via Chromium `page.pdf()` — NOT a crawl input). `FakeDriver` for browserless tests.
- `scanner` — `EvidenceStore`, `FetchHttpClient` (scope-gated, conservative rate, optional `proxy` for Burp), the validator runner + catalog (`exposed_file`/`auth_required`/`cors_misconfig`), Info-level header audit (`headers.ts`/`passive.ts`), Burp XML report parsing (`burp.ts`), and the **OOB subsystem** (`oob.ts` `OobProvider` + `oob-interactsh.ts` Interactsh/OAST + `burp-oob.ts` Burp Collaborator + `oob-resolve.ts`) confirming BLIND vulns via a target callback to a unique VERDICT-issued host. **This is where evidence discipline lives.**
- `agent` — business-logic: `generateHypotheses` (LLM + rule fallback), the IDOR verifier, `authDiffScreen` (multi-role authz comparison). Reuses `scanner`'s evidence discipline.
- `llm-attacks` — LLM/AI-assistant red-team (`redteam`): Playwright-drives a chatbot UI, confirms canary leaks. Deps: core + scanner.
- `llm` — `ClaudeCliClient` (subprocess) + `OpenAiClient` (OpenAI-compatible) + `FakeLlmClient` + `makeLlmClient`/`resolveLlmConfig` (provider selection) + zod-validated structured-output helpers.
- `server`/`webui` — React 3-pane observer; webui imports `core` **types only**, built by Vite. `apps/desktop` reuses the webui `App` inside an Electron frameless window.

**Data layout** (`runs/` is gitignored): `runs/<assessment_id>/` → `state.sqlite`, `screen_inventory.json`, `artifacts/screens/<screen_id>.png` (per-screen screenshots), `artifacts/<screen_id>/<evidence_id>/` (req/resp), `report.md` (+ `report.html`/`report.pdf`/`findings.csv` from `report --format`), `browser-profile/` (persistent userDataDir — auth state lives here). The WebUI (`serve`) is one page per target: SITE TREE + progress bar + tabs (Screen / Findings / APIs / 診断ログ) with an inline evidence viewer.

### Desktop app (`apps/desktop`, `@veritas/desktop`) — the primary operator entry

An **Electron 44** shell (README banner: "Desktop-first"). The main process (`src/main.ts`) hosts **`@veritas/server` in-process** (127.0.0.1, ephemeral port) — the same server `serve` runs — and serves its own renderer build (the `@veritas/webui` `App` in a custom frameless title bar). It **spawns `@veritas/cli` as a child** (via `ELECTRON_RUN_AS_NODE`) to run assessments. An **"attended browser" tab** lets a human log in live; the captured session (`attended_session_<host>.json`, a `loadCookieFile` input) hands off to the auto-scan. A sectioned **Settings** panel configures the AI provider + Deep/Light models, the Chromium path (`VERDICT_BROWSER_PATH`), Burp, and the upstream proxy; state persists under the OS userData dir (`settings.json`, `runs/`). **No native modules** (store = `node:sqlite`, bundled in Electron's Node 22.22; browser = external `playwright-core` chromium). Dev: `pnpm --filter @veritas/desktop dev`. Package: `pnpm -r build` → `pnpm --filter @veritas/desktop deploy ./bundle` → `cd bundle && npx electron-builder --config electron-builder.yml --win` (`asar:false`; the Windows `.exe` (NSIS) is normally built by `.github/workflows/windows-build.yml` on a Windows runner — cross-building Windows on Linux needs Wine).

## Invariants (don't break these)

- **Contract types live only in `@veritas/core`.** Don't redeclare `Screen`/`Hypothesis`/`Finding`/`ScopePolicy` etc. elsewhere; import them. `webui` must stay **types-only** on core (it's bundled by Vite, not Node).
- **Evidence discipline** (`scanner`): a finding is `confirmed` only with a **negative control that fails + ≥2 positive replays that succeed**; catch-all / 0-byte-200 / unstable responses → `refuted`. `agent`, `pilot`, and `llm-attacks` all route confirmations through this — never mark `confirmed` by hand. The **OOB path** (`probe_oob`) is a distinct callback oracle but STILL rides this contract (a benign control + ≥2 positive callbacks). Pilot's post-diagnosis **findings-QA** (`triagePilotFindings`) can only **DEMOTE** (never promote) — the deterministic evidence floor stays the confirm authority, so an over-confident model can't talk a fake into `confirmed`.
- **Scope gate on every network action.** `isInScope(url, scope)` (core `scope-check.ts`) guards crawler navigation, `FetchHttpClient` (via its `allow` callback), and pilot tools. Out-of-scope returns blocked, not an exception.
- **LLM default = `claude` CLI subscription, not the metered API.** `ClaudeCliClient` runs `claude -p --output-format json --model <m>` and parses the JSON envelope (Max subscription, no per-token billing) — keep that the default. **But it is no longer the only backend:** `makeLlmClient`/`resolveLlmConfig` (`packages/llm`) fork on **`VERDICT_LLM_PROVIDER`** — `openai` selects `OpenAiClient` (an OpenAI-compatible endpoint: `VERDICT_LLM_BASE_URL`/`_API_KEY`/`_MODEL`/`_FAST_MODEL`), and pilot's `agent-loop.ts` runs the whole staged loop natively on it (function-calling + text-ReAct fallback). Never hit a real CLI/endpoint in `node:test` — use `FakeLlmClient`.
- **State is append-only + replayable.** Every state transition appends a `StateEvent` in the same transaction as the row write. The WebUI is a pure projection (`buildStateView`/`buildSiteTree`); don't mutate UI state out-of-band.
- **Auth = operator-provided material (creds OR a pre-captured cookie file).** A role is either credentials (`{name, pass}` → `smartLogin` auto-discovers the login form) OR a cookie file (`{name, cookieFile}` → `loadCookieFile` reads a raw `Cookie:` header or a Playwright `storageState` JSON, and the `login` tool injects it into the browser + http session). The cookie path is for walls the agent can't auto-login (Arkose/MFA). **The agent never fabricates or steals cookies — it only uses material the operator explicitly supplies; cookie files are secrets (gitignored).** MFA/CAPTCHA without a cookie file → `detectStuck` raises a non-blocking `HumanHandoff` (headed browser, human logs in the live profile). `roles[0]` = primary; multiple roles drive `authDiffScreen`.
- **Brand is "VERDICT" but code-internal names are intentionally kept (VERITAS→AMRAAM→VERDICT lineage).** Everything an operator sees is VERDICT: display brand, the traffic marker (`x-verdict`), the scanner UA (`verdict-scanner`), the session cookie (`verdict_session`), and the env vars **`VERDICT_WEB_PASSWORD[_VIEWER]`** / **`VERDICT_BROWSER_PATH`** (the old `AMRAAM_WEB_PASSWORD*` / `VERITAS_BROWSER_PATH` names are still accepted as **fallbacks** so existing `.env` files don't break — see `cmdServe` and the browser-path resolution in `packages/cli/src/main.ts`). But the **truly invisible code namespaces stay VERITAS/AMRAAM-era**: the package scope **`@veritas/*`**, the MCP namespace **`mcp__veritas__`** (tool prefix in `STAGE_TOOLS`/`allowedTools`), the in-page globals **`__veritasRoutes`/`__verdict_xss`**, and only the Burp extension's Java **package + maven group `com.amraam.burpaudit`** (the package path & group stay AMRAAM-era; everything else about the extension is VERDICT — display name "VERDICT Audit REST", jar `verdict-burp-audit.jar`, config `verdict-audit.properties`, env `VERDICT_AUDIT_*`). Renaming those namespaces is churn across every import/package.json/gradle with zero user benefit — don't "fix" the inconsistency.
- **Burp integration is opt-in and additive.** `--burp-proxy` and `burp-import` only act when invoked; with the flag off, behaviour is byte-identical (the `undici` ProxyAgent is lazy-imported only when a proxy is set). Keep it that way.

## TypeScript strictness gotchas

`tsconfig.base.json` is strict in ways that bite: `verbatimModuleSyntax` (type-only imports **must** use `import type`), `noUncheckedIndexedAccess` (array/record access is `T | undefined` — narrow it), `isolatedModules`, `noUnusedLocals`/`noUnusedParameters`, `noFallthroughCasesInSwitch`. ESM `NodeNext` resolution → relative imports need the **`.js`** extension even from `.ts` sources.

No linter/formatter is configured. Match nearby code: ESM, 4-space-ish existing style, kebab-case filenames, PascalCase types, camelCase functions. Comments and code are English (the codebase was historically bilingual with Japanese comments — that has been translated to English; keep new comments English). Note: some LLM-facing prompt/tool-`description:` strings in `packages/pilot/src` (`system.ts`, `tools.ts`) may still be Japanese by design — those are model inputs, not on-screen text; leave them unless asked.
