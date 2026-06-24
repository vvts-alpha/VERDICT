<div align="center">

# AMRAAM 🚀

### Autonomous web / API pentest agent

**AI drives · evidence proves · scans _behind_ login.**

A Claude-led agent that maps your target, hunts vulns with strict evidence discipline,
drives Burp for breadth, and reaches the authenticated surface other tools miss.

![Node](https://img.shields.io/badge/Node-%E2%89%A5%2024-339933?logo=nodedotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-strict-3178C6?logo=typescript&logoColor=white)
![LLM](https://img.shields.io/badge/LLM-Claude%20(CLI%20sub)-D97757?logo=anthropic&logoColor=white)
![Playwright](https://img.shields.io/badge/Browser-Playwright%20chromium-2EAD33?logo=playwright&logoColor=white)
![tests](https://img.shields.io/badge/tests-passing-success)
![status](https://img.shields.io/badge/status-active-blue)

[Quickstart](#-quickstart) · [How it works](#-how-it-works) · [Why AMRAAM](#-why-amraam) · [Burp](#-burp-integration) · [WebUI](#-webui)

</div>

---

> ⚠️ **Authorized testing only.** Every network action passes a scope gate; out-of-scope is denied, not attempted.

AMRAAM runs a real browser and a scoped HTTP client through tools that **Claude operates** — survey → methodology → diagnosis → (multi-step logic) → (Burp) → report. It is **staged on purpose** so the model can't "skim and skip", and **evidence-disciplined** so a finding is `confirmed` only when it actually reproduces. Everything streams to a live WebUI.

## ✨ Features

- 🧠 **Claude-led, staged** — survey → methodology → per-screen diagnosis. Bounded queries stop the model from eliding work.
- 🔬 **Evidence discipline** — `confirmed` requires a negative control that fails **+ ≥2 stable positive replays**. Catch-all 200s / flaky responses are auto-refuted. FP reduced *by construction*.
- 🔐 **Scans behind login** — Bearer-JWT propagation + a Burp extension that takes the **authenticated request itself**, so the auth surface (the crown jewels) actually gets tested.
- 🧩 **A04 multi-step logic** — a dedicated scenario stage chains requests across endpoints (coupon stacking, negative-qty checkout, mass-assignment) with a differential oracle.
- 🤝 **AI depth × Burp breadth** — the agent owns IDOR / authz / business-logic; Burp owns injection breadth. Imports are de-duped and **AI re-verified**.
- ✅ **Coverage gate** — `screen_done` must account for every planned attack class — no "find one, move on".
- 🛰 **Confirmation oracles** — `probe_xss` / `probe_redirect` / `probe_jwt` (alg:none) turn "looks suspicious" into evidence.
- 🖥 **Observe + launch UI** — a 3-pane React app projects an append-only event log: SITE TREE, screenshots, findings, evidence viewer, live diagnostic log. Launch & control runs from the browser.
- 🧾 **Reports** — Markdown / HTML / PDF / CSV + a screen inventory + an OpenAPI spec of everything it discovered.
- 🛡 **Safe by design** — operator-provided auth only (never fabricated), never auto-hits logout, secrets redacted in evidence, LLM on a subscription (no metered API).

## 🚀 Quickstart

```bash
# requirements: Node >= 24 (builtin node:sqlite), pnpm via corepack, a chromium binary
corepack enable pnpm
pnpm install && pnpm -r build
npx playwright install chromium          # or pass --browser-path <bin>

# 1) observability UI (separate terminal) → http://127.0.0.1:4317
node packages/cli/dist/main.js serve

# 2) a Claude-led assessment from a single URL …
node packages/cli/dist/main.js pilot --url https://app.example.com/

# … or from a scope + auth manifest (recommended)
node packages/cli/dist/main.js pilot --manifest scope.json
```

Generate a manifest interactively with `node packages/cli/dist/main.js init`. Findings, screenshots, APIs and the diagnostic log fill the WebUI live; `runs/<id>/report.md` is written at the end.

> 🧪 Dev mode (no build): `pnpm --filter @veritas/cli dev <command>` resolves `src` directly.

## 🔍 How it works

Two phases joined by one contract (`screen_inventory.json`): **recon + labeling** writes it, **scan + logic** and the WebUI read it.

```mermaid
flowchart LR
    A[🗺 Survey<br/>map screens + APIs<br/>incl. HTML form POSTs] --> B[📋 Methodology<br/>per-screen attack plan]
    B --> C[🔬 Diagnosis<br/>1 screen = 1 bounded query<br/>coverage gate]
    C --> D[🧩 Scenario A04<br/>multi-step logic abuse]
    D --> E[🐝 Burp scan<br/>authenticated · de-dup · re-verify]
    E --> F[📄 Report<br/>md · html · pdf · csv · openapi]
    C -.evidence discipline.-> C
```

Each stage is a **single `query()`** with a tool allow-list, so the model works one bounded context at a time. Model tiering routes high-value screens to a deep model (e.g. Opus) and survey / static screens to a fast one (e.g. Sonnet). `--survey-only` / `--resume` / `--attended` adjust the flow.

## 🧠 Why AMRAAM

| | What others do | What AMRAAM does |
|---|---|---|
| **Coverage** | "scan the site" → the model skims and skips | Stages + a coverage gate make completeness a *contract*, not luck |
| **False positives** | a pile of maybe-bugs to triage | `confirmed` is only set after a failing control + ≥2 stable replays |
| **Authenticated surface** | scanner can't carry the session → 401s | session **in the request** (Burp Audit REST) + Bearer propagation |
| **Breadth vs depth** | one tool, one tradeoff | AI depth (IDOR/authz/logic) × Burp breadth (injection), merged + re-verified |
| **Ground truth** | rely on Burp's lossy auto-discovery | AMRAAM holds the auth + every param and **declares** them (OpenAPI / raw requests) |
| **Overfitting** | hardcoded heuristics | standard techniques + LLM judgement — no app-specific vocabulary baked in |

## 🛠 Commands

```bash
node packages/cli/dist/main.js <command> [options]      # after pnpm -r build
```

| Command | Purpose |
|---|---|
| **`pilot`** | Claude-led assessment. `--manifest`/`--url`, `--model` (+ `--fast-model` tiering), `--max-turns`, `--max-screens`, `--rate`, `--headed`, `--burp-proxy [url]`, `--burp-scan`, `--login-url`, `--keepalive-min <n>` |
| `pilot --survey-only` | Map only (screens + screenshots + APIs); diagnose later with `--resume`. |
| `pilot --resume --id <id>` | Continue an existing run (diagnose the still-queued screens). |
| `pilot --attended[ a,b,c]` | Manual multi-session login (MFA/CAPTCHA): a headed window per role, log in by hand, diagnose on the live session. |
| `assess` | Deterministic one-shot: crawl → label → scan → logic → report. |
| `serve` | Observability WebUI + state API/WS (`127.0.0.1:4317`; `--host 0.0.0.0` + `--password` to expose). |
| `init` / `manifest` | Interactive scope-manifest generator. |
| `report` / `inventory` / `openapi` | Export report (md/html/pdf/csv) / screen inventory / OpenAPI of the discovered surface. |
| `burp-scan` / `burp-import` | Active Burp scan via REST → merge net-new / import a Burp XML report. |
| `header-audit` | Info-level security-header checks. |

## 🎛 Scope & auth (manifest)

```jsonc
{
  "target": "https://app.example.com/",
  "scopeMode": "etld",                 // same-origin | etld | unrestricted
  "scope": { "outOfScopePathPrefixes": ["/logout"] },
  "http":  { "headers": { "X-Forwarded-For": "127.0.0.1" } },  // WAF bypass / required headers
  "auth": {
    "httpBasic": { "user": "u", "pass": "p" },                 // site-wide Basic/Digest
    "roles": [
      { "name": "admin", "pass": "…", "description": "full admin" },
      { "name": "alice", "cookieFile": "alice.cookies" }       // pre-captured session (MFA walls)
    ]
  }
}
```

**Auth = operator-provided material only.** Credentials → `smartLogin` auto-discovers the form. A cookie file → injected as-is (for walls the agent can't auto-login). MFA/CAPTCHA without a cookie file → `--attended` (human logs into a live headed session). **The agent never fabricates or steals cookies**, and **never auto-hits logout** (it would kill the session). `roles[0]` is primary; multiple roles drive multi-role authz diff.

## 🐝 Burp integration

Opt-in and additive — with the flags off, behaviour is byte-identical. Connection via `.env` (auto-loaded) or args.

```bash
# proxy — route all traffic through Burp (auth'd traffic accumulates in Burp)
node packages/cli/dist/main.js pilot --manifest m.json --burp-proxy

# active scan after diagnosis → merge net-new → AI re-verify High+
node packages/cli/dist/main.js pilot --manifest m.json --burp-scan       # standard REST (1337), unauth crawl+audit

# 🔐 authenticated active scan (recommended) — AMRAAM Audit REST extension (port 1338)
export BURP_AUDIT_API=http://127.0.0.1:1338 BURP_AUDIT_TOKEN=<secret>
node packages/cli/dist/main.js pilot --manifest m.json --burp-scan       # → routes through the extension automatically
```

The standard REST API can't pass a session to a scan. The **[`tools/burp-audit-ext/`](tools/burp-audit-ext/) Montoya extension** sidesteps that: AMRAAM submits the **authenticated raw request itself** (cookie + Bearer baked in), so Burp audits *behind login*, with no crawl explosion. `BURP_AUDIT_API` flips `--burp-scan` onto this path; otherwise it falls back to the standard REST. Build it with `gradle shadowJar` and load the jar in Burp.

> **Division of labour:** the agent = emergent logic (IDOR chains, mass-assignment, business logic); Burp = mechanical injection breadth (A03 SQLi/XSS) + passive. Overlap is de-duped; imported High+ findings are re-tested by the agent.

## 🖥 WebUI

One target = one page. Left: **SITE TREE** (URL hierarchy + scan badges). Top: progress bar. Right tabs: **Screen** (screenshot + APIs + findings), **Findings** (filter + inline evidence viewer), **APIs**, **Diagnostic log** (live), **💬 Ask** (read-only Q&A over the assessment).

From `/` (the **projects list**) you can **launch and control runs**: **+ New** opens a full manifest editor — target, scope mode, model tiering, **custom headers** (name/value), **login URL**, **target-URL list import** (CSV / one-per-line), **max screens**, HTTP Basic, auth roles — and the server spawns the CLI as a child process. Stop / Resume per run. Expose with `--host 0.0.0.0` **and** `--password` / `AMRAAM_WEB_PASSWORD`.

## 🎯 Detection coverage

OWASP-mapped: **A01** access control (IDOR/BOLA, auth-bypass) · **A03** injection (SQLi, reflected XSS, path-traversal) · **A04** business logic (price/qty tampering, mass-assignment, workflow bypass) · **A07** auth (JWT alg:none / claim tampering, predictable cookies) · **A10** SSRF / open-redirect · plus info-disclosure and header audit. Deep payload breadth (XSS variants, SSTI, desync) is delegated to **Burp**; AMRAAM imports and re-verifies.

## ⚙️ Setup & requirements

- **Node.js ≥ 24** (mandatory — the state store uses builtin `node:sqlite`). `nvm use 24`.
- **pnpm** via corepack (`corepack enable pnpm`).
- **Chromium** for Playwright: `npx playwright install chromium`, or `--browser-path <bin>` / `VERITAS_BROWSER_PATH`. In containers add `--no-sandbox`.
- **LLM = the `claude` CLI** (subscription auth) — no `ANTHROPIC_API_KEY`, no metered billing.

```bash
pnpm install
pnpm -r build        # tsc per package (+ Vite for webui)
pnpm -r test         # node:test via tsx (FakeDriver / FakeHttpClient / FakeLlmClient — no network/LLM)
```

`.env` (repo root, auto-loaded; shell `export` wins; gitignored): `VERITAS_BROWSER_PATH`, `BURP_API`, `BURP_PROXY`, `BURP_RESOURCE_POOL`, `BURP_AUDIT_API`, `BURP_AUDIT_TOKEN`.

## 🧩 Architecture

TypeScript monorepo; dependencies flow downward; contract types live only in `@veritas/core`.

```
cli ── orchestrates everything
pilot ─ agent ─ scanner ─┐
crawler ─ llm ───────────┤
server   webui ──────────┴── core   (types · SQLite store · scope gate · evidence discipline · projections · OpenAPI)
```

`AssessmentStore` (`state.sqlite`) is the agent's working memory **and** the WebUI's data source: normalized tables + an **append-only event log** the server polls to push WS diffs. The WebUI is a pure projection. `tools/burp-audit-ext/` is a standalone Java/Montoya Burp extension.

## 🛡 Safety & invariants

- **Scope gate on every network action** — `isInScope(url, scope)` is deny-first; out-of-scope returns blocked, not an exception.
- **Evidence discipline** — confirmed needs a failing control + ≥2 stable replays; nothing is marked confirmed by hand.
- **Auth is operator-provided** — creds or a cookie file; never fabricated or stolen; cookie files are secrets (gitignored).
- **Never auto-logout** — the agent must not hit logout/signout (it destroys the session).
- **Append-only, replayable state** — every transition appends an event in the same transaction.
- **LLM = `claude` CLI subscription**, not the metered API.

---

<div align="center">

**AMRAAM** — autonomous · evidence-disciplined · authenticated-deep web/API pentest.

</div>
