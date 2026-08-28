# VERDICT — Operator Usage Guide

This is the **how-to**. The [README](../README.md) is the overview (what VERDICT is, why, benchmarks); this
walks a real engagement from an empty directory to a signed-off report — and, more importantly, tells you **what
to do at each fork**: which auth tier to reach for, what to do when a WAF blocks you, how to run recon-first and
resume, how to point it at a pure-API target.

Read §3 (Authentication) before your first authenticated run — it is where most engagements actually get stuck.

---

## 0. Install once

Node **≥ 24** is mandatory (the state store uses builtin `node:sqlite`).

```bash
nvm use 24                               # if you juggle Node versions
corepack enable pnpm                     # pnpm@9.15.4 is pinned
pnpm install && pnpm -r build            # tsc per package (+ Vite for the webui)
npx playwright install chromium          # or supply your own: --browser-path <bin>
```

Optional `.env` at the repo root (auto-loaded, gitignored) — browser path, Burp endpoints, WebUI passwords:

```bash
VERDICT_BROWSER_PATH=/path/to/chromium   # instead of --browser-path each run
BURP_AUDIT_API=http://127.0.0.1:1338     # authenticated Burp scan (see §6)
BURP_AUDIT_TOKEN=<secret>
```

**Smoke-test** the install before pointing it at anything real:

```bash
node packages/cli/dist/main.js serve                              # → http://127.0.0.1:4317
node packages/cli/dist/main.js pilot --url https://example.com/ --survey-only   # maps, no attacks
```

Every command below is `node packages/cli/dist/main.js <cmd>`. During development, skip the build with
`pnpm --filter @veritas/cli dev <cmd>` (resolves `src` directly).

---

## 1. The shape of a run

```
manifest (scope + auth)  →  pilot  →  live WebUI  →  report
                             │
              survey ─→ methodology ─→ diagnosis ─→ scenario (A04) ─→ (Burp) ─→ report
              (map)     (per-screen    (1 screen =   (multi-step
                         attack plan)   1 bounded     logic abuse)
                                        query)
```

Everything a run produces lives under `runs/<assessment_id>/` (gitignored):

| Path | What |
|---|---|
| `state.sqlite` | the agent's working memory **and** the WebUI's data source (append-only event log) |
| `screen_inventory.json` | the Phase-1→Phase-2 contract (screens + APIs) |
| `artifacts/screens/<id>.png` | per-screen screenshots |
| `artifacts/<screen>/<evidence>/` | raw request/response for every finding |
| `report.md` | written at the end (also export html/pdf/csv) |
| `browser-profile/` | the persistent browser profile — **your auth session lives here** |

Keep the WebUI (`serve`) open in a second terminal the whole time — progress, findings, screenshots and the
diagnostic log stream in live. You do not have to watch the terminal.

---

## 2. Scope a target (the manifest)

`--url` works for a quick look (scope = same-origin + that path prefix), but a **manifest is the real entry point**
— it carries scope *and* auth. Generate one interactively:

```bash
node packages/cli/dist/main.js init            # prompts for target / scope / rate / model / auth → writes a JSON
```

Or hand-write it:

```jsonc
{
  "target": "https://app.example.com/",
  "scopeMode": "etld",                          // same-origin | etld | unrestricted
  "scope": { "outOfScopePathPrefixes": ["/logout", "/signout"] },
  "http":  { "headers": { "X-Bypass-Token": "…" } },   // edge / WAF bypass or engagement-mandated headers
  "auth": {
    "httpBasic": { "user": "u", "pass": "p" },          // optional site-wide Basic/Digest
    "roles": [
      { "name": "admin", "pass": "…", "description": "full admin" },
      { "name": "alice", "cookieFile": "alice.cookies" }
    ]
  }
}
```

**`scopeMode`** — pick the tightest that covers the target:

| mode | in-scope | use when |
|---|---|---|
| `same-origin` | exactly the target origin | single SPA/host, don't wander |
| `etld` | the registrable domain (all subdomains) | app + `api.` + `auth.` on one eTLD+1 |
| `unrestricted` | anything (still deny-listed) | multi-domain engagement — **only with explicit authorization** |

Always list logout/signout under `outOfScopePathPrefixes` (or rely on the built-in guard) — the agent must never
hit them, they destroy the session. The scope gate is deny-first on **every** network action; out-of-scope returns
*blocked*, never an exception.

---

## 3. Authentication — the decision tree

Most engagements live or die here. VERDICT has **three auth tiers plus a WAF playbook**. Reach for the *lowest*
tier that clears the wall.

### Tier 1 — credentials (`smartLogin`)

Plain form logins. Put `{name, pass}` in a role; `smartLogin` auto-discovers the login form and submits.

```jsonc
"roles": [ { "name": "admin", "pass": "hunter2" } ]
```

Nothing else to do — the run logs in and proceeds. If the form is unusual, add `--login-url <url>` to point it
straight at the login page.

### Tier 2 — a pre-captured cookie file

When auto-login **can't** clear the wall (MFA, Arkose, a bespoke SSO form) but you *can* log in by hand once,
capture the session in **your own everyday browser** and hand VERDICT the result:

```jsonc
"roles": [ { "name": "alice", "cookieFile": "alice.cookies" } ]
```

`alice.cookies` is either a raw `Cookie:` header (`a=1; b=2`) or a Playwright `storageState` JSON — VERDICT
auto-detects and injects it into both the browser and the raw-HTTP client. **The agent never fabricates or steals
cookies** — it only uses material you explicitly supply. Cookie files are secrets; keep them gitignored.

> Match the exporting browser's **User-Agent** (and run from the **same egress IP**) when the site binds sessions
> to them — see the WAF note below for why.

### Tier 3 — attended login (SSO / MFA / CAPTCHA, cleared by hand, live)

For Microsoft/Okta SSO, TOTP, or a CAPTCHA you must solve interactively: **you** do exactly the login, the **agent**
does everything after. VERDICT holds one real browser per role and inherits each session once you're in.

```bash
node packages/cli/dist/main.js pilot --manifest m.json --attended admin,user1
```

Each role opens a headed window; log in, press Enter at the terminal for each. Or drive it from the WebUI: set each
role to **manual (Sessions tab)** in the New form — a live screencast of the target's login page renders inside the
WebUI and your mouse/keyboard/paste are relayed over CDP. Click **Done (logged in)** and the agent takes over.

> The screencast drives the target's *own* login page. A login that spawns a **separate OAuth pop-up** or an
> **OS file-picker/dialog** is the known limit of the WebUI path — use the headed CLI (`--attended`) there, where
> you're on the real OS window.

### The WAF / Cloudflare wall — the honest playbook

A **Cloudflare Managed Challenge / Turnstile** (or Akamai/DataDome equivalent) is a different problem from a login,
and it is worth stating plainly:

> **You cannot reliably drive an automated browser through a Managed Challenge — not even by solving it by hand in
> VERDICT's window.** The challenge fingerprints `navigator.webdriver`, the CDP session, and the TLS/HTTP2
> handshake (JA3/JA4) — all of which read as automation regardless of a realistic User-Agent — so it re-issues the
> challenge and never clears. This is not a VERDICT limitation; every automation stack (Burp/ZAP/nuclei) hits it.

You don't beat it, you **go around it**. In priority order:

1. **Client-provided bypass — the professional path.** On an authorized engagement the client can allowlist your
   **egress IP** at the edge, or give you an **edge-bypass header** the WAF checks before challenging. Put that
   header in the manifest and it rides every request:
   ```jsonc
   "http": { "headers": { "X-Bypass-Token": "<client-supplied>" } }
   ```
   Fighting the WAF isn't the engagement's goal anyway — the vulnerabilities behind it are.

2. **`cookieFile` from your real browser** (Tier 2) — works cleanly when the site **only challenges at the edge/login**
   and then runs on a portable app-session cookie. Log in in your normal browser (it passes the challenge
   natively), export the session, and **match VERDICT's `userAgent` + egress IP** to what obtained it — a
   `cf_clearance` cookie is bound to UA + IP and is rejected if replayed from a mismatched client.

3. **Out of scope, documented.** If the site puts a **fingerprint-bound challenge on every request** and the client
   won't provide a bypass, no cookie-replay approach can work from a different client. Record it as a known
   limitation in the handoff and move on — do **not** burn the engagement trying to defeat it.

> **Do not** try to "stealth" your way through with a patched `navigator.webdriver` or a spoofed channel. It fixes
> JS-level tells but not the TLS fingerprint, so it fails against a Managed Challenge and gives you false confidence.

### Multi-role

`roles[0]` is the primary session; supplying more than one drives **authz diff** — the agent replays a lower-privilege
role against a higher-privilege screen to catch broken access control (IDOR/BOLA). Name the roles you want attended
inline: `--attended admin,user1,user2`.

---

## 4. Run it

### Full run

```bash
node packages/cli/dist/main.js serve                          # terminal 1 — WebUI
node packages/cli/dist/main.js pilot --manifest m.json        # terminal 2 — the assessment
```

Watch it in the WebUI: SITE TREE fills as it surveys, the progress bar tracks the stages, findings and the
diagnostic log stream in live. `report.md` lands in `runs/<id>/` at the end.

### Recon first, diagnose later

Cheap map now, expensive diagnosis when you're ready:

```bash
node packages/cli/dist/main.js pilot --manifest m.json --survey-only   # map screens + APIs + screenshots only
node packages/cli/dist/main.js pilot --resume --id <id>                # later: diagnose the still-queued screens
```

`--resume` reuses the run's `browser-profile/`, so an authenticated survey stays authenticated on resume.

### Knobs worth knowing

| Flag | Effect |
|---|---|
| `--model` / `--fast-model` | model tiering — deep model for high-value screens, fast model for survey/static |
| `--max-screens <n>` | cap breadth (large apps / time-boxed runs) |
| `--max-turns <n>` | cap the per-stage tool budget |
| `--rate <n>` | global request spacing (be gentle on fragile targets) |
| `--headed` | watch the real browser (debugging auth/nav) |
| `--keepalive-min <n>` | touch the top page every *n* min to keep an authed session warm (default 4; `0` = off) |

If a session dies mid-run (absolute-TTL expiry, server-side logout), the agent raises a handoff rather than
thrashing — re-auth (Tier 2/3) and `--resume`. **Stop / Resume** are also available per-run from the WebUI.

---

## 5. API-only targets (no web UI)

Hand VERDICT an OpenAPI 3.x / Swagger 2.0 spec and it tests **every declared endpoint** behind a Bearer — no
browser required. Put the token in the manifest (`http.headers.Authorization` or an `auth` role), then:

```bash
node packages/cli/dist/main.js spec-import --spec swagger.json --url https://api.example.com   # seed the surface
node packages/cli/dist/main.js scan  --id <id> --manifest m.json                                # deterministic scan
node packages/cli/dist/main.js logic --id <id> --manifest m.json                                # multi-step logic
node packages/cli/dist/main.js report --id <id>
```

`scan`/`logic` are browser-free and take `--manifest` so the Bearer/cookie reaches token-protected endpoints. To
reach endpoints the **UI never calls**, overlay the spec on an existing crawl: `spec-import --id <run> --spec …`
merges net-new paths into that run.

---

## 6. Burp — mechanical breadth (optional, additive)

With the flags off, behaviour is byte-identical. Division of labour: the **agent** owns emergent logic
(IDOR chains, mass-assignment, business logic); **Burp** owns injection breadth (A03 SQLi/XSS) + passive. Overlap
is de-duped and imported High+ findings are AI re-verified.

```bash
# route all traffic through Burp (auth'd traffic accumulates there)
node packages/cli/dist/main.js pilot --manifest m.json --burp-proxy

# active scan after diagnosis → merge net-new → re-verify
node packages/cli/dist/main.js pilot --manifest m.json --burp-scan          # standard REST (unauth crawl+audit)

# authenticated active scan (recommended) — VERDICT Audit REST extension
export BURP_AUDIT_API=http://127.0.0.1:1338 BURP_AUDIT_TOKEN=<secret>
node packages/cli/dist/main.js pilot --manifest m.json --burp-scan          # submits the authenticated request itself
```

The standard REST API can't pass a session to a scan; the [`tools/burp-audit-ext/`](../tools/burp-audit-ext/)
Montoya extension does — VERDICT submits the authenticated raw request (cookie + Bearer baked in), so Burp audits
*behind login* with no crawl explosion. Build with `gradle shadowJar`, load the jar in Burp. You can also
`burp-import --id <id> --report <xml>` to merge an existing Burp XML report.

---

## 7. Output

```bash
node packages/cli/dist/main.js report    --id <id>            # report.md (default) — also html/pdf/csv
node packages/cli/dist/main.js inventory --id <id>            # the screen inventory
node packages/cli/dist/main.js openapi   --id <id>            # OpenAPI spec of everything it discovered
node packages/cli/dist/main.js status    --id <id>            # phase / coverage / stop condition
node packages/cli/dist/main.js list                          # all runs
```

Every finding carries its evidence — the failing negative control and ≥2 positive replays with raw
request/response — visible inline in the WebUI (Findings tab) and in the report. The WebUI **💬 Ask** tab answers
read-only questions over the finished assessment.

---

## 8. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `node:sqlite` / build errors | Node < 24. `nvm use 24`, rebuild. |
| "browser not found" | `npx playwright install chromium`, or `--browser-path` / `VERDICT_BROWSER_PATH`. In containers add `--no-sandbox`. |
| CAPTCHA / Cloudflare loop, even by hand | Managed Challenge — see §3 WAF playbook. Don't drive through it; use a client bypass header / `cookieFile` / document as out-of-scope. |
| 401s everywhere mid-run | session expired. Re-auth (Tier 2/3) and `--resume --id <id>`; consider `--keepalive-min`. |
| Everything "blocked" | scope too tight — check `scopeMode` and the target host; the gate is deny-first by design. |
| Run stalls on a login pop-up | OAuth pop-up / OS dialog is the screencast limit — use `--attended` (headed CLI) for that role. |

---

**Authorized testing only.** Every network action passes the scope gate; out-of-scope is denied, not attempted.
Auth is operator-provided material only — never fabricated. The agent never auto-hits logout.
