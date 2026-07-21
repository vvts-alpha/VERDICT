#!/usr/bin/env node
// @veritas/cli — DESIGN §11 / §12 M0.
// Creates an assessment and writes runs/<id>/state.sqlite (+ observe via status / list).
// The crawl/scan bodies are later milestones. This is a thin front over the state store.

import { parseArgs } from "node:util";
import { createRequire } from "node:module";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { lookup, resolve4, resolveCname } from "node:dns/promises";

import {
  AssessmentStore,
  buildReport,
  buildReportModel,
  buildOpenApi,
  renderMarkdown,
  renderReportHtml,
  renderFindingsCsv,
  renderScreensCsv,
  renderInventoryHtml,
  coverage,
  type EvidenceLoader,
  deriveScopeFromSingleUrl,
  deriveScopeFromUrls,
  evaluateStop,
  isInScope,
  newAssessmentId,
  parseTargetUrl,
  type AssessmentState,
  type Asset,
  type AssetBand,
  type Screen,
  type ScopeMode,
  type ScopePolicy,
  type TargetInput,
} from "@veritas/core";
import { PlaywrightDriver, buildInventory, crawl, exploreScreen, htmlToPdf, labelInventory, normalizePath, parseOpenApiToScreens, smartLogin, writeScreenInventory } from "@veritas/crawler";
import type { LoginCreds } from "@veritas/crawler";
import { ClaudeCliClient } from "@veritas/llm";
import { EvidenceStore, FetchHttpClient, SECURITY_HEADERS, auditHeaders, parseBurpReport, pickBurpConfigs, readEvidenceArtifact, scanInventory, startBurpScan, getBurpScan, dedupSeedUrls, submitAudit, getAuditStatusAll, getAuditIssues, resetAudit, buildRawRequest, mergeBurpIssues as scannerMergeBurpIssues, triageBurpInfo, formatBurpLeads } from "@veritas/scanner";
import type { BurpAuditConn } from "@veritas/scanner";
import type { BurpIssue } from "@veritas/scanner";
import { assessLogicInventory, assessScreenLogic, authDiffScreen } from "@veritas/agent";
import type { RoleContext } from "@veritas/agent";
import { runPilot, verifyBurpFindings, triageAndDeepDiveBurp, LiveControl } from "@veritas/pilot";
import { BrowserChatAdapter, runLlmRedteam, defaultInjectedContextProbes, generateCanary } from "@veritas/llm-attacks";
import { discoverCrtSh, fetchHttpGet, primarySourceFailureAction, filterInScope, mergeCandidates, orderCandidatesForProbe, importRecon, execFileRunTool, subfinderDiscover, dnsxBrute, dnsxReachable, nativeBrute, DEFAULT_SUBDOMAIN_WORDLIST, parseWordlist, probeHost, probeSurface, enumerateListing, detectTakeover, reconFindings, scoreAsset, triageAsset, buildAssetInventory, writeAssetInventory, readAssetInventory } from "@veritas/asr";
import type { HostCandidate } from "@veritas/asr";
import { runFromAsr, spawnPilotLauncher } from "./from-asr.js";
import type { AsrScopePins } from "./from-asr.js";
import { startServer } from "@veritas/server";
import { loadDotEnv } from "./dotenv.js";

const RUNS_DIR_DEFAULT = "runs";

const USAGE = `veritas <command> [options]

commands:
  manifest [--out <file.json>] [--force]   (alias: init)
            interactive scope-manifest generator: answer the prompts to produce the JSON pilot/assess read
            (target / in·out-of-scope hosts·path / rate / crawl / model / auth roles. password echo is masked)
  pilot   --manifest <file.json> | --url <url> [--model <m>] [--fast-model <m>] [--max-turns <n>] [--max-screens <n>] [--max-survey-screens <n>] [--rate <ms>] [--headed] [--focus "<text>"] [--browser-path <bin>] [--browser-channel <name>] [--no-sandbox] [--out <dir>]
            --max-screens caps how many screens get diagnosed (default 40); --max-survey-screens caps how many the survey maps (default unlimited — stops exploring once reached)
            ★Claude-led: Claude drives the tools (browser/http/login/record) to autonomously explore, verify, and record
            --focus "<text>": operator emphasis injected as the TOP priority of the A04 scenario stage (not per-screen diagnosis). e.g. "focus on the payment flow and IDOR in /api/orders"
            uses the manifest's auth.roles via the login(role) tool. more flexible than the deterministic pipeline (no metered API / Max subscription)
            --fast-model enables model tiering: survey/methodology/login and low-value screens on fast, only high-value screen diagnosis on --model (e.g. --model opus --fast-model sonnet)
            after per-screen diagnosis, a SCENARIO stage (deep model) hunts multi-step A04 business-logic abuse across endpoints (coupon/price/qty tampering, step-skip, mass-assignment) — auto-skipped if no transactional surface. [--no-scenario] disables it. the stage also always runs built-in default scenarios (e.g. credential/secret hunting); [--no-default-scenarios] keeps A04 but drops those. [--focus "<text>"] adds an operator objective on top. after that, a FINGERPRINT stage (A06) collects tech/version banners (server, middleware, frontend libs) and flags components with known CVEs; [--no-fingerprint] skips it. [--cve-lookup] (opt-in, external egress) queries online CVE DBs — OSV.dev by exact version for libraries, NVD by keyword for servers/middleware — for authoritative CVE ids instead of model knowledge.
  pilot --survey-only --manifest <file.json> | --url <url> [...]
            survey only: maps screens + screenshots + API extraction only, no diagnosis/findings (cheap recon. diagnose later with --resume)
            ※ by default, during survey the model dynamically prunes low-value CMS content trees etc. via ignore_paths (curbs frontier explosion).
              add [--exhaustive] to disable pruning and extract every screen (= full survey mode).
  pilot --resume --id <id> [--manifest <file.json>] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
  pilot --from-asr <asr-id|asset_inventory.json> [--from-asr-top <n>] [--from-asr-band critical|high|medium|low] [--from-asr-concurrency <n>] [--out <dir>]
            continue an existing run: skip survey/methodology, diagnose only undiagnosed (queued) screens (finish a crashed run)
  pilot --attended[ a,b,c] (--manifest <file.json> | --url <url>) [--login-url <u>] [--keepalive-min <n>] [...]
            manual multi-session auth (headed required): opens a persistent context per role for a human to log in (clear CAPTCHA/MFA/Arkose)
            → Enter to confirm → explore/diagnose on the live session. diagnosis uses per-role live cookies and keeps sessions warm between screens (re-login requested on expiry)
            roles can be given inline via --attended admin,userA,userB (no manifest needed / overrides). bare --attended uses the manifest's auth.roles
            ※ Burp integration (env by default, overridable by args): [--burp-proxy [url]] route all traffic through Burp (env BURP_PROXY if no value).
              [--burp-scan [--burp-api url]] after diagnosis, also run a Burp active scan against the same run → merge results → AI re-verifies the High+ imports (connection via env BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL). both off by default. [--no-burp-verify] skips the verify phase.
                 ※ set env BURP_AUDIT_API=http://<host>:1338 (+ BURP_AUDIT_TOKEN) to route --burp-scan through the VERDICT Audit REST extension instead: it submits the AUTHENTICATED raw requests (session in the request) so it scans behind login — see tools/burp-audit-ext/.
  burp-scan --id <id> [--burp-api <url>] [--api-key <key>] [--config "<named config>"]... [--resource-pool <name>] [--manifest <m.json>] [--max-min <n>] [--poll <sec>] [--no-burp-verify] [--model <m>] [--out <dir>]
            launch a Burp Pro active scan via its REST API → poll to completion → import issues (no XML export needed) → AI re-verifies the High+ imports. connection via env (BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL) → overridable by args.
            target URLs = the in-scope screens the AI mapped for that run (= the AI decides the targets). checks/speed = Burp's named config.
            --config can be given multiple times (stack crawl speed + audit checks). scan speed is set by Burp's crawl strategy preset:
              e.g.) --config "Crawl strategy - fastest" --config "Audit checks - critical issues only"  (fast)
                  --config "Crawl strategy - most complete" --config "Audit checks - all except time-based detection methods"  (thorough, slow)
              with NO --config, the profile is auto-selected from the mapped surface (size → crawl strategy, scale → audit depth);
              --config overrides it. the integrated --burp-scan flag (pilot/assess, WebUI) also auto-selects.
            speed/throttle = Burp's Resource pool (max concurrent requests · inter-request delay). REST can't hold ms as a number, only references pools by name.
              defaults to the "250ms" pool (create it in Burp: Settings → Resource pool → Add → concurrency 1 / Delay 250ms).
              if absent, auto-continues on Burp's default pool (prints how to create one). override with --resource-pool <name>, --resource-pool "" for Burp's default.
            pass --manifest credentials for an authenticated scan. API key via --api-key or env BURP_API_KEY. Burp Pro's REST API must be enabled.
  burp-import --id <id> --report <burp.xml> [--manifest <m.json>] [--no-burp-verify] [--no-burp-triage] [--model <m>] [--out <dir>]
            import a Burp Pro XML report, adding only net-new issues that don't duplicate existing findings, then AI re-verifies the High+ imports (--no-burp-verify to skip). after that, a triage phase shows the model the sub-High lead titles (reflected-input→XSS, external-interaction→SSRF, loose CORS…), it picks the promising ones, and only those are deep-dived with the same evidence discipline (--no-burp-triage to skip just this phase). integration is flag-driven / optional.
  assess  --manifest <file.json> | --url <url> [--login-url <u>] [--login-wait <s>] [--no-label] [--no-logic] [--no-explore] [--browser-path <bin>] [--no-sandbox] [--model <m>] [--out <dir>]
            one-shot run (deterministic pipeline): crawl → label → scan → logic → report in a single command
            --login-url opens a headed browser and waits for login (password entered by hand, never injected)
  run     --url <url> [--follow] [--max-depth <n>] [--out <dir>]
            create an empty assessment for an authorized target and write runs/<id>/state.sqlite
  crawl   --url <url> | --id <id> [--follow] [--max-depth <n>] [--headed] [--login-url <u>] [--login-wait <s>] [--out <dir>]
            Phase1: crawl + intercept with Playwright → screen_inventory.json + coverage ledger
  label   --id <id> [--model <model>] [--out <dir>]
            Phase1 labeling: classify each screen with the LLM (claude subscription auth, no metered API)
  scan    --id <id> [--rate <ms>] [--manifest <m.json>] [--out <dir>]
            Phase2: generic validators + evidence discipline (neg+2replay). confirmed → findings. --manifest injects auth headers (Bearer/Cookie/Basic) — needed for a spec-seeded API run.
  logic   --id <id> [--screen <sid>] [--model <model>] [--rate <ms>] [--manifest <m.json>] [--out <dir>]
            Phase2 business logic: hypothesis generation (LLM) → verify IDOR etc. with evidence discipline. --manifest injects auth headers for a spec-seeded API run.
  spec-import --spec <openapi.json> --url <base> [--id <existing>] [--manifest <m.json>] [--out <dir>]
            ingest an OpenAPI 3.x / Swagger 2.0 spec (JSON) → seed the screen inventory so the browser-free scan/logic can assess a pure-API target. --url = where the API lives (base). with --id, overlay the spec on an existing crawl (fills endpoints the UI never called). token-protected APIs: put Authorization: Bearer … in the manifest's http.headers.
  asr     --domain <apex|*.wildcard> [--tools subfinder|--no-tools] [--brute [--wordlist <file>] [--resolvers <file>]] [--import <httpx.json|hosts.txt|dir> [--import-trust-liveness]] [--allow-degraded] [--out-of-scope a.ex.com,b.ex.com] [--screenshot] [--paths] [--triage [--triage-top <n>] [--model <m>]] [--max-hosts <n>] [--rate <ms>] [--browser-path <bin>] [--no-sandbox] [--headed] [--out <dir>]
            Attack Surface Recon: passive discovery (crt.sh CT logs) → dns resolve + HTTP liveness → deterministic attack-target score (ranked) → runs/<id>/asset_inventory.json
            [--screenshot] per-host screenshot · [--paths] probe curated high-signal paths on live hosts (/.git/, /.env, /actuator, swagger, server-status…) → real exposure + auto-escalate
            [--triage] Claude classifies the top-N by score (default 15, --triage-top) → category / band / attack-angle (a lead, not a finding; claude CLI subscription, no metered API)
            wide-shallow triage feeding pilot; observe-only (no attacks). view in the WebUI (serve) 🌐 ASR tab (sorted by score, band badges)
  redteam --url <chat-ui-url> | --manifest <file.json>  --canary <token> [--headed] [--max-replays <n>] [--composer <sel>] [--send <sel>] [--new-chat <sel>] [--file-input <sel>] [--transcript <sel>] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            (alias: assistant) LLM/AI-assistant red-team: drive a deployed chatbot and confirm canary leaks. the canary is planted out-of-band by the operator in the system prompt / custom instructions and passed via --canary or manifest assistant.canary
  serve   [--port <n>] [--host <h>] [--out <dir>] [--web-root <dir>] [--no-web] [--password <pw>] [--viewer-password <pw>] [--no-auth] [--no-launch]
            start the observability WebUI + state API/WS (default 127.0.0.1:4317. expose to LAN with --host 0.0.0.0)
            two roles gate the WebUI/API/WS (/login + signed cookie): operator = env VERDICT_WEB_PASSWORD / --password (full: New/Resume/Stop/mutate);
            viewer = env VERDICT_WEB_PASSWORD_VIEWER / --viewer-password (read-only). ENV preferred over args. --no-auth disables the gate
            the WebUI "+ New" launches pilot/assess by spawning the CLI as a child; --no-launch disables run launching
  report  --id <id> [--format md,html,pdf,csv] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            generate the diagnosis report from findings (by severity + repro + evidence + scope basis).
            default md,html. pdf = HTML printed via Chromium (reuses the browser; needs a chromium binary). csv = findings.csv
  inventory --id <id> [--format csv,html] [--out <dir>]
            export the screen inventory (survey result / screen list): screens.csv + inventory.html (with screenshots)
  openapi --id <id> [--out <dir>]
            emit the discovered API surface (XHR/fetch + HTML form POSTs, with body/query params) as openapi.json — feed it to Burp's API scan
  shots   --id <id> [--headed] [--browser-path <bin>] [--no-sandbox] [--out <dir>]
            re-shoot each screen of an existing run to backfill WebUI screenshots (reuses the run's authed profile, navigate-only)
  header-audit --id <id> [--headers csp,hsts,xfo,xcto,refpol,permpol] [--rate <ms>] [--out <dir>]
            Info-level: audit each screen's response headers and record a finding per missing header (deterministic / toggle = run it or not)
  status  --id <assessment-id> [--out <dir>]
            show phase, coverage, and findings
  list    [--out <dir>]
            list the assessments under runs/

note: out-of-scope is denied. --url's default scope is same-origin + path-prefix (DESIGN §4.2 / §5).
`;

function fail(msg: string): never {
  console.error(`error: ${msg}\n`);
  console.error(USAGE);
  process.exit(1);
}

function describeTarget(t: TargetInput): string {
  return t.kind === "single_url"
    ? `single_url ${t.url} (depth ${t.maxDepth}, follow=${t.followLinks})`
    : `scope_manifest ${t.path}`;
}

function dbPathFor(runsDir: string, id: string): string {
  return join(runsDir, id, "state.sqlite");
}

function cmdRun(args: string[]): void {
  const { values } = parseArgs({
    args,
    options: {
      url: { type: "string" },
      scope: { type: "string" },
      follow: { type: "boolean" },
      "max-depth": { type: "string" },
      out: { type: "string" },
    },
  });

  if (values.scope) {
    fail("--scope (scope_manifest) parsing is not implemented yet (M-future); use --url for now");
  }
  if (!values.url) fail("run requires --url <url>");

  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const maxDepth = values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3;
  if (!Number.isFinite(maxDepth) || maxDepth < 0) fail("--max-depth must be a non-negative integer");

  const id = newAssessmentId();
  mkdirSync(join(runsDir, id), { recursive: true });
  const dbPath = dbPathFor(runsDir, id);

  const target: TargetInput = {
    kind: "single_url",
    url: values.url,
    followLinks: values.follow ?? false,
    maxDepth,
  };

  const store = AssessmentStore.open(dbPath);
  const state = store.createAssessment({ id, target, scope: deriveScopeFromSingleUrl(values.url) });
  store.close();

  console.log(`created assessment ${state.id}`);
  console.log(`  phase:  ${state.phase}`);
  console.log(`  target: ${describeTarget(state.target)}`);
  console.log(
    `  scope:  hosts=${state.scope.inScopeHosts.join(",")} rate=${state.scope.rate.requestsPerMinute}/min`,
  );
  console.log(`  state:  ${dbPath}`);
}

function cmdStatus(args: string[]): void {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" } },
  });
  if (!values.id) fail("status requires --id <assessment-id>");

  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found in ${dbPath}`);

  const cov = coverage(state);
  const pending = state.handoffs.filter((h) => h.status === "pending").length;
  console.log(`assessment ${state.id}`);
  console.log(`  phase:    ${state.phase}`);
  console.log(`  target:   ${describeTarget(state.target)}`);
  console.log(
    `  coverage: ${cov.terminal}/${cov.total} terminal, ${cov.remaining} remaining, ${cov.scannable} scannable${cov.complete ? " (complete)" : ""}`,
  );
  console.log(`  findings: ${state.findings.length}`);
  console.log(`  tokens:   ${state.budget.tokensUsed.toLocaleString()} / ${state.budget.limits.maxTokens.toLocaleString()}`);
  console.log(`  handoffs: ${pending} pending`);
  console.log(`  events:   ${state.events.length}`);
  const stop = evaluateStop(state);
  console.log(`  stop:     ${stop.stop ? `${stop.reason} (${stop.detail})` : "continue"}`);
}

/** Loader that reads evidence req/resp from runs/<id>/artifacts (for embedding into the report). */
function evidenceLoaderFor(runsDir: string, id: string): EvidenceLoader {
  const artifactsDir = join(runsDir, id, "artifacts");
  return (evId) => readEvidenceArtifact(artifactsDir, evId);
}

const REPORT_FORMATS = ["md", "html", "pdf", "csv"] as const;
type ReportFormat = (typeof REPORT_FORMATS)[number];

/** Parses a CSV like "md,html" into a valid ReportFormat[]. Empty/invalid -> fail. */
function parseFormats(spec: string | undefined, fallback: ReportFormat[], allowed: readonly ReportFormat[]): ReportFormat[] {
  const want = (spec ?? "").split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
  const fmts = want.length ? want : fallback;
  for (const f of fmts) if (!allowed.includes(f as ReportFormat)) fail(`unknown format '${f}' (allowed: ${allowed.join(",")})`);
  return [...new Set(fmts)] as ReportFormat[];
}

async function cmdReport(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      format: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
    },
  });
  if (!values.id) fail("report requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found`);

  const formats = parseFormats(values.format, ["md", "html"], REPORT_FORMATS);
  const model = buildReportModel(state, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, values.id) });
  const dir = join(runsDir, values.id);
  const written: string[] = [];

  if (formats.includes("md")) {
    const p = join(dir, "report.md");
    writeFileSync(p, renderMarkdown(model));
    written.push(p);
  }
  let html: string | null = null;
  if (formats.includes("html") || formats.includes("pdf")) html = renderReportHtml(model);
  if (formats.includes("html")) {
    const p = join(dir, "report.html");
    writeFileSync(p, html!);
    written.push(p);
  }
  if (formats.includes("csv")) {
    const p = join(dir, "findings.csv");
    writeFileSync(p, renderFindingsCsv(model));
    written.push(p);
  }
  if (formats.includes("pdf")) {
    const browserPath = values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH);
    const pdf = await htmlToPdf(html!, {
      ...(browserPath ? { executablePath: browserPath } : {}),
      ...(values["no-sandbox"] ? { noSandbox: true } : {}),
    });
    const p = join(dir, "report.pdf");
    writeFileSync(p, pdf);
    written.push(p);
  }

  console.log(`report written (${formats.join(", ")}):`);
  for (const p of written) console.log(`  ${p}`);
  console.log(`  ${state.findings.length} finding(s), phase ${state.phase}`);
}

const INVENTORY_FORMATS = ["csv", "html"] as const;

/** Standalone export of the screen inventory (survey result): screens.csv / inventory.html. */
function cmdInventory(args: string[]): void {
  const { values } = parseArgs({ args, options: { id: { type: "string" }, out: { type: "string" }, format: { type: "string" } } });
  if (!values.id) fail("inventory requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found`);

  const formats = parseFormats(values.format, ["csv", "html"], INVENTORY_FORMATS as readonly ReportFormat[]);
  const model = buildReportModel(state);
  const dir = join(runsDir, values.id);
  const written: string[] = [];
  if (formats.includes("csv")) {
    const p = join(dir, "screens.csv");
    writeFileSync(p, renderScreensCsv(model));
    written.push(p);
  }
  if (formats.includes("html")) {
    const p = join(dir, "inventory.html");
    writeFileSync(p, renderInventoryHtml(model));
    written.push(p);
  }
  console.log(`inventory written (${formats.join(", ")}): ${model.screens.length} screen(s)`);
  for (const p of written) console.log(`  ${p}`);
}

// Writes the screen inventory (XHR/fetch ∪ HTML form POSTs) as an OpenAPI 3.0 definition (a base to feed Burp's API scan).
function cmdOpenApi(args: string[]): void {
  const { values } = parseArgs({ args, options: { id: { type: "string" }, out: { type: "string" } } });
  if (!values.id) fail("openapi requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  store.close();
  if (!state) fail(`assessment ${values.id} not found`);

  // Base for servers = decided in the order target.url -> a screen's observed URL -> scope host.
  const deriveBaseUrl = (): string => {
    if ("url" in state.target && state.target.url) {
      try {
        const u = new URL(state.target.url);
        return `${u.protocol}//${u.host}`;
      } catch {
        /* fall through */
      }
    }
    for (const sc of state.screens) {
      for (const ou of sc.observedUrls) {
        try {
          const u = new URL(ou);
          return `${u.protocol}//${u.host}`;
        } catch {
          /* next */
        }
      }
    }
    const h = state.scope.inScopeHosts.find((x) => x !== "*" && !x.startsWith("*."));
    return h ? `https://${h}` : "https://localhost";
  };

  const doc = buildOpenApi(state.screens, { baseUrl: deriveBaseUrl() });
  const p = join(runsDir, values.id, "openapi.json");
  writeFileSync(p, `${JSON.stringify(doc, null, 2)}\n`);
  const ops = Object.values(doc.paths as Record<string, Record<string, unknown>>).reduce((n, m) => n + Object.keys(m).length, 0);
  console.log(`openapi written: ${ops} operation(s) across ${Object.keys(doc.paths as object).length} path(s) → ${p}`);
}

function cmdList(args: string[]): void {
  const { values } = parseArgs({ args, options: { out: { type: "string" } } });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  if (!existsSync(runsDir)) {
    console.log("(no runs yet)");
    return;
  }
  const ids = readdirSync(runsDir, { withFileTypes: true })
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .filter((id) => existsSync(dbPathFor(runsDir, id)));
  if (ids.length === 0) {
    console.log("(no runs yet)");
    return;
  }
  for (const id of ids) {
    const store = AssessmentStore.open(dbPathFor(runsDir, id));
    const state = store.loadAssessment(id);
    store.close();
    if (!state) continue;
    const cov = coverage(state);
    const tk = state.budget.tokensUsed;
    const tkStr = tk >= 1000 ? `${(tk / 1000).toFixed(1)}k` : `${tk}`;
    console.log(
      `${state.id}  ${state.phase.padEnd(13)} screens=${state.screens.length} cov=${cov.terminal}/${cov.total} findings=${state.findings.length} tok=${tkStr}  ${describeTarget(state.target)}`,
    );
  }
}

async function cmdCrawl(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      url: { type: "string" },
      id: { type: "string" },
      out: { type: "string" },
      "max-depth": { type: "string" },
      follow: { type: "boolean" },
      headed: { type: "boolean" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      "login-url": { type: "string" },
      "login-wait": { type: "string" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;

  // Resolve the target assessment (--url creates a new one, --id uses an existing one)
  let id: string;
  if (values.url) {
    id = newAssessmentId();
    mkdirSync(join(runsDir, id), { recursive: true });
    const maxDepth = values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3;
    const seedStore = AssessmentStore.open(dbPathFor(runsDir, id));
    seedStore.createAssessment({
      id,
      target: { kind: "single_url", url: values.url, followLinks: values.follow ?? true, maxDepth },
      scope: deriveScopeFromSingleUrl(values.url),
    });
    seedStore.close();
  } else if (values.id) {
    id = values.id;
    if (!existsSync(dbPathFor(runsDir, id))) fail(`no state.sqlite at ${dbPathFor(runsDir, id)}`);
  } else {
    fail("crawl requires --url <url> (new) or --id <id> (existing)");
  }

  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found`);
  }
  if (state.target.kind !== "single_url") {
    store.close();
    fail("crawl supports single_url targets only (M1)");
  }

  const profileDir = join(runsDir, id, "browser-profile");
  mkdirSync(profileDir, { recursive: true });

  console.log(`crawling ${state.target.url} (depth ${state.target.maxDepth}, follow=${state.target.followLinks})`);
  const loginUrl = values["login-url"];
  const driver = await PlaywrightDriver.launch({
    userDataDir: profileDir,
    headless: !values.headed && !loginUrl,
    executablePath: values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH),
    args: values["no-sandbox"] ? ["--no-sandbox"] : undefined,
  });

  try {
    if (loginUrl) {
      const waitSec = values["login-wait"] ? Number.parseInt(values["login-wait"], 10) : 60;
      console.log(`🔐 waiting for login: log in to ${loginUrl} in the opened browser (${waitSec}s)…`);
      await driver.interactiveLogin(loginUrl, waitSec * 1000);
      console.log("   continuing (auth state kept in browser-profile)");
    }
    const result = await crawl(
      {
        startUrl: state.target.url,
        scope: state.scope,
        followLinks: state.target.followLinks,
        maxDepth: state.target.maxDepth,
      },
      driver,
      {
        store,
        assessmentId: id,
        onScreen: (s, isNew) => {
          if (isNew) {
            const labels = s.labels.length ? ` [${s.labels.join(",")}]` : "";
            console.log(`  + ${s.screenId} ${s.screenType.padEnd(9)} ${s.urlTemplate}  apis=${s.apis.length}${labels}`);
          }
        },
      },
    );
    const invPath = join(runsDir, id, "screen_inventory.json");
    writeScreenInventory(invPath, buildInventory(result.startUrl, result.screens));
    console.log(
      `\ncrawl done: ${result.stats.screens} screens, ${result.stats.apis} apis, visited ${result.stats.visited}, stop=${result.stats.stopReason} (${result.stats.elapsedMs}ms)`,
    );
    console.log(`  inventory: ${invPath}`);
    console.log(`  state:     ${dbPathFor(runsDir, id)}`);
  } finally {
    await driver.close();
    store.close();
  }
}

async function cmdLabel(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, model: { type: "string" } },
  });
  if (!values.id) fail("label requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens to label — run `crawl` first");
  }

  const model = values.model ?? "claude-sonnet-5";
  const client = new ClaudeCliClient({ defaultModel: model });
  console.log(`labeling ${state.screens.length} screens with ${model} ...`);
  try {
    const result = await labelInventory(state.screens, client, {
      store,
      assessmentId: values.id,
      model,
      onLabeled: (s, usedFallback) => {
        const mark = usedFallback ? "~" : "✓";
        console.log(`  ${mark} ${s.screenId} ${s.screenType.padEnd(9)} ${s.urlTemplate} [${s.labels.join(",")}]`);
      },
    });
    const startUrl = state.target.kind === "single_url" ? state.target.url : values.id;
    const invPath = join(runsDir, values.id, "screen_inventory.json");
    writeScreenInventory(invPath, buildInventory(startUrl, result.screens));
    console.log(`\nlabeled ${result.labeled}, fallback(rule) ${result.fallback}  →  phase1_label`);
    console.log(`  inventory: ${invPath}`);
  } finally {
    store.close();
  }
}

interface AssessManifest {
  /** Seed (start) URL. Required. */
  target: string;
  /** Additional target URLs to diagnose (multiple seeds). When given, used together with target for scope derivation + as survey start points. */
  targets?: string[];
  /** Hard-lock to the URL list: when true, survey maps only target+targets and does not crawl across the site
   *  (diagnosis is limited to that list + the APIs each screen calls). For when the targets are strictly fixed by URL. */
  lockToTargets?: boolean;
  /** Scope width (how the allowed-host set is built). "same-origin" (default) | "etld" | "unrestricted".
   *  For a fixed-URL-list assessment, "etld" is recommended (includes the same-program API subdomains the seed screens call). */
  scopeMode?: ScopeMode;
  /** Explicit scope (partial allowed; unspecified fields are filled from defaults derived from target/scopeMode). */
  scope?: Partial<ScopePolicy>;
  crawl?: { followLinks?: boolean; maxDepth?: number };
  /** Operator-provided custom headers (WAF evasion, engagement-mandated headers, etc.). Applied to both the
   *  browser (same-origin only) and the raw http path. Not written to state.sqlite (the manifest is gitignored). */
  http?: { headers?: Record<string, string> };
  /** Operator focus hint (free text). Injected as the top-priority objective of the scenario stage (same as --focus). */
  focus?: string;
  model?: string;
  /** Redteam / assistant-mode config (the redteam command). The canary must be planted out-of-band by the
   *  operator (system prompt / custom instructions); the file-upload seedMode that plants it lands in a later slice. */
  assistant?: {
    chatUrl?: string;
    composerSelector?: string;
    sendSelector?: string;
    newChatSelector?: string;
    fileInputSelector?: string;
    /** Pins the transcript/reply container when the driver's default selector list misfires. */
    transcriptSelector?: string;
    canary?: string;
    seededIn?: "system-prompt" | "custom-instructions" | "rag" | "profile";
  };
  /** Auth (DESIGN §6.3). Credentials alone suffice — the agent auto-discovers the login URL/fields.
   *  Not written to state.sqlite. The manifest is gitignored. */
  auth?: {
    note?: string;
    /** Site-wide HTTP Basic/Digest auth (operator-provided). For a wall in front of the app's login form.
     *  The browser answers 401 automatically via httpCredentials (Basic/Digest); raw http injects Authorization: Basic. */
    httpBasic?: { user: string; pass: string };
    /** Primary-login credentials (optional; roles[0] works too). */
    login?: { username?: string; password: string };
    /** Roles (name = username, pass/password = password). [0] = primary login, all = auth-diff. */
    roles?: Array<{
      name: string;
      /** Free-text privilege level (e.g. "full admin" / "regular user (read-only)"). Used for auth-diff high/low-privilege judgement. */
      description?: string;
      desc?: string;
      username?: string;
      pass?: string;
      password?: string;
      /** Path to a pre-captured cookie file (instead of pass; for walls that can't be auto-logged-in). */
      cookieFile?: string;
      cookie_file?: string;
      cookie_file_path?: string;
      /** This role's own login entry URL (for apps where roles log in at different pages: a user login vs an admin login). */
      loginUrl?: string;
      login_url?: string;
      headers?: Record<string, string>;
    }>;
  };
}

/** Whether at least one "manual-only" role has neither credentials nor a cookie file (= attended is required). */
function manifestHasManualRole(m: AssessManifest | null): boolean {
  return (m?.auth?.roles ?? []).some((r) => !(r.password ?? r.pass) && !(r.cookieFile ?? r.cookie_file ?? r.cookie_file_path));
}

/** Site-wide HTTP Basic/Digest credentials (if any). Only valid once both user and pass are present. */
function manifestHttpBasic(m: AssessManifest | null): { user: string; pass: string } | null {
  const b = m?.auth?.httpBasic;
  return b && b.user && b.pass ? { user: b.user, pass: b.pass } : null;
}

/** The manifest's custom headers (WAF evasion, etc.). Drops entries with an empty name. null if empty. */
function manifestCustomHeaders(m: AssessManifest | null): Record<string, string> | null {
  const h = m?.http?.headers;
  if (!h) return null;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(h)) if (k.trim()) out[k.trim()] = String(v ?? "");
  return Object.keys(out).length ? out : null;
}

/** Authorization: Basic header for raw http (FetchHttpClient). Empty object if null. */
function basicHeader(b: { user: string; pass: string } | null): Record<string, string> {
  return b ? { authorization: `Basic ${Buffer.from(`${b.user}:${b.pass}`, "utf8").toString("base64")}` } : {};
}

/** Auth headers for the headless raw-http path (scan / logic on a spec-seeded run): manifest Basic + custom headers
 *  (this is how an operator supplies `Authorization: Bearer …` / `Cookie: …` for a token-protected API with no login form). */
function manifestAuthHeaders(m: AssessManifest | null): Record<string, string> {
  return { ...basicHeader(manifestHttpBasic(m)), ...(manifestCustomHeaders(m) ?? {}) };
}

function manifestPrimaryCreds(m: AssessManifest | null): LoginCreds | null {
  if (m?.auth?.login?.password) return { username: m.auth.login.username ?? "", password: m.auth.login.password };
  for (const role of m?.auth?.roles ?? []) {
    const password = role.password ?? role.pass;
    if (password) return { username: role.username ?? role.name, password };
  }
  return null;
}

function manifestRoleCreds(m: AssessManifest | null): Array<{ name: string; creds: LoginCreds }> {
  const out: Array<{ name: string; creds: LoginCreds }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const password = role.password ?? role.pass;
    if (password) out.push({ name: role.name, creds: { username: role.username ?? role.name, password } });
  }
  return out;
}

/** Role name -> privilege description (optional). Passed to the agent as a cue for distinguishing high/low privilege in auth-diff. */
function manifestRoleDescriptions(m: AssessManifest | null): Array<{ name: string; description: string }> {
  const out: Array<{ name: string; description: string }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const description = (role.description ?? role.desc ?? "").trim();
    if (description) out.push({ name: role.name, description });
  }
  return out;
}

/** Role name -> pre-captured cookie file (can be given instead of pass). */
function manifestRoleCookies(m: AssessManifest | null): Array<{ name: string; file: string }> {
  const out: Array<{ name: string; file: string }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const file = role.cookieFile ?? role.cookie_file ?? role.cookie_file_path;
    if (file) out.push({ name: role.name, file });
  }
  return out;
}

/** Role name -> that role's own login entry URL (user vs admin log in at different pages). Optional. */
function manifestRoleLoginUrls(m: AssessManifest | null): Array<{ name: string; url: string }> {
  const out: Array<{ name: string; url: string }> = [];
  for (const role of m?.auth?.roles ?? []) {
    const url = role.loginUrl ?? role.login_url;
    if (url) out.push({ name: role.name, url });
  }
  return out;
}

function loadManifest(path: string): AssessManifest {
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    fail(`cannot read manifest ${path}: ${(e as Error).message}`);
  }
  const m = raw as AssessManifest;
  if (!m || typeof m.target !== "string") fail('manifest must include a string "target" (seed URL)');
  return m;
}

// One-shot pipeline: ① crawl → ② (label) → ③ scan → ④ (logic) → ⑤ report. Started via manifest or --url.
async function cmdAssess(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      manifest: { type: "string" },
      url: { type: "string" },
      id: { type: "string" },
      out: { type: "string" },
      model: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
      rate: { type: "string" },
      "max-depth": { type: "string" },
      "no-label": { type: "boolean" },
      "no-logic": { type: "boolean" },
      "no-explore": { type: "boolean" },
      "login-url": { type: "string" },
      "login-wait": { type: "string" },
      headless: { type: "boolean" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const seedUrl = manifest?.target ?? values.url;
  if (!seedUrl) fail("assess requires --manifest <file.json> or --url <url>");

  const seeds = [seedUrl, ...(manifest?.targets ?? [])];
  const scope: ScopePolicy = { ...deriveScopeFromUrls(seeds, manifest?.scopeMode ?? "same-origin"), ...(manifest?.scope ?? {}) };
  const followLinks = manifest?.crawl?.followLinks ?? true;
  const maxDepth = manifest?.crawl?.maxDepth ?? (values["max-depth"] ? Number.parseInt(values["max-depth"], 10) : 3);
  const model = values.model ?? manifest?.model ?? "claude-sonnet-5";
  const rate = values.rate ? Number.parseInt(values.rate, 10) : 250;

  const id = values.id ?? newAssessmentId(); // server-spawned runs supply --id; otherwise generate
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  store.createAssessment({ id, target: { kind: "single_url", url: seedUrl, followLinks, maxDepth }, scope });

  console.log(`▶ assessment ${id}`);
  console.log(`  target ${seedUrl} | scope hosts=[${scope.inScopeHosts.join(",")}] | rate ${rate}ms`);
  if (manifest?.auth?.roles?.length) {
    console.log(`  auth roles: ${manifest.auth.roles.map((r) => r.name).join(", ")} (for auth-diff / not persisted to state)`);
  }

  const screensNow = () => store.loadAssessment(id)?.screens ?? [];
  const httpBasic = manifestHttpBasic(manifest); // site-wide Basic/Digest (if any)
  const assessCustomHeaders = manifestCustomHeaders(manifest); // WAF-bypass / mandated headers (if any)
  const claude = new ClaudeCliClient({ defaultModel: model });
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, scope), minDelayMs: rate, headers: manifestAuthHeaders(manifest) }); // basic + custom headers (was httpBasic only)
  const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));

  // ① unauth crawl → ② login (credentials or human) → ③ post-login crawl → (⑤ capture role sessions)
  const profileDir = join(runsDir, id, "browser-profile");
  mkdirSync(profileDir, { recursive: true });
  const primaryCreds = manifestPrimaryCreds(manifest);
  const roleCredsList = manifestRoleCreds(manifest);
  const interactiveUrl = values["login-url"];
  // Headless by default (auto-login works headless). Headed only when --headed / --login-url is given explicitly.
  // Credentials alone don't force headed (creds auto-login runs even on a headless VM/CI).
  const headed = !values.headless && (values.headed || !!interactiveUrl);
  const waitSec = values["login-wait"] ? Number.parseInt(values["login-wait"], 10) : 60;
  const roleSessions: RoleContext[] = [];
  let primaryCookie = "";

  const driver = await PlaywrightDriver.launch({
    userDataDir: profileDir,
    headless: !headed,
    executablePath: values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH),
    args: values["no-sandbox"] ? ["--no-sandbox"] : undefined,
    ...(httpBasic ? { httpCredentials: { username: httpBasic.user, password: httpBasic.pass } } : {}),
    ...(assessCustomHeaders ? { extraHeaders: assessCustomHeaders } : {}), // WAF-bypass / mandated headers on the browser too (same-origin-only, CORS-safe)
  });

  // Active-exploration hook (fully automatic): drives the browser on each new screen to draw out fired APIs / new URLs (§7.2)
  const exploreHook = values["no-explore"]
    ? undefined
    : async (): Promise<{ apis: Awaited<ReturnType<typeof exploreScreen>>["firedApis"]; urls: string[] }> => {
        const r = await exploreScreen(driver, claude, { model });
        return { apis: r.firedApis, urls: r.newUrls };
      };

  try {
    console.log("① crawl unauth (Playwright) …");
    const unauth = await crawl(
      { startUrl: seedUrl, scope, followLinks, maxDepth, authState: "unauth" },
      driver,
      { store, assessmentId: id, ...(exploreHook ? { explore: exploreHook } : {}) },
    );
    console.log(`   ${unauth.stats.screens} screens, ${unauth.stats.apis} apis, ${unauth.stats.handoffs} handoff(s)`);
    const unauthScreens = screensNow();
    const unauthIds = new Set(unauthScreens.map((s) => s.screenId));

    if (primaryCreds || interactiveUrl) {
      const loginScreenUrl = screensNow().find((s) => s.screenType === "auth")?.observedUrls[0];
      let loggedIn = false;
      if (primaryCreds) {
        console.log("② login (auto-discover login screen/fields from credentials) …");
        const r = await smartLogin(driver, claude, primaryCreds, {
          targetUrl: seedUrl,
          ...(loginScreenUrl ? { loginScreenUrl } : {}),
          model,
        });
        if (r.ok) {
          console.log(`   ✓ ${r.reason}`);
          loggedIn = true;
        } else if (r.needsHuman && headed) {
          const u = interactiveUrl ?? r.loginUrl ?? seedUrl;
          console.log(`🔐 ${r.reason} → switching to manual login: ${u} (${waitSec}s)…`);
          await driver.interactiveLogin(u, waitSec * 1000);
          loggedIn = true;
        } else if (r.needsHuman) {
          console.log(`   ${r.reason} — for MFA/CAPTCHA, re-run with --headed in a display environment (continuing unauthenticated)`);
        } else {
          console.log(`   auto-login failed: ${r.reason} (continuing unauthenticated)`);
        }
      } else if (interactiveUrl) {
        console.log(`🔐 waiting for login: ${interactiveUrl} (${waitSec}s)…`);
        await driver.interactiveLogin(interactiveUrl, waitSec * 1000);
        loggedIn = true;
      }
      if (loggedIn) {
        // Re-crawl from the post-login landing page (e.g. /dashboard) as the start (to reach authed screens unreachable from the seed)
        const postLoginUrl = driver.currentUrl();
        const authStart = isInScope(postLoginUrl, scope) ? postLoginUrl : seedUrl;
        console.log(`③ crawl post-login (from ${authStart}) …`);
        await crawl(
          { startUrl: authStart, scope, followLinks, maxDepth, authState: "post-login" },
          driver,
          { store, assessmentId: id, seedScreens: unauthScreens, ...(exploreHook ? { explore: exploreHook } : {}) },
        );
        const authOnly = screensNow().filter((s) => !unauthIds.has(s.screenId));
        console.log(`   +${authOnly.length} auth-only screens: ${authOnly.slice(0, 8).map((s) => s.urlTemplate).join(", ")}`);
        if (authOnly.length > 0) {
          store.appendEvent(id, { type: "note", payload: { message: `auth-only screens: ${authOnly.map((s) => s.screenId).join(",")}` } });
        }
        primaryCookie = await driver.sessionCookieHeader(); // used for post-auth verification (IDOR, etc.)
      }
    }
    writeScreenInventory(join(runsDir, id, "screen_inventory.json"), buildInventory(seedUrl, screensNow()));

    // ⑤ (first half) log in as each role to capture its session cookie
    if (roleCredsList.length >= 2) {
      console.log("⑤ auth-diff: log in as each role to capture sessions …");
      for (const rc of roleCredsList) {
        await driver.clearSession();
        const r = await smartLogin(driver, claude, rc.creds, { targetUrl: seedUrl, model });
        if (r.ok) {
          const cookie = await driver.sessionCookieHeader();
          roleSessions.push({ name: rc.name, headers: cookie ? { cookie } : {} });
          console.log(`   ✓ ${rc.name}`);
        } else {
          console.log(`   ✗ ${rc.name}: ${r.reason}`);
        }
      }
    }
  } finally {
    await driver.close();
  }

  // ② label
  if (!values["no-label"]) {
    console.log(`② label (LLM ${model}) …`);
    const lr = await labelInventory(screensNow(), claude, { store, assessmentId: id, model });
    console.log(`   labeled ${lr.labeled}, fallback ${lr.fallback}`);
  }

  // ③ scan
  console.log("③ scan (validators + evidence discipline) …");
  const sr = await scanInventory(screensNow(), http, evidence, { store, assessmentId: id });
  console.log(`   ${sr.confirmed} confirmed`);

  // ④ logic (authed screens/APIs are verified with the primary role's session = hit IDOR under auth)
  if (!values["no-logic"]) {
    console.log("④ logic (business logic) …");
    const logicHttp = primaryCookie
      ? new FetchHttpClient({ allow: (url) => isInScope(url, scope), minDelayMs: rate, headers: { cookie: primaryCookie, ...basicHeader(httpBasic) } })
      : http;
    const lr = await assessLogicInventory(screensNow(), claude, logicHttp, evidence, { store, assessmentId: id }, { model });
    console.log(`   ${lr.hypotheses} hypotheses, ${lr.confirmed} confirmed`);
  }

  // ⑤ (second half) auth-diff: compare the same API across roles (HTTP layer, no browser needed)
  if (roleSessions.length >= 2) {
    const high = roleSessions[0];
    const low = roleSessions[1];
    if (high && low) {
      console.log(`⑤ auth-diff (${high.name} vs ${low.name}) …`);
      let confirmed = 0;
      for (const screen of screensNow()) {
        if (!screen.apis.some((a) => a.auth !== "none")) continue;
        const r = await authDiffScreen(screen, http, evidence, high, low);
        if (r.status === "confirmed") {
          confirmed += 1;
          store.upsertFinding(id, {
            id: `adf-${screen.screenId}`,
            screenId: screen.screenId,
            title: `Authorization boundary crossed on ${screen.urlTemplate}`,
            severity: "high",
            source: { kind: "validator", validatorName: "auth_diff" },
            description: r.reason,
            reproSteps: `compared roles '${high.name}' vs '${low.name}' on the screen's authenticated API`,
            evidenceIds: r.evidenceIds,
            scopeBasis: "same origin as a crawled in-scope screen",
          });
        }
      }
      console.log(`   ${confirmed} auth-diff confirmed`);
    }
  }

  // ⑥ report
  const finalState = store.loadAssessment(id);
  if (finalState) writeFileSync(join(runsDir, id, "report.md"), buildReport(finalState, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }));
  store.close();
  console.log(`⑥ report → ${join(runsDir, id, "report.md")}`);
  console.log(`\n✓ done. observe: if serve is running, http://127.0.0.1:4317/?id=${id}`);
}

/** Pre-pass that extracts the inline CSV of `--attended admin,userA,userB`.
 *  Only picks it up as a value when the token right after `--attended` is not a flag (= the role CSV); `--attended` itself stays boolean.
 *  Also supports the `--attended=admin,userA` form and a bare `--attended` (from the manifest). */
export function extractAttendedRoles(args: string[]): { args: string[]; roles?: string[] } {
  const out: string[] = [];
  let roles: string[] | undefined;
  const csv = (s: string): string[] => s.split(",").map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === "--attended") {
      out.push("--attended");
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        roles = csv(next);
        i++; // consume the CSV value (don't leave it as a positional)
      }
    } else if (a.startsWith("--attended=")) {
      out.push("--attended");
      roles = csv(a.slice("--attended=".length));
    } else {
      out.push(a);
    }
  }
  return roles ? { args: out, roles } : { args: out };
}

/** Extracts a `--flag [value]` optional-value flag from argv. The token after `--flag` is the value unless it's a flag/end-of-args (then bare).
 *  The `--flag=value` form is also allowed. bare (present but no value) is for falling back to an env default. */
export function extractOptValueFlag(args: string[], flag: string): { args: string[]; present: boolean; value?: string } {
  const out: string[] = [];
  let present = false;
  let value: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i] ?? "";
    if (a === flag) {
      present = true;
      const next = args[i + 1];
      if (next !== undefined && !next.startsWith("-")) {
        value = next;
        i++;
      }
    } else if (a.startsWith(`${flag}=`)) {
      present = true;
      value = a.slice(flag.length + 1);
    } else {
      out.push(a);
    }
  }
  return value !== undefined ? { args: out, present, value } : { args: out, present };
}

// Claude-led assessment: Claude drives the tools to autonomously explore, verify, and record (@veritas/pilot).
// P3 handoff resolver: turn a `--from-asr <asr-id | asset_inventory.json | run-dir>` reference into the inventory path
// + the ASR run's authorization boundary (pins), then promote. Pins come from the ASR run's STORED assessment (apex +
// carve-outs) so promotion inherits exactly what ASR was authorized for — never widens. Apex-only fallback (with a
// loud warning) only if no store is found beside the inventory.
async function runFromAsrCli(ref: string, runsDir: string, o: { top: number; band?: string; concurrency: number }): Promise<void> {
  const band = o.band;
  if (band && !["critical", "high", "medium", "low"].includes(band)) fail("--from-asr-band must be one of critical|high|medium|low");
  let dir: string;
  let invPath: string;
  if (ref.endsWith(".json")) {
    invPath = resolve(ref);
    dir = dirname(invPath);
  } else if (isAbsolute(ref) || ref.includes("/") || ref.includes("\\")) {
    dir = resolve(ref);
    invPath = join(dir, "asset_inventory.json");
  } else {
    dir = join(runsDir, ref); // a bare asr-id → runs/<id>/
    invPath = join(dir, "asset_inventory.json");
  }
  if (!existsSync(invPath)) fail(`pilot --from-asr: no asset_inventory.json at ${invPath}`);

  // Pins = the ASR run's stored authorization boundary (id = the run-dir name). Promotion may only NARROW, never widen.
  let stored: AssessmentState | null = null;
  const dbPath = join(dir, "state.sqlite");
  const storedId = basename(dir);
  if (existsSync(dbPath)) {
    const s = AssessmentStore.open(dbPath);
    stored = s.loadAssessment(storedId);
    s.close();
  }
  let pins: AsrScopePins;
  if (stored) {
    pins = { inScopeHosts: stored.scope.inScopeHosts, outOfScopeHosts: stored.scope.outOfScopeHosts };
  } else {
    const apex = readAssetInventory(invPath).apex;
    pins = { inScopeHosts: [`*.${apex}`], outOfScopeHosts: [] };
    console.log(`⚠ from-asr: no stored scope for ${storedId} — pinning apex-only *.${apex} (out-of-scope carve-outs not recoverable; keep the ASR run's state.sqlite present to inherit them)`);
  }
  console.log(`▶ pilot --from-asr ${storedId}: scope pinned to ${pins.inScopeHosts.join(",")}${pins.outOfScopeHosts.length ? ` (−${pins.outOfScopeHosts.join(",")})` : ""}`);

  const results = await runFromAsr(
    { invPath, runsDir, pins, top: o.top, ...(band ? { minBand: band as AssetBand } : {}), concurrency: o.concurrency, newId: newAssessmentId },
    spawnPilotLauncher,
  );
  const ok = results.filter((r) => r.ok).length;
  console.log(`\nfrom-asr: launched ${results.length} pilot run(s)${results.length ? ` (${ok} ok)` : ""} — promoted links written to ${invPath}`);
  for (const r of results) console.log(`  ${r.ok ? "✓" : "✗"} ${r.host} → ${r.childId}`);
}

async function cmdPilot(rawArgs: string[]): Promise<void> {
  const a1 = extractAttendedRoles(rawArgs);
  const inlineAttendedRoles = a1.roles;
  // --burp-proxy is an optional-value flag: bare uses env BURP_PROXY, with a value uses that (env by default, overridden by the arg).
  const bp = extractOptValueFlag(a1.args, "--burp-proxy");
  const { values } = parseArgs({
    args: bp.args,
    options: {
      manifest: { type: "string" },
      url: { type: "string" },
      id: { type: "string" },
      resume: { type: "boolean" },
      "survey-only": { type: "boolean" },
      out: { type: "string" },
      model: { type: "string" },
      "fast-model": { type: "string" },
      "browser-path": { type: "string" },
      "browser-channel": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
      headless: { type: "boolean" },
      attended: { type: "boolean" },
      exhaustive: { type: "boolean" },
      "login-url": { type: "string" },
      rate: { type: "string" },
      "max-turns": { type: "string" },
      "max-screens": { type: "string" },
      "max-survey-screens": { type: "string" },
      focus: { type: "string" }, // operator focus hint (free text). Injected as the scenario stage's top-priority objective (not mixed into per-screen)
      "no-input-sweep": { type: "boolean" }, // submit each screen's input fields with benign values to discover new routes/APIs (default on). Set to disable
      "safe-forms": { type: "boolean" }, // in the input sweep, don't submit POST forms (GET/search only = don't write data to the target)
      "no-scenario": { type: "boolean" }, // by default runs the A04 scenario (cross-endpoint logic) after diagnosis. Set to skip
      "no-default-scenarios": { type: "boolean" }, // by default injects built-in scenarios (credential hunting, etc.). Set to disable just those (A04 stays)
      "no-fingerprint": { type: "boolean" }, // by default runs A06 fingerprinting (collect versions -> known-CVE assessment). Set to skip
      "cve-lookup": { type: "boolean" }, // in A06, query online CVE DBs (OSV/NVD) for detected versions (opt-in: third-party egress). Default off
      "burp-scan": { type: "boolean" },
      "burp-api": { type: "string" },
      "no-burp-verify": { type: "boolean" }, // by default AI re-verifies Burp High+. Set to skip the verify phase
      "keepalive-min": { type: "string" },
      "keepalive-url": { type: "string" }, // explicit URL for the keepalive touch (default: the authed page being diagnosed; never `/`)
      "anchor-url": { type: "string" }, // goto-safe authed hub (menu): reach cold-nav-bouncing routes by clicking their link from here; also the keepalive target
      "control-url": { type: "string" }, // attended×LiveHands: reverse-connection target for serve (supplied by the supervisor)
      "from-asr": { type: "string" }, // P3 handoff: promote an ASR run's ranked assets into per-host pilot runs (arg = asr-id | asset_inventory.json)
      "from-asr-top": { type: "string" }, // take the top-N promotable hosts (default 5)
      "from-asr-band": { type: "string" }, // band floor: critical|high|medium|low (only promote at/above)
      "from-asr-concurrency": { type: "string" }, // parallel child pilots (default 1 — Claude subscription concurrency)
    },
  });
  // --burp-proxy: active only when given. Address = the arg value -> env BURP_PROXY.
  const burpProxy = bp.present ? (bp.value ?? process.env.BURP_PROXY) : undefined;
  if (bp.present && !burpProxy) console.log("⚠ --burp-proxy was given but neither a value nor BURP_PROXY env is set (continuing without a proxy)");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  // P3 — pilot --from-asr <asr-id|inventory.json>: promote an ASR run's ranked assets into per-host deep pilot runs.
  // A distinct mode (no survey/manifest of its own); the child pilots inherit the ASR scope, pinned — never widened.
  if (values["from-asr"]) {
    await runFromAsrCli(values["from-asr"], runsDir, {
      top: values["from-asr-top"] ? Math.max(1, Number.parseInt(values["from-asr-top"], 10)) : 5,
      band: values["from-asr-band"],
      concurrency: values["from-asr-concurrency"] ? Math.max(1, Number.parseInt(values["from-asr-concurrency"], 10)) : 1,
    });
    return;
  }
  const resume = !!values.resume;
  // resume skips survey/methodology and resumes only diagnosis. Even without --manifest, it reads back the
  // runs/<id>/manifest.json persisted at start to restore the auth material (roleCreds/cookie/httpBasic/attended).
  // Note: without this, everything after resume becomes unauth and everything behind the auth wall returns 401, making diagnosis impossible.
  const manifest = values.manifest
    ? loadManifest(values.manifest)
    : resume && values.id && existsSync(join(runsDir, values.id, "manifest.json"))
      ? loadManifest(join(runsDir, values.id, "manifest.json"))
      : null;
  const model = values.model ?? manifest?.model ?? "claude-opus-4-8"; // deep model default = Opus (high-value screens / scenario / CVE)
  const rate = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const maxTurns = values["max-turns"] ? Number.parseInt(values["max-turns"], 10) : 80;
  // On resume, re-derive attended from the manifest's manual roles (neither creds nor cookie).
  const attended = !!values.attended || (resume && manifestHasManualRole(manifest)); // manual multi-session auth (always headed)
  const headed = attended || (!values.headless && !!values.headed);
  if (attended && values.headless) console.log("⚠ --attended needs a headed browser for manual login (--headless ignored)");
  const browserPath = values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH);
  const browserChannel = values["browser-channel"] ?? process.env.VERDICT_BROWSER_CHANNEL; // e.g. "chrome" — real browser vs bundled Chromium (defeats more anti-bot)
  const surveyOnly = !!values["survey-only"];

  let id: string;
  let store: AssessmentStore;
  let scope: ScopePolicy;
  let seedUrl: string;
  let seedUrls: string[] = []; // multiple seeds (target + manifest.targets). Survey start points.
  const lockToTargets = manifest?.lockToTargets === true; // fixed URL list (no cross-site crawl)

  if (resume) {
    if (!values.id) fail("pilot --resume requires --id <assessment-id>");
    id = values.id;
    const dbPath = dbPathFor(runsDir, id);
    if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
    store = AssessmentStore.open(dbPath);
    const state = store.loadAssessment(id);
    if (!state) {
      store.close();
      fail(`assessment ${id} not found in ${dbPath}`);
    }
    scope = state.scope;
    seedUrl = "url" in state.target ? state.target.url : "";
    seedUrls = [seedUrl];
  } else {
    seedUrl = manifest?.target ?? values.url ?? "";
    if (!seedUrl) fail("pilot requires --manifest <file.json> or --url <url> (or --resume --id <id>)");
    seedUrls = [...new Set([seedUrl, ...(manifest?.targets ?? [])])];
    scope = { ...deriveScopeFromUrls(seedUrls, manifest?.scopeMode ?? "same-origin"), ...(manifest?.scope ?? {}) };
    id = values.id ?? newAssessmentId(); // server-spawned runs supply --id; otherwise generate
    mkdirSync(join(runsDir, id), { recursive: true });
    store = AssessmentStore.open(dbPathFor(runsDir, id));
    store.createAssessment({
      id,
      // When hard-locked, don't follow links (survey maps only the seeds).
      target: { kind: "single_url", url: seedUrl, followLinks: !lockToTargets, maxDepth: manifest?.crawl?.maxDepth ?? 10 }, // crawl default depth = 10
      scope,
    });
  }

  const roleCreds = new Map<string, LoginCreds>();
  for (const rc of manifestRoleCreds(manifest)) roleCreds.set(rc.name, rc.creds);
  const primary = manifestPrimaryCreds(manifest);
  if (roleCreds.size === 0 && primary) roleCreds.set(primary.username || "user", primary);
  const roleCookieFiles = new Map<string, string>();
  for (const rc of manifestRoleCookies(manifest)) roleCookieFiles.set(rc.name, rc.file);
  const roleLoginUrls = new Map<string, string>();
  for (const rc of manifestRoleLoginUrls(manifest)) roleLoginUrls.set(rc.name, rc.url);
  const roleDescriptions = new Map<string, string>();
  for (const rc of manifestRoleDescriptions(manifest)) roleDescriptions.set(rc.name, rc.description);
  const httpBasic = manifestHttpBasic(manifest); // site-wide Basic/Digest (if any)
  const customHeaders = manifestCustomHeaders(manifest); // custom headers (WAF evasion, etc.; if any)
  if (resume)
    console.log(
      `  ↻ resume: restored config from manifest — httpBasic ${httpBasic ? "✓" : "—"}, creds ${roleCreds.size}, cookies ${roleCookieFiles.size}, attended ${attended ? "✓" : "—"}`,
    );

  const mode = `${surveyOnly ? " · survey-only" : resume ? " · resume" : ""}${attended ? " · attended (manual multi-session)" : ""}`;
  console.log(`▶ pilot ${id}  (Claude-led${mode})`);
  console.log(`  target ${seedUrl} | scope hosts=[${scope.inScopeHosts.join(",")}] | model ${model}${values["fast-model"] ? ` (deep) / ${values["fast-model"]} (fast)` : ""} | rate ${rate}ms`);
  // Roles to open windows for in attended: the inline CSV (--attended a,b,c) takes priority; otherwise all role names from the manifest
  // (including manual-only roles with no creds/cookie). Also used for the listing display.
  const attendedRoles = attended ? (inlineAttendedRoles ?? (manifest?.auth?.roles ?? []).map((r) => r.name)) : [];
  const allRoles = [...new Set([...attendedRoles, ...roleCreds.keys(), ...roleCookieFiles.keys()])];
  const roleLabel = (r: string): string => {
    const kind = roleCookieFiles.has(r) ? `${r}(cookie)` : roleCreds.has(r) ? r : attended ? `${r}(manual)` : r;
    const d = roleDescriptions.get(r);
    return d ? `${kind} — ${d}` : kind;
  };
  console.log(`  roles: ${allRoles.map(roleLabel).join(", ") || "none"} | max-turns ${maxTurns}${surveyOnly ? " | survey only (no diagnosis)" : resume ? " | resuming undiagnosed screens only" : ""}\n`);

  // attended human-operation wait: print a message and resolve on Enter (a sync point for manual login/re-login).
  const { createInterface } = await import("node:readline");
  const rl = attended ? createInterface({ input: process.stdin, output: process.stdout }) : null;
  const promptOperator = (message: string): Promise<void> =>
    new Promise((resolve) => {
      if (!rl) return resolve();
      rl.question(`\n${message} `, () => resolve());
    });

  try {
    // Resolve the OOB (Burp Collaborator) connection so it's usable during diagnosis (probe_oob is enabled if BURP_AUDIT_API is set).
    const oobConn = resolveBurpAudit();
    if (oobConn) console.log(`  🛰 OOB ready via Collaborator (${oobConn.base}) — probe_oob enabled for blind SSRF/XXE/SQLi`);
    const res = await runPilot({
      store,
      assessmentId: id,
      targetUrl: seedUrl,
      scope,
      ...(seedUrls.length > 1 ? { seedUrls } : {}),
      ...(lockToTargets ? { lockToSeeds: true } : {}),
      ...(httpBasic ? { httpBasic } : {}),
      ...(customHeaders ? { customHeaders } : {}),
      ...(oobConn ? { oob: oobConn } : {}),
      ...((values.focus ?? manifest?.focus) ? { focus: values.focus ?? manifest?.focus } : {}),
      ...(values["no-input-sweep"] ? { inputSweep: false } : {}),
      ...(values["safe-forms"] ? { aggressiveForms: false } : {}),
      profileDir: join(runsDir, id, "browser-profile"),
      artifactsDir: join(runsDir, id, "artifacts"),
      roleCreds,
      model,
      maxTurns,
      rateMs: rate,
      headless: !headed,
      ...(resume ? { resume: true } : {}),
      ...(surveyOnly ? { surveyOnly: true } : {}),
      ...(values.exhaustive ? { exhaustiveSurvey: true } : {}),
      ...(attended
        ? {
            attended: true,
            attendedProfilesDir: join(runsDir, id, "profiles"),
            promptOperator,
            // Open windows by role name from the inline CSV or the manifest (including manual-only roles with no pass/cookieFile).
            ...(attendedRoles.length ? { attendedRoles } : {}),
          }
        : {}),
      ...(values["login-url"] ? { loginUrl: values["login-url"] } : {}),
      ...(values["control-url"] ? { controlUrl: values["control-url"] } : {}),
      ...(values["max-screens"] ? { maxScreens: Number.parseInt(values["max-screens"], 10) } : {}),
      ...(values["max-survey-screens"] ? { maxSurveyScreens: Number.parseInt(values["max-survey-screens"], 10) } : {}),
      ...(roleCookieFiles.size ? { roleCookieFiles } : {}),
      ...(roleLoginUrls.size ? { roleLoginUrls } : {}),
      ...(roleDescriptions.size ? { roleDescriptions } : {}),
      fastModel: values["fast-model"] ?? "claude-sonnet-5", // fast model default = Sonnet (survey/methodology/low-value screens -> model tiering ON by default)
      ...(values["no-scenario"] ? { scenarioPass: false } : {}), // ON by default. Set to drop the A04 scenario
      ...(values["no-default-scenarios"] ? { defaultScenarios: false } : {}), // ON by default. Set to drop only the built-in scenarios
      ...(values["no-fingerprint"] ? { fingerprintPass: false } : {}), // ON by default. Set to drop A06 fingerprinting
      ...(values["cve-lookup"] ? { cveLookup: true } : {}), // OFF by default. Set to enable online CVE DB lookups
      ...(burpProxy ? { burpProxy } : {}),
      ...(values["keepalive-min"] ? { keepAliveMinutes: Number.parseInt(values["keepalive-min"], 10) } : {}),
      ...(values["keepalive-url"] ? { keepAliveUrl: values["keepalive-url"] } : {}),
      ...(values["anchor-url"] ? { anchorUrl: values["anchor-url"] } : {}),
      ...(browserPath ? { browserPath } : {}),
      ...(browserChannel ? { browserChannel } : {}),
      ...(values["no-sandbox"] ? { noSandbox: true } : {}),
      onText: (t) => console.log(`\n${t}`),
      onTool: (n, i) => console.log(`  ⚙ ${n.replace("mcp__veritas__", "")} ${JSON.stringify(i).slice(0, 160)}`),
      // --burp-scan: after diagnosis/scenario, runs a Burp active scan -> import -> High+ re-verify as a **phase2_burpscan phase while the session is alive**.
      // Calls keepWarm between polls to keep the token/cookie alive. Doesn't crash the run on failure.
      ...(values["burp-scan"] && !surveyOnly
        ? {
            onBurpScanPhase: async ({ keepWarm, cookie, bearer }: { keepWarm: () => Promise<void>; cookie: string; bearer: string }): Promise<void> => {
              const burpState = store.loadAssessment(id);
              if (!burpState) return;
              // If BURP_AUDIT_API is set, use the VERDICT Audit REST (1338, session-embedded). Otherwise the standard REST (1337).
              const auditConn = resolveBurpAudit();
              if (auditConn) {
                await runBurpAuditOnRun(store, id, burpState, runsDir, {
                  conn: auditConn,
                  cookie,
                  bearer,
                  httpBasic,
                  ...(customHeaders ? { customHeaders } : {}), // carry operator custom headers (WAF-bypass / mandated) into the Burp-audited requests
                  verify: !values["no-burp-verify"],
                  ...(model ? { verifyModel: model } : {}),
                  pollSec: 10,
                  maxMin: 30,
                  onPoll: keepWarm,
                });
                return;
              }
              const burpLogins = manifestRoleCreds(manifest).map((rc) => ({ username: rc.creds.username, password: rc.creds.password }));
              const auto = pickBurpConfigs(burpState); // auto-select the best named config for the surface (crawl strategy, etc.)
              const customConfigs = buildBurpCustomConfigs(cookie, bearer); // your scan policy + session injection (env)
              await runBurpScanOnRun(store, id, burpState, runsDir, {
                conn: resolveBurpRest({ ...(values["burp-api"] ? { "burp-api": values["burp-api"] } : {}) }),
                configs: auto.configs,
                configReason: `auto: ${auto.reason}`,
                logins: burpLogins,
                pollSec: 10,
                maxMin: 30,
                verify: !values["no-burp-verify"], // default: AI re-verifies the imported High+
                verifyModel: model, // verification is deep (adversarial), so use the deep model
                httpBasic,
                ...(customHeaders ? { customHeaders } : {}), // carry operator custom headers into the REST-scan re-verify
                ...(customConfigs.length ? { customConfigs } : {}),
                onPoll: keepWarm, // keep the session alive
              });
            },
          }
        : {}),
    });
    const finalState = store.loadAssessment(id);
    if (finalState) writeFileSync(join(runsDir, id, "report.md"), buildReport(finalState, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }));
    const tk = res.tokensUsed >= 1000 ? `${(res.tokensUsed / 1000).toFixed(1)}k` : `${res.tokensUsed}`;
    console.log(`\n=== ${res.findings.length} finding(s) in ${res.turns} turns · ${tk} tokens${res.costUsd > 0 ? ` · ~$${res.costUsd.toFixed(2)}` : ""} ===`);
    for (const f of res.findings) console.log(`  - [${f.severity}] ${f.title}`);
    console.log(`\nreport → ${join(runsDir, id, "report.md")}`);
    console.log(`observe: if serve is running, http://127.0.0.1:4317/?id=${id}`);
  } finally {
    rl?.close();
    store.close();
  }
}

function resolveWebRoot(): string | undefined {
  try {
    const require = createRequire(import.meta.url);
    return join(dirname(require.resolve("@veritas/webui/package.json")), "dist");
  } catch {
    return undefined;
  }
}

async function cmdScan(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, rate: { type: "string" }, manifest: { type: "string" }, "burp-proxy": { type: "string" } },
  });
  if (!values.id) fail("scan requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens to scan — run `crawl` first");
  }

  const minDelayMs = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const authHeaders = manifestAuthHeaders(values.manifest ? loadManifest(values.manifest) : null);
  const scanProxy = values["burp-proxy"] ?? process.env.BURP_PROXY;
  const http = new FetchHttpClient({ allow: (url) => isInScope(url, state.scope), minDelayMs, ...(Object.keys(authHeaders).length ? { headers: authHeaders } : {}), ...(scanProxy ? { proxy: scanProxy } : {}) });
  const evidence = new EvidenceStore(join(runsDir, values.id, "artifacts"));
  console.log(`scanning ${state.screens.length} screens (scope-gated, rate ${minDelayMs}ms) ...`);
  try {
    const result = await scanInventory(state.screens, http, evidence, {
      store,
      assessmentId: values.id,
      onScreen: (r) => {
        for (const o of r.outcomes) {
          if (o.status === "confirmed") {
            console.log(`  ⚠ [${o.severity}] ${r.screenId} ${o.validator}/${o.probeId}: ${o.title}`);
          }
        }
      },
    });
    console.log(`\nscan done: ${result.confirmed} confirmed finding(s) → phase2_scan`);
    console.log(`  evidence: ${join(runsDir, values.id, "artifacts")}`);
    console.log(`  state:    ${dbPath}`);
  } finally {
    store.close();
  }
}

async function cmdLogic(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      model: { type: "string" },
      screen: { type: "string" },
      rate: { type: "string" },
      manifest: { type: "string" },
      "burp-proxy": { type: "string" },
    },
  });
  if (!values.id) fail("logic requires --id <assessment-id>");
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, values.id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);

  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(values.id);
  if (!state) {
    store.close();
    fail(`assessment ${values.id} not found`);
  }
  if (state.screens.length === 0) {
    store.close();
    fail("no screens — run `crawl` first");
  }

  const minDelayMs = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const llm = new ClaudeCliClient(values.model ? { defaultModel: values.model } : {});
  const authHeaders = manifestAuthHeaders(values.manifest ? loadManifest(values.manifest) : null);
  const logicProxy = values["burp-proxy"] ?? process.env.BURP_PROXY;
  const http = new FetchHttpClient({ allow: (url) => isInScope(url, state.scope), minDelayMs, ...(Object.keys(authHeaders).length ? { headers: authHeaders } : {}), ...(logicProxy ? { proxy: logicProxy } : {}) });
  const evidence = new EvidenceStore(join(runsDir, values.id, "artifacts"));
  const hypoOpts = values.model ? { model: values.model } : {};
  const onHypothesis = (h: { screenId: string; class: string; statement: string }, o: { status: string }): void => {
    const mark = o.status === "confirmed" ? "⚠" : o.status === "blocked" ? "·" : "○";
    console.log(`  ${mark} ${h.screenId} [${h.class}] ${h.statement.slice(0, 72)} → ${o.status}`);
  };

  try {
    if (values.screen) {
      const screen = state.screens.find((s) => s.screenId === values.screen);
      if (!screen) {
        store.close();
        fail(`screen ${values.screen} not found`);
      }
      console.log(`assessing business logic on ${screen.screenId} ...`);
      const r = await assessScreenLogic(screen, llm, http, evidence, { store, assessmentId: values.id, onHypothesis }, hypoOpts);
      console.log(`\nlogic done: ${r.hypotheses.length} hypotheses, ${r.findings.length} confirmed`);
    } else {
      console.log("assessing business logic on idor-candidate / object_ref screens ...");
      const r = await assessLogicInventory(state.screens, llm, http, evidence, { store, assessmentId: values.id, onHypothesis }, hypoOpts);
      console.log(`\nlogic done: ${r.hypotheses} hypotheses across ${r.results.length} screens, ${r.confirmed} confirmed`);
    }
    console.log(`  evidence: ${join(runsDir, values.id, "artifacts")}`);
  } finally {
    store.close();
  }
}

async function cmdServe(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      out: { type: "string" },
      port: { type: "string" },
      host: { type: "string" },
      "web-root": { type: "string" },
      "no-web": { type: "boolean" },
      password: { type: "string" },
      "viewer-password": { type: "string" },
      "no-auth": { type: "boolean" },
      "no-launch": { type: "boolean" },
    },
  });
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const port = values.port ? Number.parseInt(values.port, 10) : 4317;
  const host = values.host ?? "127.0.0.1";
  const webRoot = values["no-web"] ? undefined : (values["web-root"] ?? resolveWebRoot());
  if (!values["no-web"] && !webRoot) {
    console.error("warning: webui dist not found (build @veritas/webui first); serving API/WS only");
  }
  // WebUI auth (2 roles): operator = full access / viewer = read-only. ENV is primary, args are the fallback. --no-auth disables it.
  //   operator: --password / env VERDICT_WEB_PASSWORD   viewer: --viewer-password / env VERDICT_WEB_PASSWORD_VIEWER
  //   The old names AMRAAM_WEB_PASSWORD[_VIEWER] are also accepted as fallbacks (so existing .env files don't break).
  const operatorPw = values["no-auth"] ? undefined : (process.env.VERDICT_WEB_PASSWORD ?? process.env.AMRAAM_WEB_PASSWORD ?? values.password);
  const viewerPw = values["no-auth"] ? undefined : (process.env.VERDICT_WEB_PASSWORD_VIEWER ?? process.env.AMRAAM_WEB_PASSWORD_VIEWER ?? values["viewer-password"]);
  if (!operatorPw && viewerPw) {
    console.error("error: a viewer password was set without an operator password — set VERDICT_WEB_PASSWORD (or --password) too.");
    process.exit(1);
  }
  const authPasswords = operatorPw ? { operator: operatorPw, ...(viewerPw ? { viewer: viewerPw } : {}) } : undefined;
  // Launch/stop/resume runs from the WebUI (the server spawns the CLI as a child process). --no-launch disables it.
  // Requires launching from the built CLI (dist/main.js); spawning isn't possible under tsx dev.
  const cliPath = process.argv[1] ?? "";
  const canLaunch = !values["no-launch"] && cliPath.endsWith(".js");
  const runLauncher = canLaunch
    ? { runsDir, cliPath, nodePath: process.execPath, onLog: (m: string) => console.log(`  ${m}`) }
    : undefined;

  const srv = await startServer({
    runsDir,
    port,
    host,
    ...(webRoot ? { webRoot } : {}),
    ...(authPasswords ? { authPasswords } : {}),
    ...(runLauncher ? { runLauncher } : {}),
    onLog: (m) => console.log(`  ${m}`),
  });
  const authLabel = authPasswords ? (authPasswords.viewer ? ", 🔒 auth on (operator+viewer)" : ", 🔒 auth on (operator)") : "";
  console.log(
    `veritas server: http://${host}:${srv.port}  (runs: ${runsDir}${webRoot ? "" : ", API/WS only"}${authLabel}${runLauncher ? ", ▶ launch on" : ""})`,
  );
  if (host === "0.0.0.0") {
    console.log("  ⚠ listening on all interfaces. from the LAN: http://<this-machine-ip>:" + srv.port + "/");
    if (!authPasswords) console.log("  ⚠ exposed without auth. gate the WebUI with env VERDICT_WEB_PASSWORD (operator) [+ VERDICT_WEB_PASSWORD_VIEWER].");
  }
  console.log("Ctrl-C to stop");
  let stopping = false;
  const shutdown = (): void => {
    if (stopping) return; // don't double-close on repeated presses (avoids the MaxListeners warning)
    stopping = true;
    console.log("\nshutting down …");
    const force = setTimeout(() => process.exit(0), 2000); // exit for sure even if connections remain
    void srv.close().then(() => {
      clearTimeout(force);
      process.exit(0);
    });
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

// Backfill a screenshot for each screen of an existing run (for WebUI display). Doesn't re-run the assessment; opens just
// one of screen.observedUrls and captures it. Reuses the run's browser-profile, so authed screens can be captured too (if the session is alive).
async function cmdShots(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
    },
  });
  if (!values.id) fail("shots requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const browserPath = values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH);
  const artifactsDir = join(runsDir, id, "artifacts");
  console.log(`▶ shots ${id}: ${state.screens.length} screens (reusing the run's browser-profile)`);
  const driver = await PlaywrightDriver.launch({
    userDataDir: join(runsDir, id, "browser-profile"),
    headless: !values.headed,
    ...(browserPath ? { executablePath: browserPath } : {}),
    ...(values["no-sandbox"] ? { args: ["--no-sandbox"] } : {}),
  });

  let n = 0;
  try {
    for (const screen of state.screens) {
      const url = screen.observedUrls.find((u) => isInScope(u, state.scope));
      if (!url) continue;
      try {
        await driver.visit(url);
        const rel = `screens/${screen.screenId}.png`;
        if (await driver.saveScreenshot(join(artifactsDir, rel))) {
          store.upsertScreen(id, { ...screen, screenshot: rel });
          n += 1;
          console.log(`  ✓ ${screen.screenId}  ${screen.urlTemplate}`);
        }
      } catch (e) {
        console.log(`  ✗ ${screen.screenId}  ${screen.urlTemplate} — ${String(e).slice(0, 80)}`);
      }
    }
  } finally {
    await driver.close();
    store.close();
  }
  console.log(`\n${n}/${state.screens.length} screenshots captured → reload the WebUI (serve)`);
}

// ASR — Attack Surface Recon (Phase-0, docs/ASR.md). A wildcard/apex → crt.sh passive discovery → dns resolve +
// HTTP liveness → (optional) per-host screenshot → runs/<id>/asset_inventory.json. Wide-shallow triage feeding pilot.
// P0: passive discovery + liveness + screenshots + inventory. Active DNS brute, scoring and AI triage are later slices.
async function cmdAsr(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      domain: { type: "string" },
      id: { type: "string" },
      manifest: { type: "string" },
      "out-of-scope": { type: "string" },
      screenshot: { type: "boolean" },
      paths: { type: "boolean" },
      triage: { type: "boolean" },
      "triage-top": { type: "string" },
      model: { type: "string" },
      "max-hosts": { type: "string" },
      rate: { type: "string" },
      out: { type: "string" },
      import: { type: "string" },
      "import-trust-liveness": { type: "boolean" },
      "allow-degraded": { type: "boolean" },
      tools: { type: "string" },
      "no-tools": { type: "boolean" },
      brute: { type: "boolean" },
      wordlist: { type: "string" },
      resolvers: { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
    },
  });
  if (!values.domain) fail("asr requires --domain <apex|*.wildcard> (e.g. --domain '*.example.com')");
  const apex = values.domain.trim().toLowerCase().replace(/^\*\./, "").replace(/\.$/, "");
  const base = `https://${apex}`;
  try {
    parseTargetUrl(base); // the apex must form a valid http(s) origin
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  const outOfScope = (values["out-of-scope"] ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const maxHosts = values["max-hosts"] ? Math.max(1, Number.parseInt(values["max-hosts"], 10)) : 200;
  const minDelayMs = values.rate ? Math.max(0, Number.parseInt(values.rate, 10)) : 250;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;

  const scope: ScopePolicy = {
    ...deriveScopeFromUrls([base], "etld"),
    inScopeHosts: [`*.${apex}`], // scope to the operator's --domain, not the registrable domain (a deep apex must not widen)
    outOfScopeHosts: outOfScope.map((d) => (d.startsWith("*.") ? d : `*.${d}`)), // carve-outs enforced at the probe gate too, not just discovery
  };
  const id = values.id ?? newAssessmentId(); // the WebUI launch passes a pre-generated id via the supervisor
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  if (!store.loadAssessment(id)) {
    // fresh run; a --id re-scan (resume) reuses the existing assessment row (avoids a UNIQUE conflict)
    store.createAssessment({ id, target: { kind: "single_url", url: base, followLinks: false, maxDepth: 0 }, scope });
  }
  store.close(); // assets persist to asset_inventory.json, not the store (a store table is a later slice)
  const invPath = join(runsDir, id, "asset_inventory.json");
  writeAssetInventory(invPath, buildAssetInventory(apex, [])); // write empty now so the WebUI detects an ASR run while it scans

  // ① DISCOVER — merge sources (passive crt.sh CT logs + offline --import of recon.sh output), then funnel the whole set
  //   through the ONE scope filter (§1.2) + the probe-loop isInScope backstop. crt.sh touches no target host; import is offline.
  const importPath = values.import;
  const trustLiveness = !!values["import-trust-liveness"];
  console.log(`▶ asr ${id}: discovering *.${apex} via crt.sh${importPath ? ` + import(${importPath})` : ""}…`);
  let crtHosts: string[] = [];
  let crtFailed: string | null = null;
  try {
    crtHosts = await discoverCrtSh({ domain: apex, outOfScope }, fetchHttpGet);
  } catch (e) {
    crtFailed = String(e).slice(0, 160);
    console.error(`  crt.sh discovery failed: ${crtFailed}`);
  }
  const crtCandidates = crtHosts.map((h) => ({ host: h, source: "crt.sh" as const }));
  const importCandidates = importPath ? importRecon(importPath) : [];
  // subfinder (PASSIVE external tool: aggregates OSINT feeds, no brute) — auto-run if the binary is present, unless
  // --no-tools; --tools <list> opts specific tools in/out. A missing binary degrades to [] + a one-line note.
  const toolsList = values.tools ? values.tools.split(",").map((t) => t.trim()).filter(Boolean) : null;
  const subfinderEnabled = !values["no-tools"] && (toolsList === null || toolsList.includes("subfinder"));
  if (subfinderEnabled) console.log("▶ subfinder: querying passive feeds…"); // pre-run line so the Log doesn't look stuck on the crt.sh error during subfinder's ~45s
  const sf = subfinderEnabled ? await subfinderDiscover(execFileRunTool, apex) : { candidates: [], missing: false };
  if (subfinderEnabled && sf.missing) console.log("  subfinder not installed — skipping (install it or pass --no-tools to silence)");
  else if (subfinderEnabled) console.log(`  subfinder: ${sf.candidates.length} host(s)`);
  // --brute (ACTIVE, opt-in): resolve <word>.<apex> against a resolver pool. dnsx if present (needs a wordlist FILE, so
  // the bundled default is materialized to a run-dir file), else the native node:dns fallback (zero external deps).
  let bruteCandidates: HostCandidate[] = [];
  if (values.brute) {
    const wlPathGiven = values.wordlist;
    const words = wlPathGiven ? parseWordlist(readFileSync(wlPathGiven, "utf8")) : DEFAULT_SUBDOMAIN_WORDLIST;
    // dnsx reads a file; if none was given, write the bundled default beside the run so dnsx and native brute the same set.
    const dnsxWordlist = wlPathGiven ?? join(runsDir, id, "brute-wordlist.txt");
    if (!wlPathGiven) writeFileSync(dnsxWordlist, DEFAULT_SUBDOMAIN_WORDLIST.join("\n") + "\n");
    console.log(`▶ brute: resolving ${words.length} subdomain word(s) under *.${apex} (ACTIVE — dnsx or native node:dns)…`);
    // Fast reachability probe (~8s) so a dnsx whose resolvers are unreachable doesn't dead-air the full brute timeout
    // (~60s) before we fall back. A healthy dnsx answers in well under a second. Then dnsx brute (native on error),
    // else straight to the native node:dns brute (system resolver — works even where dnsx's public resolvers don't).
    const dnsxOk = await dnsxReachable(execFileRunTool, apex, values.resolvers ? { resolvers: values.resolvers } : undefined);
    if (dnsxOk) {
      const dx = await dnsxBrute(execFileRunTool, apex, { wordlist: dnsxWordlist, ...(values.resolvers ? { resolvers: values.resolvers } : {}) });
      if (dx.failed) console.log("  dnsx errored mid-run — native node:dns fallback");
      bruteCandidates = dx.failed ? await nativeBrute((h) => resolve4(h).catch(() => []), apex, words, { concurrency: 10 }) : dx.candidates;
    } else {
      console.log("  dnsx unavailable / resolvers unreachable — using native node:dns brute (system resolver)");
      bruteCandidates = await nativeBrute((h) => resolve4(h).catch(() => []), apex, words, { concurrency: 10 });
    }
    console.log(`  brute: ${bruteCandidates.length} host(s) resolved`);
  }
  const merged = mergeCandidates(crtCandidates, importCandidates, sf.candidates, bruteCandidates);
  const inScopeHosts = new Set(filterInScope(merged.map((c) => c.host), { domain: apex, outOfScope })); // same filter as crt.sh
  let candidates = merged.filter((c) => inScopeHosts.has(c.host));
  console.log(
    `  ${crtCandidates.length} crt.sh${importPath ? ` + ${importCandidates.length} import` : ""}${subfinderEnabled && !sf.missing ? ` + ${sf.candidates.length} subfinder` : ""}${values.brute ? ` + ${bruteCandidates.length} brute` : ""} → ${candidates.length} in-scope host(s)`,
  );
  // A crt.sh (primary-source) outage DEGRADES the map but does NOT discard a run other sources still populated:
  // subfinder / --import / brute routinely carry a run on their own (subfinder alone returned 2564 hosts where crt.sh
  // timed out). We refuse only to present a degraded map as COMPLETE — brand it `degraded` + warn loudly — and hard-stop
  // solely when the whole result is empty, cleanly (a one-line error, NOT the usage dump) and overridable with --allow-degraded.
  let degraded: { reason: string } | undefined;
  if (crtFailed) {
    const action = primarySourceFailureAction({ primaryFailed: true, otherHostCount: candidates.length, allowDegraded: !!values["allow-degraded"] });
    degraded = { reason: `crt.sh (a primary source) failed: ${crtFailed} — map built from the remaining sources (subfinder/import/brute); may be INCOMPLETE` };
    if (action.abort) {
      writeAssetInventory(invPath, buildAssetInventory(apex, [], new Date(), undefined, degraded));
      console.error(
        `\nerror: discovery found 0 hosts and crt.sh (a primary source) failed: ${crtFailed}\n` +
          `  nothing to assess — this looks like a source outage, not necessarily an empty surface.\n` +
          `  → retry when crt.sh recovers (it 502s under load), add --import <recon.json|hosts.txt>, or pass --allow-degraded to accept an empty result.`,
      );
      process.exit(1);
    }
    console.log(`  ⚠ DEGRADED: crt.sh failed — proceeding with ${candidates.length} host(s) from the other sources; asset map marked INCOMPLETE.`);
  }
  if (candidates.length > maxHosts) {
    // Order by probe priority BEFORE the cap so a flood of auto-generated ephemeral hosts (deep CNAME chains / random
    // leftmost labels, e.g. *.hydra.<apex> from CT logs) doesn't starve the budget of high-value named hosts.
    candidates = orderCandidatesForProbe(candidates);
    console.log(`  capping to --max-hosts ${maxHosts} (${candidates.length - maxHosts} dropped; named/shallow hosts prioritized over ephemeral)`);
    candidates = candidates.slice(0, maxHosts);
  }

  // ② PROBE — dns resolve + HTTP liveness (scope-gated + rate-limited via FetchHttpClient)
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, scope), minDelayMs, timeoutMs: 10_000 });
  const assets: Asset[] = [];
  // Probe one candidate → Asset. A resolving-but-dead host costs ~20s (https 10s + http 10s timeout), so the loop below
  // runs these CONCURRENTLY (each worker probes a DIFFERENT host, so no single host is hit more than its own 1-2 GETs).
  const probeOne = async (cand: (typeof candidates)[number]): Promise<Asset> => {
    const host = cand.host;
    if (trustLiveness && cand.hint && cand.hint.alive != null) {
      // --import-trust-liveness: trust the imported httpx liveness/fingerprint — no re-probe
      return {
        host,
        source: cand.source,
        resolved: [],
        alive: cand.hint.alive,
        scheme: cand.hint.scheme ?? (cand.hint.alive ? "https" : null),
        status: cand.hint.status ?? null,
        title: cand.hint.title ?? null,
        tech: cand.hint.tech ?? (cand.hint.server ? [cand.hint.server] : []),
        screenshot: null,
        inScope: isInScope(`https://${host}/`, scope),
      };
    }
    const p = await probeHost(
      host,
      async (h) => {
        try {
          return (await lookup(h, { all: true })).map((a) => a.address);
        } catch {
          return [];
        }
      },
      (url) => http.send({ method: "GET", url }),
      (h) => resolveCname(h).catch(() => []),
    );
    const asset: Asset = {
      host,
      source: cand.source, // provenance from the merged candidate, not hardcoded
      resolved: p.addresses,
      alive: p.alive,
      scheme: p.scheme,
      status: p.status,
      title: p.title,
      tech: p.server ? [p.server] : [],
      screenshot: null,
      inScope: isInScope(`https://${host}/`, scope),
    };
    const tko = detectTakeover({ cnames: p.cnames, status: p.status, body: p.bodySample });
    if (tko) {
      asset.takeover = tko;
      console.log(`  ! ${host}: possible subdomain takeover — ${tko.service} (${tko.confidence})`);
    }
    return asset;
  };
  // Bounded-concurrency probe pool: dead hosts (which each block ~20s on timeouts) overlap instead of stacking, so
  // probing N hosts is ~(dead-host-seconds / concurrency) rather than the sum. Each worker takes a distinct candidate.
  const PROBE_CONCURRENCY = 8;
  let pIdx = 0;
  const probeWorker = async (): Promise<void> => {
    for (;;) {
      const cand = candidates[pIdx++]; // idx++ is synchronous between awaits → each worker gets a distinct host
      if (!cand) break;
      const asset = await probeOne(cand);
      assets.push(asset);
      console.log(asset.alive ? `  ✓ ${asset.host}  ${asset.status ?? ""} ${asset.title ?? ""}`.trimEnd() : `  · ${asset.host}`);
      // Incremental write → the WebUI (polling /assets) shows hosts appear. First 10 completions each write (immediate
      // feedback), then every 10 (bounded I/O). Writes are synchronous so concurrent workers don't corrupt the file.
      if (assets.length <= 10 || assets.length % 10 === 0) writeAssetInventory(invPath, buildAssetInventory(apex, assets, new Date(), candidates.length, degraded));
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(PROBE_CONCURRENCY, candidates.length)) }, () => probeWorker()));
  const live = assets.filter((a) => a.alive);

  // ③ SCREENSHOT (optional) — one nav per live host, scope-gated
  if (values.screenshot && live.length > 0) {
    const browserPath = values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH);
    const artifactsDir = join(runsDir, id, "artifacts");
    console.log(`▶ screenshotting ${live.length} live host(s)…`);
    const driver = await PlaywrightDriver.launch({
      userDataDir: join(runsDir, id, "browser-profile"),
      headless: !values.headed,
      ...(browserPath ? { executablePath: browserPath } : {}),
      ...(values["no-sandbox"] ? { args: ["--no-sandbox"] } : {}),
    });
    try {
      for (const a of live) {
        const url = `${a.scheme}://${a.host}/`;
        if (!isInScope(url, scope)) continue;
        try {
          await driver.visit(url);
          const rel = `hosts/${a.host}.png`;
          if (await driver.saveScreenshot(join(artifactsDir, rel))) {
            a.screenshot = rel;
            console.log(`  ✓ ${a.host}`);
          }
        } catch (e) {
          console.log(`  ✗ ${a.host} — ${String(e).slice(0, 60)}`);
        }
      }
    } finally {
      await driver.close();
    }
  }

  // ③b SURFACE (P1, opt-in) — curated path probing on live in-scope hosts → real exposure + auto-escalate
  if (values.paths && live.length > 0) {
    console.log(`▶ probing curated paths on ${live.length} live host(s)…`);
    for (const a of live) {
      if (!a.scheme || !isInScope(`${a.scheme}://${a.host}/`, scope)) continue;
      a.notablePaths = await probeSurface(a.host, a.scheme, (u) => http.send({ method: "GET", url: u }));
      if (a.notablePaths.length > 0) {
        console.log(`  ${a.host}: ${a.notablePaths.map((h) => (h.escalate ? `⚠${h.path}` : h.path)).join(", ")}`);
      }
      // open directory listing → enumerate it into a tree (depth/entry-bounded)
      if ((a.title ?? "").toLowerCase().includes("index of")) {
        a.listing = await enumerateListing(`${a.scheme}://${a.host}`, "/", (u) => http.send({ method: "GET", url: u }));
        if (a.listing.length > 0) console.log(`  ${a.host}: open directory listing (${a.listing.length} top-level entries)`);
      }
    }
  }

  // ④ SCORE — recon findings + deterministic attack-target rubric, then rank by band (auto-escalate first), then score
  for (const a of assets) a.findings = reconFindings(a);
  for (const a of assets) a.score = scoreAsset(a);
  const bandRank = (b: string | undefined): number => (b === "critical" ? 3 : b === "high" ? 2 : b === "medium" ? 1 : 0);
  assets.sort(
    (x, y) =>
      bandRank(y.score?.band) - bandRank(x.score?.band) ||
      (y.score?.total ?? 0) - (x.score?.total ?? 0) ||
      Number(y.alive) - Number(x.alive) ||
      x.host.localeCompare(y.host),
  );

  // ④b AI TRIAGE (P1, opt-in) — Claude classifies the top-scoring live hosts (category/band/angle). A lead, not a finding.
  if (values.triage) {
    const topN = values["triage-top"] ? Math.max(1, Number.parseInt(values["triage-top"], 10)) : 15;
    const targets = assets.filter((a) => a.alive).slice(0, topN);
    if (targets.length > 0) {
      const llm = new ClaudeCliClient({});
      console.log(`▶ AI triage on the top ${targets.length} live host(s)…`);
      for (const a of targets) {
        try {
          a.ai = (await triageAsset(a, llm, values.model)) ?? undefined;
          if (a.ai) console.log(`  [${a.ai.band}] ${a.host} — ${a.ai.category}${a.ai.angle ? `: ${a.ai.angle}` : ""}`);
        } catch (e) {
          console.log(`  ✗ ${a.host}: ${String(e).slice(0, 70)}`);
        }
      }
    }
  }

  // ⑤ persist the asset inventory (overwrite the early empty file with the scored, ranked set)
  writeAssetInventory(invPath, buildAssetInventory(apex, assets, new Date(), candidates.length, degraded));
  console.log(`\nasr ${id}: ${assets.length} asset(s), ${live.length} live → ${invPath}`);
  const top = assets.filter((a) => a.alive).slice(0, 10);
  if (top.length > 0) {
    console.log(`  top targets by score:`);
    for (const a of top) {
      console.log(`    [${(a.score?.band ?? "low").padEnd(8)} ${String(a.score?.total ?? 0).padStart(3)}]  ${a.host}  ${a.status ?? ""}`);
    }
  }
  console.log(`  view in the WebUI: serve → open ${id} → Assets tab`);
}

// Info-level security-header audit (deterministic, no LLM). Checks each screen's response headers in an existing run
// and records one (aggregated) finding per missing header. Toggle = run it or not.
// --headers csp,hsts,… narrows the set (custom list).
async function cmdHeaderAudit(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: { id: { type: "string" }, out: { type: "string" }, headers: { type: "string" }, rate: { type: "string" }, manifest: { type: "string" } },
  });
  if (!values.id) fail("header-audit requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const wanted = values.headers ? new Set(values.headers.split(",").map((s) => s.trim().toLowerCase())) : null;
  const rules = wanted ? SECURITY_HEADERS.filter((r) => wanted.has(r.key)) : SECURITY_HEADERS;
  const minDelay = values.rate ? Number.parseInt(values.rate, 10) : 250;
  const haHeaders = manifestAuthHeaders(values.manifest ? loadManifest(values.manifest) : null); // auth + custom headers → measure behind-login header posture, not the login/WAF page
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, state.scope), minDelayMs: minDelay, headers: haHeaders });
  const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));
  console.log(`▶ header-audit ${id}: ${state.screens.length} screens × [${rules.map((r) => r.key).join(",")}]`);

  // Aggregate the screens/URLs where each rule was missing. Record one piece of evidence from the first example.
  const missing = new Map<string, { rule: (typeof rules)[number]; urls: string[]; evId: string | null }>();
  for (const screen of state.screens) {
    const url = screen.observedUrls.find((u) => isInScope(u, state.scope));
    if (!url) continue;
    let res;
    try {
      res = await http.send({ method: "GET", url, headers: {}, body: null });
    } catch {
      continue;
    }
    for (const r of auditHeaders(res.headers, url, rules)) {
      const e = missing.get(r.key) ?? { rule: r, urls: [], evId: null };
      e.urls.push(url);
      if (!e.evId) {
        const ev = evidence.record({
          screenId: screen.screenId,
          validator: "header-audit",
          kind: "positive_replay",
          request: { method: "GET", url, headers: {}, body: null },
          response: res,
          note: `missing ${r.header}`,
        });
        e.evId = ev.id;
      }
      missing.set(r.key, e);
    }
  }

  for (const [, e] of missing) {
    store.upsertFinding(id, {
      id: `h-${e.rule.key}`, // stable id -> a re-run overwrites (idempotent)
      screenId: null,
      title: `[headers] ${e.rule.title}`,
      severity: e.rule.severity,
      source: { kind: "validator", validatorName: "header-audit" },
      description: `${e.rule.note} Missing on ${e.urls.length} page(s). e.g.: ${e.urls.slice(0, 5).join(", ")}`,
      reproSteps: `GET the target URL -> confirm the response has no '${e.rule.header}' header.`,
      evidenceIds: e.evId ? [e.evId] : [],
      scopeBasis: "authorized in-scope screens",
    });
    console.log(`  + h-${e.rule.key} [${e.rule.severity}] ${e.rule.title} (${e.urls.length} pages)`);
  }
  store.close();
  console.log(`\n${missing.size} header finding(s) recorded → reload the WebUI (toggle info via the severity filter)`);
}

// Merge Burp issues (from XML or REST) into a run. Deduplicates against existing findings by (coarse category × normalized endpoint)
// and drops out-of-scope ones. Shared logic used by both burp-import and burp-scan.
// Delegates to scanner's shared merge (only injecting crawler's normalizePath for endpoint normalization).
// The CLI only logs the number imported (the server reflects it to the WebUI over WS).
function mergeBurpIssues(
  store: AssessmentStore,
  id: string,
  state: AssessmentState,
  runsDir: string,
  issues: ReadonlyArray<BurpIssue>,
  prefix = "b",
): { added: number; skipped: number; oos: number } {
  const before = store.loadAssessment(id)?.findings.length ?? state.findings.length;
  const res = scannerMergeBurpIssues(store, id, state, join(runsDir, id, "artifacts"), issues, {
    prefix,
    pathTemplate: (p) => normalizePath(p).template,
  });
  if (res.added) console.log(`  + ${res.added} net-new finding(s) merged (from ${before} existing)`);

  // ── info triage ── verifyImportedBurp only re-verifies High+. Everything below (Information/Low/Medium)
  //    passes straight through, but "entry points to real vulns" hide in there — reflection->XSS, external interaction->SSRF, loose CORS->data theft…
  //    Rather than verify all of them (operator's policy), triage by name and surface **only the promising leads**.
  const subHigh = issues.filter((i) => {
    if (/high|critical/i.test(i.severity)) return false; // High+ is the verify phase's job
    let url: string;
    try {
      url = new URL(i.path || "/", i.host).toString();
    } catch {
      url = i.host;
    }
    return isInScope(url, state.scope);
  });
  const leads = triageBurpInfo(subHigh);
  if (leads.length) {
    const lines = formatBurpLeads(leads);
    console.log(`  🔎 Burp info triage — ${leads.length} promising lead type(s) below High (verify covers High+ only; not auto-verified):`);
    for (const ln of lines) console.log(`     ${ln}`);
    const notable = leads.filter((l) => l.priority !== "low");
    store.appendEvent(id, {
      type: "note",
      payload: {
        message:
          `🔎 Burp info triage: ${leads.length} lead(s) worth a look (High+ go to verify; these don't) — ` +
          formatBurpLeads(notable.length ? notable : leads)
            .slice(0, 8)
            .join(" | "),
      },
    });
  }
  return res;
}

// Import a Burp Pro XML report, adding only net-new issues that don't duplicate existing findings.
// Flow: pilot --burp-proxy <burp> routes all traffic through Burp -> scan in Burp -> export the report XML
// -> import it with this command. Deduplication is by (coarse category × normalized endpoint).
async function cmdBurpImport(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      report: { type: "string" },
      out: { type: "string" },
      manifest: { type: "string" }, // pass Basic credentials for re-verifying authed findings (optional)
      "no-burp-verify": { type: "boolean" },
      "no-burp-triage": { type: "boolean" }, // keep High+ verification but disable only the sub-High lead deep-dive phase
      model: { type: "string" },
    },
  });
  if (!values.id) fail("burp-import requires --id <assessment-id>");
  if (!values.report) fail("burp-import requires --report <burp-report.xml>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  if (!existsSync(values.report)) fail(`no report at ${values.report}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const issues = parseBurpReport(readFileSync(values.report, "utf8"));
  const { added, skipped, oos } = mergeBurpIssues(store, id, state, runsDir, issues);
  console.log(`\nburp-import ${id}: ${issues.length} issue(s) → +${added} net-new(dup ${skipped} / out-of-scope ${oos})`);
  // AI actively re-verifies the imported Burp High+ (same phase as the REST path). --no-burp-verify disables it.
  if (added > 0 && !values["no-burp-verify"]) {
    const bmani = values.manifest ? loadManifest(values.manifest) : null;
    const httpBasic = manifestHttpBasic(bmani);
    const importCustomHeaders = manifestCustomHeaders(bmani);
    await verifyImportedBurp(store, id, runsDir, { ...(values.model ? { model: values.model } : {}), httpBasic, ...(importCustomHeaders ? { customHeaders: importCustomHeaders } : {}), triage: !values["no-burp-triage"] });
    const fs2 = store.loadAssessment(id);
    if (fs2) writeFileSync(join(runsDir, id, "report.md"), buildReport(fs2, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }));
  }
  store.close();
}

/** Fall back to the spec's own declared base when --url is omitted: servers[0].url (3.x) or schemes+host+basePath (2.0). */
function deriveSpecBase(rawDoc: unknown): string | null {
  const doc = rawDoc && typeof rawDoc === "object" ? (rawDoc as Record<string, unknown>) : null;
  if (!doc) return null;
  const servers = doc["servers"];
  if (Array.isArray(servers) && servers[0] && typeof servers[0] === "object") {
    const u = (servers[0] as Record<string, unknown>)["url"];
    if (typeof u === "string" && /^https?:\/\//i.test(u)) return u;
  }
  const host = typeof doc["host"] === "string" ? (doc["host"] as string) : null; // Swagger 2.0
  if (host) {
    const schemes = Array.isArray(doc["schemes"]) ? (doc["schemes"] as unknown[]) : [];
    const scheme = schemes.includes("https") ? "https" : typeof schemes[0] === "string" ? (schemes[0] as string) : "https";
    const basePath = typeof doc["basePath"] === "string" ? (doc["basePath"] as string) : "";
    return `${scheme}://${host}${basePath}`;
  }
  return null;
}

// Ingest a provided OpenAPI 3.x / Swagger 2.0 spec → seed the screen inventory, so the browser-free `scan`/`logic`
// steps can assess a pure-API target (or overlay a spec on a crawl with --id). Mirrors the burp-import shape.
async function cmdSpecImport(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      spec: { type: "string" },
      url: { type: "string" },
      id: { type: "string" },
      manifest: { type: "string" },
      out: { type: "string" },
    },
  });
  if (!values.spec) fail("spec-import requires --spec <openapi.json>");
  if (!existsSync(values.spec)) fail(`no spec at ${values.spec}`);
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(values.spec, "utf8"));
  } catch (e) {
    fail(`spec is not valid JSON (${String(e).slice(0, 100)}). YAML specs aren't supported yet — convert to JSON first.`);
  }
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const manifest = values.manifest ? loadManifest(values.manifest) : null;

  const base = values.url ?? deriveSpecBase(doc);
  if (!base) fail("spec-import requires --url <base-url> (the spec declares no absolute server URL)");
  try {
    parseTargetUrl(base); // require an http(s) scheme (same gate as scope derivation)
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }

  let id: string;
  let store: AssessmentStore;
  let existing: Screen[] = [];
  if (values.id) {
    id = values.id;
    const dbPath = dbPathFor(runsDir, id);
    if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
    store = AssessmentStore.open(dbPath);
    const state = store.loadAssessment(id);
    if (!state) {
      store.close();
      fail(`assessment ${id} not found`);
    }
    existing = state.screens;
  } else {
    id = newAssessmentId();
    mkdirSync(join(runsDir, id), { recursive: true });
    const mode: ScopeMode = manifest?.scopeMode ?? "same-origin";
    const scope: ScopePolicy = { ...deriveScopeFromUrls([base], mode), ...(manifest?.scope ?? {}) };
    store = AssessmentStore.open(dbPathFor(runsDir, id));
    store.createAssessment({ id, target: { kind: "single_url", url: base, followLinks: false, maxDepth: 0 }, scope });
  }

  const screens = parseOpenApiToScreens(doc, base, existing);
  for (const sc of screens) store.upsertScreen(id, sc);
  writeScreenInventory(join(runsDir, id, "screen_inventory.json"), buildInventory(base, screens));
  store.close();

  const ops = screens.reduce((n, s) => n + s.apis.length, 0);
  const suffix = values.id ? ` (+${screens.length - existing.length} net-new over the crawl)` : " (fresh run)";
  console.log(`\nspec-import ${id}: ${screens.length} screen(s), ${ops} operation(s)${suffix} → ${join(runsDir, id, "screen_inventory.json")}`);
  console.log(`  next: scan --id ${id}${values.manifest ? ` --manifest ${values.manifest}` : ""}  then  logic --id ${id}${values.manifest ? ` --manifest ${values.manifest}` : ""}  then  report --id ${id}`);
}

// Resolve Burp REST connection info in the order "arg -> env -> default". env: BURP_API / BURP_API_KEY / BURP_RESOURCE_POOL.
interface BurpRestConn {
  base: string;
  apiKey?: string;
  resourcePool: string; // "" = Burp's default pool
}
function resolveBurpRest(v: { "burp-api"?: string; "api-key"?: string; "resource-pool"?: string }): BurpRestConn {
  const base = v["burp-api"] ?? process.env.BURP_API ?? "http://127.0.0.1:1337";
  const apiKey = v["api-key"] ?? process.env.BURP_API_KEY;
  const resourcePool = v["resource-pool"] !== undefined ? v["resource-pool"] : (process.env.BURP_RESOURCE_POOL ?? "250ms");
  return { base, ...(apiKey ? { apiKey } : {}), resourcePool };
}

// operator 提供の Burp CustomConfiguration を読み込んで重ねる(named config の後勝ち)。スキーマはバージョン
// 依存なので VERDICT は生成せず、Burp から export した JSON をそのまま渡す。値は {{COOKIE}}/{{BEARER}} を live
// セッションで差し替える(置換後に JSON 妥当性チェック)。
//   - BURP_SCAN_CONFIG_FILE: 普段使う scan policy(監査ポリシー = ScanPolicy.json 等)
//   - BURP_SESSION_CONFIG_FILE: セッション注入の session-handling rule(認証下スキャン)
function loadBurpCustomConfig(file: string | undefined, label: string, cookie: string, bearer: string): string | null {
  if (!file) return null;
  if (!existsSync(file)) {
    console.log(`  ⚠ ${label} not found: ${file} — skipping that config`);
    return null;
  }
  try {
    const tpl = readFileSync(file, "utf8").replaceAll("{{COOKIE}}", cookie).replaceAll("{{BEARER}}", bearer);
    JSON.parse(tpl); // 壊れた JSON を Burp に送らない
    return tpl;
  } catch (e) {
    console.log(`  ⚠ ${label} invalid JSON after substitution (${String(e).slice(0, 120)}) — skipping that config`);
    return null;
  }
}

function buildBurpCustomConfigs(cookie: string, bearer: string): string[] {
  const out: string[] = [];
  const scan = loadBurpCustomConfig(process.env.BURP_SCAN_CONFIG_FILE, "BURP_SCAN_CONFIG_FILE", cookie, bearer);
  if (scan) {
    out.push(scan);
    console.log("  ⚙ using your scan policy from BURP_SCAN_CONFIG_FILE");
  }
  const sess = loadBurpCustomConfig(process.env.BURP_SESSION_CONFIG_FILE, "BURP_SESSION_CONFIG_FILE", cookie, bearer);
  if (sess) {
    out.push(sess);
    console.log(`  🔐 session injection via BURP_SESSION_CONFIG_FILE (cookie ${cookie ? "✓" : "—"} / bearer ${bearer ? "✓" : "—"})`);
  } else if ((cookie || bearer) && !process.env.BURP_SESSION_CONFIG_FILE) {
    console.log("  ℹ session present but BURP_SESSION_CONFIG_FILE unset → Burp scans UNAUTHENTICATED.");
    console.log("    Build a Burp session-handling rule with 'Set a specific cookie/header', export it,");
    console.log("    put {{COOKIE}} / {{BEARER}} where the value goes, and set BURP_SESSION_CONFIG_FILE.");
  }
  return out;
}

// Burp 能動スキャンを 1 つの run に対して実行(start→poll→merge→report)。store の open/close は呼び出し側が管理。
// 非致命: Burp が無い/失敗しても例外で run を落とさず、ログして added=0 を返す(pilot --burp-scan から呼ぶため)。
async function runBurpScanOnRun(
  store: AssessmentStore,
  id: string,
  state: AssessmentState,
  runsDir: string,
  o: { conn: BurpRestConn; configs: string[]; configReason?: string; logins: Array<{ username: string; password: string }>; pollSec: number; maxMin: number; verify?: boolean; verifyModel?: string; httpBasic?: { user: string; pass: string } | null; customHeaders?: Record<string, string>; onPoll?: () => Promise<void>; customConfigs?: string[] },
): Promise<number> {
  const { base, apiKey, resourcePool } = o.conn;
  const usePool = resourcePool !== "";
  const candidates: string[] = [];
  if ("url" in state.target && state.target.url) candidates.push(state.target.url);
  for (const sc of state.screens) {
    for (const u of sc.observedUrls ?? []) {
      const u0 = u.split("#")[0] ?? u;
      if (isInScope(u0, state.scope)) candidates.push(u0);
    }
  }
  // 同一エンドポイント(パス + クエリ param 名)の値違いを1本に畳む(/login?next=… の大量スキャン生成を防ぐ)。
  const urls = dedupSeedUrls(candidates).slice(0, 300);
  if (urls.length === 0) {
    console.log("⚠ burp-scan: no in-scope URLs, skipping (run survey/pilot first)");
    return 0;
  }
  console.log(`▶ burp-scan ${id} → ${base}`);
  console.log(`  config: ${o.configs.join(" + ")}${o.configReason ? ` (${o.configReason})` : ""}${usePool ? ` | pool: ${resourcePool}` : " | pool: (Burp default)"} | seeds: ${urls.length}${o.logins.length ? ` | auth: ${o.logins.length}` : ""}`);

  const startScan = (pool: string | undefined, customs: string[] | undefined): Promise<string> =>
    startBurpScan({ base, ...(apiKey ? { apiKey } : {}), urls, configs: o.configs, ...(pool ? { resourcePool: pool } : {}), ...(o.logins.length ? { logins: o.logins } : {}), ...(customs && customs.length ? { customConfigs: customs } : {}) });

  const pool0 = usePool ? resourcePool : undefined;
  const customs0 = o.customConfigs && o.customConfigs.length ? o.customConfigs : undefined;
  let taskId: string;
  try {
    taskId = await startScan(pool0, customs0);
  } catch (e) {
    const msg = String(e);
    if (customs0) {
      // operator の CustomConfiguration(scan policy / session 注入)が弾かれた可能性 → 無しで再試行(スキャン自体は走らせる)。
      console.log(`⚠ scan start with your CustomConfiguration failed (${msg.slice(0, 120)}); retrying WITHOUT it (auto config / UNAUTHENTICATED). Check BURP_SCAN_CONFIG_FILE / BURP_SESSION_CONFIG_FILE against your Burp.`);
      try {
        taskId = await startScan(pool0, undefined);
      } catch (e2) {
        if (usePool && /resource pool/i.test(String(e2))) {
          try {
            taskId = await startScan(undefined, undefined);
          } catch (e3) {
            console.log(`⚠ burp-scan start failed: ${String(e3).slice(0, 160)} — skipping`);
            return 0;
          }
        } else {
          console.log(`⚠ burp-scan start failed: ${String(e2).slice(0, 160)} — skipping`);
          return 0;
        }
      }
    } else if (usePool && /resource pool/i.test(msg)) {
      console.log(`⚠ resource pool "${resourcePool}" not found in Burp, continuing on the default pool (create a concurrency 1 / Delay 250ms pool to throttle).`);
      try {
        taskId = await startScan(undefined, undefined);
      } catch (e2) {
        console.log(`⚠ burp-scan start failed: ${String(e2).slice(0, 160)} — skipping`);
        return 0;
      }
    } else {
      console.log(`⚠ burp-scan start failed: ${msg.slice(0, 160)}\n  → Burp Pro REST enabled? base=${base} / key? — skipping`);
      return 0;
    }
  }
  console.log(`  scan task ${taskId} started; polling every ${o.pollSec}s (timeout ${o.maxMin}m)…`);

  const deadline = Date.now() + o.maxMin * 60_000;
  let last: Awaited<ReturnType<typeof getBurpScan>> | null = null;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, o.pollSec * 1000));
    await o.onPoll?.(); // セッション維持(authed Burp スキャン中に Cookie/トークンを stale 化させない)
    try {
      last = await getBurpScan(base, apiKey, taskId);
    } catch (e) {
      console.log(`  ⚠ poll error: ${String(e).slice(0, 120)}`);
      continue;
    }
    console.log(`  [${last.status}] progress ${last.progress}% · ${last.issueEvents} issue event(s)`);
    if (last.status === "succeeded" || last.status === "failed") break;
  }
  if (!last) {
    console.log("⚠ burp-scan: couldn't get scan status (timeout) — skipping");
    return 0;
  }
  if (last.status !== "succeeded") console.log(`⚠ scan ended status=${last.status} — importing the issues found so far`);

  const { added, skipped, oos } = mergeBurpIssues(store, id, state, runsDir, last.issues, "bs");
  console.log(`\nburp-scan ${id}: ${last.issues.length} issue(s) → +${added} net-new(dup ${skipped} / out-of-scope ${oos})`);
  if (added > 0) {
    if (o.verify !== false) await verifyImportedBurp(store, id, runsDir, { ...(o.verifyModel ? { model: o.verifyModel } : {}), httpBasic: o.httpBasic ?? null, ...(o.customHeaders ? { customHeaders: o.customHeaders } : {}) });
    const fs2 = store.loadAssessment(id);
    if (fs2) writeFileSync(join(runsDir, id, "report.md"), buildReport(fs2, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }));
  }
  return added;
}

// Burp 取り込み後の検証フェーズ: 取り込んだ Burp 由来 High+ を AI が能動再テスト(verifyBurpFindings)。
// REST(burp-scan)・XML(burp-import)両方の取り込み経路から呼ぶ共通ヘルパ。非致命(失敗しても run は継続)。
async function verifyImportedBurp(
  store: AssessmentStore,
  id: string,
  runsDir: string,
  o: { model?: string; httpBasic?: { user: string; pass: string } | null; cookie?: string; bearer?: string; customHeaders?: Record<string, string>; triage?: boolean },
): Promise<void> {
  const st = store.loadAssessment(id);
  if (!st) return;
  const scope = st.scope;
  const rpm = scope.rate?.requestsPerMinute ?? 30;
  const minDelayMs = Math.max(0, Math.floor(60_000 / Math.max(1, rpm)));
  const artifactsDir = join(runsDir, id, "artifacts");
  // 認証下 finding(Bearer 必須の /profile など)を再現できるよう、http クライアントに session を載せる。
  const sessionHeaders: Record<string, string> = {
    ...(o.customHeaders ?? {}), // operator custom headers (WAF-bypass / mandated) — carry them so a real finding isn't block-paged on re-verify and silently refuted
    ...(o.cookie ? { cookie: o.cookie } : {}),
    ...(o.bearer ? { authorization: `Bearer ${o.bearer}` } : basicHeader(o.httpBasic ?? null)),
  };
  const http = new FetchHttpClient({ allow: (u) => isInScope(u, scope), minDelayMs, headers: sessionHeaders });
  const evidence = new EvidenceStore(artifactsDir);
  // Attach a headless browser so XSS leads get an ACTUAL-EXECUTION DOM re-test (probe_dom_xss) — raw HTTP can't see
  // client-side / SPA / hash-route sinks, which is why HTTP-only re-verification mislabels DOM-XSS as false positives.
  // Best-effort: reuses the run's browser-profile (carries auth); if chromium is unavailable the re-verify degrades to
  // HTTP-only (unchanged behaviour). --no-sandbox because this ephemeral nav runs headless in the same envs the pilot does.
  const browserPath = process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH;
  let driver: PlaywrightDriver | undefined;
  try {
    driver = await PlaywrightDriver.launch({
      userDataDir: join(runsDir, id, "browser-profile"),
      headless: true,
      args: ["--no-sandbox"],
      ...(browserPath ? { executablePath: browserPath } : {}),
    });
  } catch (e) {
    console.log(`  (DOM-XSS re-verify browser unavailable — HTTP-only: ${String(e).slice(0, 80)})`);
    driver = undefined;
  }
  try {
    const res = await verifyBurpFindings({
      store,
      assessmentId: id,
      scope,
      http,
      evidence,
      artifactsDir,
      ...(driver ? { driver } : {}),
      ...(o.cookie ? { cookie: o.cookie } : {}),
      ...(o.bearer ? { bearer: o.bearer } : {}),
      ...(o.model ? { model: o.model } : {}),
      onText: (t) => console.log(`  🔎 ${t.slice(0, 200)}`),
      onTool: (n, i) => console.log(`    ⚙ ${n.replace("mcp__veritas__", "")} ${JSON.stringify(i).slice(0, 120)}`),
    });
    if (res.checked > 0)
      console.log(`▶ burp-verify ${id}: ${res.checked} High+ re-tested → ${res.confirmed} confirmed ✓ / ${res.inconclusive} inconclusive ~ / ${res.refuted} not reproduced ?`);

    // ── 深堀フェーズ ── High+ の後に、sub-High リード(info/low/medium)の **タイトル一覧をモデルに見せて
    //    有望なものを選ばせ、選ばれた分だけ同じ証拠規律で能動再テスト**する。全部はやらない(operator 方針)。
    if (o.triage !== false) {
      const t = await triageAndDeepDiveBurp({
        store,
        assessmentId: id,
        scope,
        http,
        evidence,
        artifactsDir,
        ...(driver ? { driver } : {}),
        ...(o.cookie ? { cookie: o.cookie } : {}),
        ...(o.bearer ? { bearer: o.bearer } : {}),
        ...(o.model ? { model: o.model } : {}),
        onText: (txt) => console.log(`  🔬 ${txt.slice(0, 200)}`),
        onTool: (n, i) => console.log(`    ⚙ ${n.replace("mcp__veritas__", "")} ${JSON.stringify(i).slice(0, 120)}`),
      });
      if (t.listed > 0)
        console.log(
          `▶ burp-triage ${id}: ${t.listed} sub-High lead(s) listed → model deep-dived ${t.selected} → ${t.confirmed} confirmed ✓ / ${t.inconclusive} inconclusive ~ / ${t.refuted} not reproduced ?`,
        );
    }
  } catch (e) {
    console.log(`⚠ burp-verify skipped: ${String(e).slice(0, 160)}`);
  } finally {
    await driver?.close();
  }
}

// ── VERDICT Audit REST(別ポート 1338)経由のスキャン ──
// 標準 REST(1337)と違い「認証済みの生リクエストをそのまま投入」する(セッション内包)。VERDICT が
// inventory の in-scope エンドポイントを live Cookie/Bearer 込みの生リクエストにして送る → Burp が認証下を能動監査。

/** JsonShape → 具体的なボディ例(reqSchema からダミー値)。Burp の insertion point 用。 */
function exampleFromShape(shape: { type: string; fields?: Record<string, unknown>; items?: unknown }): unknown {
  switch (shape.type) {
    case "object": {
      const o: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(shape.fields ?? {})) o[k] = exampleFromShape(v as { type: string });
      return o;
    }
    case "array":
      return [exampleFromShape((shape.items ?? { type: "string" }) as { type: string })];
    case "number":
      return 1;
    case "boolean":
      return true;
    case "null":
      return null;
    default:
      return "test";
  }
}

/** inventory(in-scope の観測 URL + 非 GET API)→ 認証スキャン用のリクエスト仕様。 */
function collectAuditRequests(state: AssessmentState): Array<{ method: string; url: string; body?: string; contentType?: string }> {
  const specs: Array<{ method: string; url: string; body?: string; contentType?: string }> = [];
  // 1) 観測した具体 URL を GET(クエリ値そのまま = 良い insertion point)。パス+param 名で dedup。
  const observed = state.screens.flatMap((sc) => (sc.observedUrls ?? []).map((u) => u.split("#")[0] ?? u)).filter((u) => isInScope(u, state.scope));
  for (const u of dedupSeedUrls(observed)) specs.push({ method: "GET", url: u });
  // 2) フォーム/ XHR の非 GET API。urlTemplate を具体化({x}→1)し reqSchema からボディを合成。
  const base = "url" in state.target && state.target.url ? state.target.url : observed[0] ?? "";
  const seen = new Set<string>();
  for (const sc of state.screens) {
    for (const api of sc.apis ?? []) {
      const m = api.method.toUpperCase();
      if (m === "GET" || m === "HEAD") continue;
      const key = `${m} ${api.urlTemplate}`;
      if (seen.has(key)) continue;
      seen.add(key);
      let abs: string;
      try {
        abs = new URL(api.urlTemplate.replace(/\{[^}]+\}/g, "1"), base).toString();
      } catch {
        continue;
      }
      if (!isInScope(abs, state.scope)) continue;
      const body = api.reqSchema ? JSON.stringify(exampleFromShape(api.reqSchema as { type: string })) : null;
      specs.push({ method: m, url: abs, ...(body ? { body, contentType: "application/json" } : {}) });
    }
  }
  return specs.slice(0, 300);
}

/** VERDICT Audit REST 経由でスキャン(submit→poll→issues→merge→verify→report)。非致命。 */
async function runBurpAuditOnRun(
  store: AssessmentStore,
  id: string,
  state: AssessmentState,
  runsDir: string,
  o: { conn: BurpAuditConn; cookie: string; bearer: string; httpBasic?: { user: string; pass: string } | null; customHeaders?: Record<string, string>; verify?: boolean; verifyModel?: string; pollSec: number; maxMin: number; onPoll?: () => Promise<void> },
): Promise<number> {
  const sessionHeaders: Record<string, string> = { ...(o.customHeaders ?? {}) }; // operator custom headers (WAF-bypass / mandated) carry into every Burp-audited raw request
  if (o.cookie) sessionHeaders.Cookie = o.cookie;
  if (o.bearer) sessionHeaders.Authorization = `Bearer ${o.bearer}`;
  else if (o.httpBasic) sessionHeaders.Authorization = `Basic ${Buffer.from(`${o.httpBasic.user}:${o.httpBasic.pass}`, "utf8").toString("base64")}`;

  const specs = collectAuditRequests(state);
  if (specs.length === 0) {
    console.log("⚠ burp-audit: no in-scope endpoints (run survey/pilot first) — skipping");
    return 0;
  }
  console.log(`▶ burp-audit ${id} → ${o.conn.base} | ${specs.length} authenticated request(s) (cookie ${o.cookie ? "✓" : "—"} / bearer ${o.bearer ? "✓" : "—"})`);

  const startTs = Date.now();
  await resetAudit(o.conn); // この拡張の蓄積をクリア(過去 run の issue を混ぜない)

  const hostKeys = new Set<string>();
  let submitted = 0;
  for (const spec of specs) {
    try {
      const u = new URL(spec.url);
      const port = u.port ? Number(u.port) : u.protocol === "https:" ? 443 : 80;
      const raw = buildRawRequest({
        method: spec.method,
        pathWithQuery: u.pathname + u.search,
        hostHeader: u.host,
        headers: sessionHeaders,
        ...(spec.body ? { body: spec.body, contentType: spec.contentType } : {}),
      });
      const key = await submitAudit(o.conn, { host: u.hostname, port, secure: u.protocol === "https:", auditMode: "active", request: raw });
      hostKeys.add(key);
      submitted += 1;
    } catch (e) {
      console.log(`  ⚠ submit failed for ${spec.method} ${spec.url}: ${String(e).slice(0, 120)}`);
    }
  }
  if (submitted === 0) {
    console.log("⚠ burp-audit: nothing submitted — is the extension up? (BURP_AUDIT_API / token) — skipping");
    return 0;
  }
  console.log(`  submitted ${submitted}; polling every ${o.pollSec}s (timeout ${o.maxMin}m)…`);

  const deadline = Date.now() + o.maxMin * 60_000;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, o.pollSec * 1000));
    await o.onPoll?.();
    let statuses;
    try {
      statuses = await getAuditStatusAll(o.conn);
    } catch (e) {
      console.log(`  ⚠ poll error: ${String(e).slice(0, 120)}`);
      continue;
    }
    const mine = statuses.filter((s) => hostKeys.has(s.host));
    const reqs = mine.reduce((n, s) => n + s.requestsMade, 0);
    console.log(`  [${mine.map((s) => s.status).join(", ") || "?"}] ${reqs} requests`);
    if (mine.length > 0 && mine.every((s) => /finished|succeeded|failed|paused/i.test(s.status))) break;
  }

  let issues;
  try {
    issues = await getAuditIssues(o.conn, { since: startTs });
  } catch (e) {
    console.log(`⚠ burp-audit /issues failed: ${String(e).slice(0, 160)} — skipping import`);
    return 0;
  }
  const { added, skipped, oos } = scannerMergeBurpIssues(store, id, state, join(runsDir, id, "artifacts"), issues, {
    prefix: "ba",
    pathTemplate: (p) => normalizePath(p).template,
  });
  console.log(`\nburp-audit ${id}: ${issues.length} issue(s) → +${added} net-new(dup ${skipped} / out-of-scope ${oos})`);
  if (added > 0) {
    // Audit 経路は authed セッション(cookie/bearer)を持つので再検証にも渡す(/profile 等の認証下 finding を再現可能に)。
    if (o.verify !== false)
      await verifyImportedBurp(store, id, runsDir, {
        ...(o.verifyModel ? { model: o.verifyModel } : {}),
        httpBasic: o.httpBasic ?? null,
        ...(o.cookie ? { cookie: o.cookie } : {}),
        ...(o.bearer ? { bearer: o.bearer } : {}),
        ...(o.customHeaders ? { customHeaders: o.customHeaders } : {}),
      });
    const fs2 = store.loadAssessment(id);
    if (fs2) writeFileSync(join(runsDir, id, "report.md"), buildReport(fs2, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }));
  }
  return added;
}

/** Audit REST 接続を env(BURP_AUDIT_API / BURP_AUDIT_TOKEN)から解決。未設定なら null(=標準 REST 1337 を使う)。 */
function resolveBurpAudit(): BurpAuditConn | null {
  const base = process.env.BURP_AUDIT_API;
  if (!base) return null;
  const token = process.env.BURP_AUDIT_TOKEN;
  return { base, ...(token ? { token } : {}) };
}

// Burp Pro の REST API を叩いて能動スキャンを起動 → 完了までポーリング → issue を取り込む(XML export 不要のライブ版)。
// 対象URL = AI がマップした in-scope の具体URL(=実質 AI が対象を決める)。検査内容 = Burp の named config(--config)。
// 接続情報は引数 → env(BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL)→ 既定 で解決。
async function cmdBurpScan(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      id: { type: "string" },
      out: { type: "string" },
      "burp-api": { type: "string" },
      "api-key": { type: "string" },
      config: { type: "string", multiple: true },
      "resource-pool": { type: "string" },
      manifest: { type: "string" },
      "max-min": { type: "string" },
      poll: { type: "string" },
      "no-burp-verify": { type: "boolean" },
      model: { type: "string" }, // 検証に使うモデル(任意)
    },
  });
  if (!values.id) fail("burp-scan requires --id <assessment-id>");
  const id = values.id;
  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const dbPath = dbPathFor(runsDir, id);
  if (!existsSync(dbPath)) fail(`no state.sqlite at ${dbPath}`);
  const store = AssessmentStore.open(dbPath);
  const state = store.loadAssessment(id);
  if (!state) {
    store.close();
    fail(`assessment ${id} not found in ${dbPath}`);
  }

  const conn = resolveBurpRest(values);
  // --config は複数指定可(クロール速度 + 監査内容を別プリセットで重ねる)。無指定なら surface から自動選択。
  const auto = values.config?.length ? null : pickBurpConfigs(state);
  const configs = auto ? auto.configs : values.config!;
  const configReason = auto ? `auto: ${auto.reason}` : "manual --config";
  const pollSec = values.poll ? Number.parseInt(values.poll, 10) : 10;
  const maxMin = values["max-min"] ? Number.parseInt(values["max-min"], 10) : 30;
  // 認証スキャン(任意): manifest の資格情報を Burp の application_logins に渡す。
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const logins = manifestRoleCreds(manifest).map((rc) => ({ username: rc.creds.username, password: rc.creds.password }));
  const httpBasic = manifestHttpBasic(manifest);
  const scanCustomHeaders = manifestCustomHeaders(manifest);

  try {
    await runBurpScanOnRun(store, id, state, runsDir, {
      conn,
      configs,
      configReason,
      logins,
      pollSec,
      maxMin,
      verify: !values["no-burp-verify"],
      ...(values.model ? { verifyModel: values.model } : {}),
      httpBasic,
      ...(scanCustomHeaders ? { customHeaders: scanCustomHeaders } : {}),
    });
  } finally {
    store.close();
  }
}

// 対話型 scope-manifest ジェネレータ(独立して使える。pilot/assess が読む JSON を組み立てる)。
async function cmdManifest(args: string[]): Promise<void> {
  const { values } = parseArgs({ args, options: { out: { type: "string" }, force: { type: "boolean" } } });
  const { createInterface } = await import("node:readline/promises");
  const isTty = process.stdin.isTTY === true;
  const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: isTty });

  // 行キュー(readline/promises の question はパイプ入力で 2 問目以降ハングするので 'line' イベントで読む)。
  const queue: string[] = [];
  const waiters: Array<{ res: (v: string) => void; rej: (e: Error) => void }> = [];
  let closed = false;
  rl.on("line", (l) => {
    const w = waiters.shift();
    if (w) w.res(l);
    else queue.push(l);
  });
  rl.on("close", () => {
    closed = true;
    while (waiters.length) waiters.shift()?.rej(new Error("input closed"));
  });
  // パスワードのエコーを伏せる(端末スクロールバック/肩越し対策)。readline の出力フックを mute フラグで制御。
  let muted = false;
  const ri = rl as unknown as { _writeToOutput?: (s: string) => void };
  const baseWrite = ri._writeToOutput?.bind(ri);
  if (baseWrite) ri._writeToOutput = (s: string): void => { if (!muted) baseWrite(s); };

  const readLine = (): Promise<string> => {
    const q = queue.shift();
    if (q !== undefined) return Promise.resolve(q);
    if (closed) return Promise.reject(new Error("input closed"));
    return new Promise((res, rej) => waiters.push({ res, rej }));
  };
  const ask = async (q: string, def?: string): Promise<string> => {
    process.stdout.write(def ? `${q} [${def}]: ` : `${q}: `);
    const a = (await readLine()).trim();
    return a || def || "";
  };
  const askBool = async (q: string, def: boolean): Promise<boolean> =>
    (await ask(`${q} (y/n)`, def ? "y" : "n")).toLowerCase().startsWith("y");
  const askInt = async (q: string, def: number): Promise<number> => {
    const n = Number.parseInt(await ask(q, String(def)), 10);
    return Number.isFinite(n) ? n : def;
  };
  const askList = async (q: string): Promise<string[]> => {
    const a = await ask(q);
    return a ? a.split(",").map((s) => s.trim()).filter(Boolean) : [];
  };
  const askSecret = async (q: string): Promise<string> => {
    process.stdout.write(`${q}: `);
    muted = true;
    try {
      return (await readLine()).trim();
    } finally {
      muted = false;
      process.stdout.write("\n");
    }
  };

  type Role = { name: string; description?: string; username?: string; password?: string; cookieFile?: string };

  try {
    console.log("\n=== VERDICT scope-manifest generator ===");
    console.log("authorized targets only. press Enter for the default at each prompt.\n");

    let target = "";
    while (!target) {
      target = await ask("Target seed URL (e.g. https://app.example.com/)");
      try {
        new URL(target);
      } catch {
        console.log("  ↳ please enter a valid URL");
        target = "";
      }
    }
    const host = new URL(target).host;

    console.log(`\n--- scope (default in-scope: ${host}) ---`);
    const extraHosts = await askList("additional in-scope hosts (comma-separated, optional)");
    const inScopeHosts = [...new Set([host, ...extraHosts])];
    const outOfScopeHosts = await askList("Out-of-scope hosts (optional)");
    const outOfScopePathPrefixes = await askList("Out-of-scope path prefixes (e.g. /logout,/signout)");
    const approvalPathPrefixes = await askList("path prefixes that need approval (sensitive areas. e.g. /admin)");
    const requestsPerMinute = await askInt("Rate: requests / minute", 30);
    const maxConcurrent = await askInt("Rate: max concurrent", 2);

    console.log("\n--- crawl ---");
    const followLinks = await askBool("follow links?", true);
    const maxDepth = await askInt("max depth", 10);

    const model = await ask("\nModel", "claude-sonnet-5");

    console.log("\n--- auth roles (empty name + Enter to finish) ---");
    console.log("  either credentials or a pre-captured cookie file. [0]=primary login, multiple = auth-diff.");
    const roles: Role[] = [];
    for (;;) {
      const name = await ask(`\nRole #${roles.length + 1} name (empty to finish)`);
      if (!name) break;
      // 権限レベルの説明(任意)。auth-diff で「どれが高権限/低権限か」をエージェントが判断する材料。
      const description = await ask("  description/privilege (optional. e.g. full admin / regular user (read-only))");
      const kind = (await ask("  type: (c)credentials / (k)cookie file", "c")).toLowerCase();
      if (kind.startsWith("k")) {
        const cookieFile = await ask("  path to cookie file");
        if (cookieFile) roles.push({ name, ...(description ? { description } : {}), cookieFile });
        else console.log("  ↳ no path entered, skipping");
      } else {
        const username = await ask("  username (empty to use the role name)");
        const password = await askSecret("  password");
        if (password) roles.push({ name, ...(description ? { description } : {}), ...(username ? { username } : {}), password });
        else console.log("  ↳ no password entered, skipping");
      }
    }

    const manifest: AssessManifest = {
      target,
      scope: {
        inScopeHosts,
        outOfScopeHosts,
        inScopePathPrefixes: ["/"],
        outOfScopePathPrefixes,
        approvalPathPrefixes,
        approvalMethods: ["DELETE", "PUT", "PATCH"],
        rate: { requestsPerMinute, maxConcurrent },
      },
      crawl: { followLinks, maxDepth },
      model,
    };
    if (roles.length) manifest.auth = { roles };

    const safeHost = host.replace(/[^a-zA-Z0-9._-]/g, "_");
    const outPath = values.out ?? (await ask("\noutput file", `scope_manifest_${safeHost}.json`));
    if (existsSync(outPath) && !values.force) {
      if (!(await askBool(`${outPath} already exists. overwrite?`, false))) {
        console.log("aborted.");
        return;
      }
    }
    writeFileSync(outPath, `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`\n✓ written: ${outPath}`);
    if (roles.length) {
      console.log("⚠ contains credentials/cookies = a secret file. make sure it matches the gitignored pattern scope_manifest_*.json.");
    }
    console.log(`\nCommand:\n  node packages/cli/dist/main.js pilot --manifest ${outPath} --model ${model}\n`);
  } finally {
    rl.close();
  }
}

// LLM / AI-assistant red-team: drive a deployed chatbot's chat UI and confirm canary leaks (@veritas/llm-attacks).
async function cmdRedteam(rawArgs: string[]): Promise<void> {
  const { values } = parseArgs({
    args: rawArgs,
    options: {
      manifest: { type: "string" },
      url: { type: "string" },
      id: { type: "string" },
      out: { type: "string" },
      canary: { type: "string" },
      "max-replays": { type: "string" },
      "browser-path": { type: "string" },
      "no-sandbox": { type: "boolean" },
      headed: { type: "boolean" },
      headless: { type: "boolean" },
      composer: { type: "string" },
      send: { type: "string" },
      "new-chat": { type: "string" },
      "file-input": { type: "string" },
      transcript: { type: "string" },
      "control-url": { type: "string" },
    },
  });

  const runsDir = values.out ?? RUNS_DIR_DEFAULT;
  const manifest = values.manifest ? loadManifest(values.manifest) : null;
  const assistant = manifest?.assistant;
  const chatUrl = assistant?.chatUrl ?? manifest?.target ?? values.url ?? "";
  if (!chatUrl) fail("redteam requires --url <chat-ui-url> or --manifest <file.json> (assistant.chatUrl / target)");

  const canary = values.canary ?? assistant?.canary;
  if (!canary) {
    fail(
      "redteam needs a canary planted out-of-band in the assistant's protected context (system prompt / custom " +
        "instructions), supplied via --canary <token> or manifest assistant.canary. Generate one: " +
        generateCanary() +
        "  (the file-upload seedMode that plants the canary for you lands in a later slice.)",
    );
  }

  const scope = { ...deriveScopeFromUrls([chatUrl], manifest?.scopeMode ?? "same-origin"), ...(manifest?.scope ?? {}) };
  if (!isInScope(chatUrl, scope)) {
    fail(
      `redteam: chat URL ${chatUrl} is out of scope — check manifest.scope / scopeMode. The scope gate applies to ` +
        "the assistant's chat URL too; a seat is not authorization to red-team a vendor's product.",
    );
  }
  if (values["max-replays"] !== undefined) {
    const n = Number(values["max-replays"]);
    if (!Number.isInteger(n) || n < 1) fail(`--max-replays must be a positive integer (got ${values["max-replays"]})`);
  }
  const id = values.id ?? newAssessmentId();
  mkdirSync(join(runsDir, id), { recursive: true });
  const store = AssessmentStore.open(dbPathFor(runsDir, id));
  store.createAssessment({
    id,
    target: { kind: "single_url", url: chatUrl, followLinks: false, maxDepth: 0 },
    scope,
  });

  const browserPath = values["browser-path"] ?? (process.env.VERDICT_BROWSER_PATH ?? process.env.VERITAS_BROWSER_PATH);
  const headed = !values.headless && !!values.headed;
  const maxReplays = values["max-replays"] ? Number.parseInt(values["max-replays"], 10) : 2;
  const controlUrl = values["control-url"]; // attended: screencast the chat into the WebUI Sessions tab for manual login
  const httpBasic = manifestHttpBasic(manifest);
  const customHeaders = manifestCustomHeaders(manifest);

  const driver = await PlaywrightDriver.launch({
    userDataDir: join(runsDir, id, "browser-profile"),
    headless: controlUrl ? true : !headed, // web-attended screencasts headless into the WebUI; else --headed opens a window
    ...(browserPath ? { executablePath: browserPath } : {}),
    ...(values["no-sandbox"] ? { args: ["--no-sandbox"] } : {}),
    ...(httpBasic ? { httpCredentials: { username: httpBasic.user, password: httpBasic.pass } } : {}),
    ...(customHeaders ? { extraHeaders: customHeaders } : {}),
  });

  console.log(`▶ redteam ${id}  (assistant @ ${chatUrl})`);
  let live: LiveControl | undefined;
  try {
    await driver.visit(chatUrl);
    const composer = values.composer ?? assistant?.composerSelector;
    const send = values.send ?? assistant?.sendSelector;
    const newChat = values["new-chat"] ?? assistant?.newChatSelector;
    const fileInput = values["file-input"] ?? assistant?.fileInputSelector;
    const transcript = values.transcript ?? assistant?.transcriptSelector;
    const adapter = new BrowserChatAdapter(driver, {
      chatUrl,
      ...(controlUrl ? { noReload: true } : {}), // attended widget: never reload the page (destroys the manual session)
      ...(composer ? { composerSelectors: [composer] } : {}),
      ...(send ? { sendSelectors: [send] } : {}),
      ...(newChat ? { newChatSelectors: [newChat] } : {}),
      ...(fileInput ? { fileInputSelector: fileInput } : {}),
      ...(transcript ? { transcriptSelector: transcript } : {}),
    });

    if (controlUrl) {
      // Attended: screencast the chat page into the WebUI Sessions tab. The operator navigates to the RIGHT
      // assistant, pastes + sends a calibration marker, then clicks Done — findMarker locates that frame + input
      // (works even for an iframe widget). Blocking before the probes avoids operator + adapter typing at once.
      live = new LiveControl(controlUrl, (m) => console.log(m));
      await live.register("chat", driver);
      const calMarker = generateCanary();
      store.appendEvent(id, { type: "note", payload: { message: `attended — in the Sessions tab, paste this marker into the assistant's message box and SEND it, then click Done: ${calMarker}` } });
      console.log(`  ⏸ Sessions tab: paste & send this marker into the assistant box, then click Done:\n     ${calMarker}`);
      await live.waitForDone("chat");
      const frame = await adapter.calibrate(calMarker);
      const where =
        frame === null
          ? "not found — probes target the top document (may be the wrong input)"
          : frame === ""
            ? "top document"
            : `frame ${frame}`;
      store.appendEvent(id, { type: "note", payload: { message: `calibration: ${where}` } });
      console.log(`  calibration → ${where}`);
    }

    const evidence = new EvidenceStore(join(runsDir, id, "artifacts"));
    const probes = defaultInjectedContextProbes(canary).map((p) => ({ ...p, replays: maxReplays }));
    store.setPhase(id, "phase2_scan");
    store.appendEvent(id, { type: "note", payload: { message: `running ${probes.length} probes against ${chatUrl}` } });
    const res = await runLlmRedteam({
      store,
      assessmentId: id,
      chatUrl,
      adapter,
      evidence,
      probes,
      onProbe: (p, v) => {
        const mark = v.status === "confirmed" ? "✓" : v.status === "suspected" ? "?" : "·";
        store.appendEvent(id, { type: "note", payload: { message: `${mark} ${p.id} [${p.category}] → ${v.status}` } });
        console.log(`  ${mark} ${p.id} [${p.category}] → ${v.status}`);
      },
    });

    const finalState = store.loadAssessment(id);
    if (finalState) {
      writeFileSync(
        join(runsDir, id, "report.md"),
        buildReport(finalState, new Date(), { loadEvidence: evidenceLoaderFor(runsDir, id) }),
      );
    }
    store.appendEvent(id, { type: "note", payload: { message: `done — ${res.findings.length} finding(s) across ${res.verdicts.length} probes` } });
    store.setPhase(id, "done");
    console.log(`\n=== ${res.findings.length} finding(s) across ${res.verdicts.length} probes ===`);
    for (const f of res.findings) console.log(`  - [${f.severity}] ${f.title}`);
    console.log(`\nreport → ${join(runsDir, id, "report.md")}`);
    console.log(`observe: if serve is running, http://127.0.0.1:4317/?id=${id}`);
  } finally {
    live?.close();
    await driver.close();
    store.close();
  }
}

async function main(): Promise<void> {
  // cwd の .env を自動ロード(shell の export が優先・未設定キーだけ反映)。BURP_* / VERITAS_BROWSER_PATH 等。
  const loadedEnv = loadDotEnv();
  if (loadedEnv.length) console.error(`(.env → ${loadedEnv.join(", ")})`);
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case "manifest":
    case "init":
      await cmdManifest(rest);
      return;
    case "assess":
      await cmdAssess(rest);
      return;
    case "pilot":
      await cmdPilot(rest);
      return;
    case "redteam":
    case "assistant":
      await cmdRedteam(rest);
      return;
    case "run":
      cmdRun(rest);
      return;
    case "crawl":
      await cmdCrawl(rest);
      return;
    case "label":
      await cmdLabel(rest);
      return;
    case "scan":
      await cmdScan(rest);
      return;
    case "logic":
      await cmdLogic(rest);
      return;
    case "serve":
      await cmdServe(rest);
      return;
    case "report":
      await cmdReport(rest);
      return;
    case "inventory":
      cmdInventory(rest);
      return;
    case "openapi":
      cmdOpenApi(rest);
      return;
    case "shots":
      await cmdShots(rest);
      return;
    case "header-audit":
      await cmdHeaderAudit(rest);
      return;
    case "burp-scan":
      await cmdBurpScan(rest);
      return;
    case "burp-import":
      await cmdBurpImport(rest);
      return;
    case "spec-import":
      await cmdSpecImport(rest);
      return;
    case "asr":
      await cmdAsr(rest);
      return;
    case "status":
      cmdStatus(rest);
      return;
    case "list":
      cmdList(rest);
      return;
    case undefined:
    case "help":
    case "-h":
    case "--help":
      console.log(USAGE);
      return;
    default:
      fail(`unknown command: ${cmd}`);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
