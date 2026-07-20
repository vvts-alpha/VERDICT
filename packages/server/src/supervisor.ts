// Process supervisor for starting/stopping/resuming runs from the WebUI.
// The server does not import the CLI; it **spawns it as a child process** (CLI = execution engine / server = control plane).
// The child writes runs/<id>/state.sqlite → the existing WS projection live-streams progress as-is. The Phase-1 control plane in docs/LIVE_TAKEOVER.md.
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { newAssessmentId } from "@veritas/core";
import type { Relay } from "./relay.js";

export interface RunLauncherConfig {
  runsDir: string;
  /** Absolute path to the built CLI entry (main.js). Injected by cmdServe. */
  cliPath: string;
  /** The node executable used to launch child processes (default process.execPath). */
  nodePath: string;
  onLog?: (m: string) => void;
}

export interface StartRunInput {
  command: "pilot" | "assess" | "redteam" | "asr";
  /** JSON in AssessManifest format (saved verbatim to runs/<id>/manifest.json). */
  manifest: unknown;
  options?: {
    model?: string;
    fastModel?: string;
    rate?: number;
    maxTurns?: number;
    headed?: boolean;
    surveyOnly?: boolean;
    exhaustive?: boolean;
    attended?: boolean;
    /** Entry URL for manual login (where each role window first opens in attended mode). */
    loginUrl?: string;
    /** Upper bound on the number of screens to diagnose (default 40). 0/unset = default. */
    maxScreens?: number;
    /** Upper bound on the number of screens survey maps. Stop exploring when reached. Unset = unlimited. */
    maxSurveyScreens?: number;
    /** Operator's focus hint (free text). Injected as the top-priority objective of the scenario stage (--focus). */
    focus?: string;
    /** pilot only: keepalive interval in minutes (0 = off). For sites whose session dies on a cold `/` hit / full reload. */
    keepAliveMin?: number;
    /** pilot only: goto-safe authed hub (menu). Reach cold-nav-bouncing routes by clicking their link from here; also the keepalive target. */
    anchorUrl?: string;
    /** pilot only: also run a Burp active scan after diagnosis (connection via env BURP_API). */
    burpScan?: boolean;
    /** pilot only: route all traffic through the Burp proxy (connection via env BURP_PROXY). */
    burpProxy?: boolean;
    /** redteam only: positive replays required to confirm a canary leak (default 2). */
    maxReplays?: number;
    /** asr only: the wildcard/apex to recon (e.g. "*.example.com"). */
    domain?: string;
    /** asr only: hosts to exclude (comma-separated carve-outs). */
    outOfScope?: string;
    /** asr only: screenshot each live host. */
    screenshot?: boolean;
    /** asr only: probe curated high-signal paths on live hosts. */
    paths?: boolean;
    /** asr only: AI-triage the top-scoring hosts. */
    triage?: boolean;
    /** asr only: cap the number of discovered hosts probed. */
    maxHosts?: number;
    /** asr only: opt-in ACTIVE DNS brute (dnsx if present, else native node:dns) — the reliable path when crt.sh/subfinder can't reach the network. */
    brute?: boolean;
    /** asr only: brute wordlist file path (default: bundled ~130). */
    wordlist?: string;
    /** asr only: trusted-resolver file path for the brute. */
    resolvers?: string;
    /** asr only: disable external passive tools (subfinder). */
    noTools?: boolean;
  };
}

interface RunProc {
  id: string;
  command: string;
  child: ChildProcess;
  startedAt: string;
  status: "running" | "exited";
  exitCode: number | null;
}

export class Supervisor {
  private readonly procs = new Map<string, RunProc>();
  private controlBase = ""; // ws://127.0.0.1:<port> (set after listen). Passed to the child in attended mode.

  constructor(
    private readonly cfg: RunLauncherConfig,
    private readonly relay?: Relay,
  ) {}

  /** Call after serve's listen. The target the child (pilot) reverse-connects to. */
  setControlBase(base: string): void {
    this.controlBase = base;
  }

  /** Save the manifest and spawn `<cli> <command> --manifest <f> --id <id> --out <runs>`. Returns the new id. */
  start(input: StartRunInput): { id: string } {
    const id = newAssessmentId();
    const dir = join(this.cfg.runsDir, id);
    mkdirSync(dir, { recursive: true });
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(manifestPath, `${JSON.stringify(input.manifest, null, 2)}\n`);
    // Persist options too so resume can restore the start-time settings (attended/model/burp etc.).
    writeFileSync(join(dir, "run.json"), `${JSON.stringify({ command: input.command, options: input.options ?? {} }, null, 2)}\n`);
    // ASR is detected by the WebUI via asset_inventory.json. Write it empty NOW (before the child has started and
    // written it) so the run opens as an ASR view immediately, not briefly as a web assessment.
    if (input.command === "asr") {
      const apex = (input.options?.domain ?? "").replace(/^\*\./, "").replace(/\.$/, "");
      writeFileSync(join(dir, "asset_inventory.json"), `${JSON.stringify({ version: 1, generatedAt: "", apex, assets: [] }, null, 2)}\n`);
    }

    const args = [this.cfg.cliPath, input.command, "--manifest", manifestPath, "--id", id, "--out", this.cfg.runsDir];
    const o = input.options ?? {};
    if (o.headed) args.push("--headed"); // shared: pilot / assess / redteam all accept --headed
    if (input.command === "redteam") {
      // redteam has a strict, small flag set — do NOT pass pilot/assess-only flags (its parseArgs would reject them).
      // canary + selectors travel in the manifest's `assistant` block, read by cmdRedteam.
      if (o.maxReplays != null) args.push("--max-replays", String(o.maxReplays));
    } else if (input.command === "asr") {
      // asr has its own flag set — do NOT pass pilot/assess flags (its parseArgs would reject them).
      // The domain travels in options; the base args already carry --manifest/--id/--out (cmdAsr accepts them).
      if (o.domain) args.push("--domain", o.domain);
      if (o.outOfScope) args.push("--out-of-scope", String(o.outOfScope));
      if (o.screenshot) args.push("--screenshot");
      if (o.paths) args.push("--paths");
      if (o.triage) args.push("--triage");
      if (o.maxHosts != null) args.push("--max-hosts", String(o.maxHosts));
      if (o.brute) args.push("--brute"); // ACTIVE DNS brute (opt-in)
      if (o.wordlist) args.push("--wordlist", String(o.wordlist));
      if (o.resolvers) args.push("--resolvers", String(o.resolvers));
      if (o.noTools) args.push("--no-tools");
      if (o.model) args.push("--model", o.model);
      if (o.rate != null) args.push("--rate", String(o.rate));
    } else {
      if (o.model) args.push("--model", o.model);
      if (o.fastModel) args.push("--fast-model", o.fastModel);
      if (o.rate != null) args.push("--rate", String(o.rate));
      if (o.maxTurns != null) args.push("--max-turns", String(o.maxTurns));
      if (o.surveyOnly) args.push("--survey-only");
      if (o.exhaustive) args.push("--exhaustive");
      if (o.attended) args.push("--attended");
      if (o.loginUrl) args.push("--login-url", o.loginUrl);
      if (o.maxScreens != null) args.push("--max-screens", String(o.maxScreens));
      if (o.maxSurveyScreens != null) args.push("--max-survey-screens", String(o.maxSurveyScreens));
      if (o.focus) args.push("--focus", o.focus);
      if (o.keepAliveMin != null) args.push("--keepalive-min", String(o.keepAliveMin));
      if (o.anchorUrl) args.push("--anchor-url", o.anchorUrl);
      if (input.command === "pilot" && o.burpScan) args.push("--burp-scan");
      if (input.command === "pilot" && o.burpProxy) args.push("--burp-proxy");
    }
    // attended×LiveHands: the child reverse-connects to serve and screencasts role sessions (token auth).
    if ((input.command === "pilot" || input.command === "redteam") && o.attended && this.relay && this.controlBase) {
      const token = randomBytes(16).toString("hex");
      this.relay.issueToken(id, token);
      args.push("--control-url", `${this.controlBase}/ws/agent?id=${id}&token=${token}`);
    }
    this.spawnChild(id, input.command, args);
    return { id };
  }

  /** Resume diagnosis of an existing run (skip survey/methodology). Restore the start-time manifest/options to
   *  recover the auth material (roleCreds/cookie/httpBasic/attended) (without this, resume floods with 401s while unauthenticated). */
  resume(id: string): void {
    const dir = join(this.cfg.runsDir, id);
    const manifestPath = join(dir, "manifest.json");
    let command = "pilot";
    let o: NonNullable<StartRunInput["options"]> = {};
    try {
      const run = JSON.parse(readFileSync(join(dir, "run.json"), "utf8")) as { command?: string; options?: unknown };
      command = run.command ?? "pilot";
      o = (run.options ?? {}) as NonNullable<StartRunInput["options"]>;
    } catch {
      /* no run.json (old run) → continue as a pilot resume with defaults */
    }

    // ASR is one-shot — "resume" re-runs the scan (asr with the saved options), NOT pilot --resume.
    if (command === "asr") {
      const args = [this.cfg.cliPath, "asr", "--id", id, "--out", this.cfg.runsDir];
      if (o.domain) args.push("--domain", o.domain);
      if (o.outOfScope) args.push("--out-of-scope", String(o.outOfScope));
      if (o.screenshot) args.push("--screenshot");
      if (o.paths) args.push("--paths");
      if (o.triage) args.push("--triage");
      if (o.maxHosts != null) args.push("--max-hosts", String(o.maxHosts));
      if (o.brute) args.push("--brute"); // ACTIVE DNS brute (opt-in)
      if (o.wordlist) args.push("--wordlist", String(o.wordlist));
      if (o.resolvers) args.push("--resolvers", String(o.resolvers));
      if (o.noTools) args.push("--no-tools");
      if (o.model) args.push("--model", o.model);
      if (o.rate != null) args.push("--rate", String(o.rate));
      this.spawnChild(id, "asr (re-scan)", args);
      return;
    }

    const args = [this.cfg.cliPath, "pilot", "--resume", "--id", id, "--out", this.cfg.runsDir];
    if (existsSync(manifestPath)) args.push("--manifest", manifestPath);
    if (o.model) args.push("--model", o.model);
    if (o.fastModel) args.push("--fast-model", o.fastModel);
    if (o.burpProxy) args.push("--burp-proxy"); // valueless flag (reads from BURP_PROXY env)
    if (o.loginUrl) args.push("--login-url", o.loginUrl);
    if (o.maxScreens != null) args.push("--max-screens", String(o.maxScreens));
    if (o.focus) args.push("--focus", o.focus);
    if (o.keepAliveMin != null) args.push("--keepalive-min", String(o.keepAliveMin));
    if (o.anchorUrl) args.push("--anchor-url", o.anchorUrl);
    // attended issues a new control channel (token) to reopen the windows in the WebUI.
    if (o.attended && this.relay && this.controlBase) {
      args.push("--attended");
      const token = randomBytes(16).toString("hex");
      this.relay.issueToken(id, token);
      args.push("--control-url", `${this.controlBase}/ws/agent?id=${id}&token=${token}`);
    }
    this.spawnChild(id, "pilot --resume", args);
  }

  /** Launch a Burp active scan (REST) against an existing run → poll until completion → auto-import issues.
   *  Connection via env (BURP_API/BURP_API_KEY/BURP_RESOURCE_POOL). If a manifest exists, an authenticated scan (application_logins).
   *  config is auto-selected from the surface (pickBurpConfigs). The live-import version that avoids exporting XML by hand. */
  burpScan(id: string): void {
    const dir = join(this.cfg.runsDir, id);
    const args = [this.cfg.cliPath, "burp-scan", "--id", id, "--out", this.cfg.runsDir];
    const manifestPath = join(dir, "manifest.json");
    if (existsSync(manifestPath)) args.push("--manifest", manifestPath);
    this.spawnChild(id, "burp-scan", args);
  }

  /** Import an uploaded Burp XML report into an existing run (merge → AI re-verify High+).
   *  The server does not merge in-process; it spawns the CLI (burp-import) (the verification phase is also consolidated on the CLI side).
   *  If a manifest exists, pass Basic credentials for re-verifying authenticated findings. */
  burpImport(id: string, reportPath: string): void {
    const dir = join(this.cfg.runsDir, id);
    const args = [this.cfg.cliPath, "burp-import", "--id", id, "--out", this.cfg.runsDir, "--report", reportPath];
    const manifestPath = join(dir, "manifest.json");
    if (existsSync(manifestPath)) args.push("--manifest", manifestPath);
    this.spawnChild(id, "burp-import", args);
  }

  /** Launch a Burp active scan (REST) against an existing run → poll until completion → auto-import issues.
   *  Playwright/chromium attach their own SIGTERM handler so graceful close drags on/stalls; kill reliably with SIGKILL. */
  stop(id: string): boolean {
    const rec = this.procs.get(id);
    if (rec && rec.status === "running") {
      rec.child.kill("SIGTERM");
      const t = setTimeout(() => {
        if (rec.status === "running") {
          try {
            rec.child.kill("SIGKILL");
          } catch {
            /* already gone */
          }
        }
      }, 5000);
      t.unref?.();
      return true;
    }
    return false;
  }

  isRunning(id: string): boolean {
    return this.procs.get(id)?.status === "running";
  }

  async closeAll(): Promise<void> {
    for (const rec of this.procs.values()) if (rec.status === "running") this.stop(rec.id);
  }

  private spawnChild(id: string, command: string, args: string[]): void {
    const existing = this.procs.get(id);
    if (existing && existing.status === "running") return; // prevent double launch
    const log = this.cfg.onLog ?? ((): void => {});
    // --disable-warning=ExperimentalWarning: the CLI uses node:sqlite, whose first-use ExperimentalWarning would
    // otherwise hit the child's stderr → run.log → the ASR Log tab (looks like a "SQLite read error"). args[0] is the
    // CLI script path, so the node flag must precede it.
    const child = spawn(this.cfg.nodePath, ["--disable-warning=ExperimentalWarning", ...args], { cwd: process.cwd(), env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    const rec: RunProc = { id, command, child, startedAt: new Date().toISOString(), status: "running", exitCode: null };
    this.procs.set(id, rec);
    // Tee the child's stdout/stderr to runs/<id>/run.log, one timestamped line at a time (the WebUI ASR Log tab
    // renders these with a .log-ts column, like the web diagnostic log).
    const logStream = createWriteStream(join(this.cfg.runsDir, id, "run.log"), { flags: "a" });
    let logBuf = "";
    const stamp = (): string => new Date().toTimeString().slice(0, 8);
    const writeLog = (chunk: string): void => {
      logBuf += chunk;
      let nl = logBuf.indexOf("\n");
      while (nl >= 0) {
        logStream.write(`[${stamp()}] ${logBuf.slice(0, nl)}\n`);
        logBuf = logBuf.slice(nl + 1);
        nl = logBuf.indexOf("\n");
      }
    };
    log(`▶ spawned ${command} ${id} (pid ${child.pid ?? "?"})`);
    child.stdout?.on("data", (d: Buffer) => {
      const s = String(d);
      writeLog(s);
      log(`[${id}] ${s.trimEnd()}`);
    });
    child.stderr?.on("data", (d: Buffer) => {
      const s = String(d);
      writeLog(s);
      log(`[${id}!] ${s.trimEnd()}`);
    });
    child.on("exit", (code) => {
      rec.status = "exited";
      rec.exitCode = code;
      if (logBuf.length) logStream.write(`[${stamp()}] ${logBuf}\n`);
      logStream.end(`[${stamp()}] exited (code ${code ?? "?"})\n`);
      this.relay?.revokeToken(id);
      log(`◼ ${command} ${id} exited (code ${code ?? "?"})`);
    });
  }
}
