// WebUI から run を起動・停止・再開するためのプロセス・スーパーバイザ。
// server は CLI を import せず **子プロセスとして spawn** する(CLI = 実行エンジン / server = 制御面)。
// 子が runs/<id>/state.sqlite を書く → 既存の WS 投影がそのまま進捗をライブ配信する。docs/LIVE_TAKEOVER.md の Phase-1 制御面。
import { spawn, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { newAssessmentId } from "@veritas/core";
import type { Relay } from "./relay.js";

export interface RunLauncherConfig {
  runsDir: string;
  /** ビルド済み CLI エントリ(main.js)の絶対パス。cmdServe が DI。 */
  cliPath: string;
  /** 子プロセスを起動する node 実体(既定 process.execPath)。 */
  nodePath: string;
  onLog?: (m: string) => void;
}

export interface StartRunInput {
  command: "pilot" | "assess";
  /** AssessManifest 形式の JSON(そのまま runs/<id>/manifest.json に保存)。 */
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
    /** pilot のみ: 診断後に Burp 能動スキャンも実施(接続は env BURP_API)。 */
    burpScan?: boolean;
    /** pilot のみ: 全トラフィックを Burp プロキシ経由(接続は env BURP_PROXY)。 */
    burpProxy?: boolean;
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
  private controlBase = ""; // ws://127.0.0.1:<port>(listen 後に設定)。attended 時に子へ渡す。

  constructor(
    private readonly cfg: RunLauncherConfig,
    private readonly relay?: Relay,
  ) {}

  /** serve の listen 後に呼ぶ。子(pilot)が逆接続する先。 */
  setControlBase(base: string): void {
    this.controlBase = base;
  }

  /** manifest を保存し、`<cli> <command> --manifest <f> --id <id> --out <runs>` を spawn。新 id を返す。 */
  start(input: StartRunInput): { id: string } {
    const id = newAssessmentId();
    const dir = join(this.cfg.runsDir, id);
    mkdirSync(dir, { recursive: true });
    const manifestPath = join(dir, "manifest.json");
    writeFileSync(manifestPath, `${JSON.stringify(input.manifest, null, 2)}\n`);

    const args = [this.cfg.cliPath, input.command, "--manifest", manifestPath, "--id", id, "--out", this.cfg.runsDir];
    const o = input.options ?? {};
    if (o.model) args.push("--model", o.model);
    if (o.fastModel) args.push("--fast-model", o.fastModel);
    if (o.rate != null) args.push("--rate", String(o.rate));
    if (o.maxTurns != null) args.push("--max-turns", String(o.maxTurns));
    if (o.headed) args.push("--headed");
    if (o.surveyOnly) args.push("--survey-only");
    if (o.exhaustive) args.push("--exhaustive");
    if (o.attended) args.push("--attended");
    if (input.command === "pilot" && o.burpScan) args.push("--burp-scan");
    if (input.command === "pilot" && o.burpProxy) args.push("--burp-proxy");
    // attended×LiveHands: 子は serve に逆接続して role セッションを screencast する(token 認証)。
    if (input.command === "pilot" && o.attended && this.relay && this.controlBase) {
      const token = randomBytes(16).toString("hex");
      this.relay.issueToken(id, token);
      args.push("--control-url", `${this.controlBase}/ws/agent?id=${id}&token=${token}`);
    }
    this.spawnChild(id, input.command, args);
    return { id };
  }

  /** 既存 run の診断を再開(survey/methodology はスキップ)。 */
  resume(id: string): void {
    const args = [this.cfg.cliPath, "pilot", "--resume", "--id", id, "--out", this.cfg.runsDir];
    this.spawnChild(id, "pilot --resume", args);
  }

  /** 実行中の子を停止(SIGTERM → 猶予後に SIGKILL でエスカレート)。停止に着手したら true。
   *  Playwright/chromium は SIGTERM に独自ハンドラを付け graceful close が長引く/詰まるため SIGKILL で確実に殺す。 */
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
    if (existing && existing.status === "running") return; // 二重起動防止
    const log = this.cfg.onLog ?? ((): void => {});
    const child = spawn(this.cfg.nodePath, args, { cwd: process.cwd(), env: process.env, stdio: ["ignore", "pipe", "pipe"] });
    const rec: RunProc = { id, command, child, startedAt: new Date().toISOString(), status: "running", exitCode: null };
    this.procs.set(id, rec);
    log(`▶ spawned ${command} ${id} (pid ${child.pid ?? "?"})`);
    child.stdout?.on("data", (d: Buffer) => log(`[${id}] ${String(d).trimEnd()}`));
    child.stderr?.on("data", (d: Buffer) => log(`[${id}!] ${String(d).trimEnd()}`));
    child.on("exit", (code) => {
      rec.status = "exited";
      rec.exitCode = code;
      this.relay?.revokeToken(id);
      log(`◼ ${command} ${id} exited (code ${code ?? "?"})`);
    });
  }
}
