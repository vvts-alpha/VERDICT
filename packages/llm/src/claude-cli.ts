// Runs `claude -p --output-format json` as a subprocess (Claude Max subscription auth, no metered API).
// Confirmed envelope: { subtype:"success", is_error, result:"<text>", ... }. result may be wrapped in a ```json fence.

import { execFile } from "node:child_process";
import type { LlmClient, LlmRequest, LlmResponse } from "./types.js";

export interface ClaudeCliOptions {
  /** Default "claude" (resolved via PATH) */
  binPath?: string;
  /** Default "claude-sonnet-4-6" */
  defaultModel?: string;
  /** Default 120000ms */
  defaultTimeoutMs?: number;
  cwd?: string;
}

interface ClaudeJsonEnvelope {
  type?: string;
  subtype?: string;
  is_error?: boolean;
  result?: string;
}

export class ClaudeCliClient implements LlmClient {
  constructor(private readonly opts: ClaudeCliOptions = {}) {}

  complete(req: LlmRequest): Promise<LlmResponse> {
    const bin = this.opts.binPath ?? "claude";
    const model = req.model ?? this.opts.defaultModel ?? "claude-sonnet-4-6";
    const timeout = req.timeoutMs ?? this.opts.defaultTimeoutMs ?? 120_000;
    const args = ["-p", "--output-format", "json", "--model", model];
    if (req.system) args.push("--system-prompt", req.system);

    return new Promise<LlmResponse>((resolve, reject) => {
      const child = execFile(
        bin,
        args,
        { timeout, maxBuffer: 32 * 1024 * 1024, cwd: this.opts.cwd },
        (err, stdout, stderr) => {
          if (err) {
            reject(new Error(`claude CLI failed: ${err.message}${stderr ? ` | ${String(stderr).slice(0, 300)}` : ""}`));
            return;
          }
          let env: ClaudeJsonEnvelope;
          try {
            env = JSON.parse(stdout) as ClaudeJsonEnvelope;
          } catch {
            reject(new Error(`claude CLI: unparseable JSON envelope: ${stdout.slice(0, 200)}`));
            return;
          }
          if (env.is_error || env.subtype !== "success" || typeof env.result !== "string") {
            reject(new Error(`claude CLI error envelope: ${JSON.stringify(env).slice(0, 300)}`));
            return;
          }
          resolve({ text: env.result, model });
        },
      );
      child.stdin?.end(req.prompt);
    });
  }
}
