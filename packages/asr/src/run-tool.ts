// ASR external-tool runner (T3MP3ST adapter discipline, VERDICT style). One injected helper over `execFile` — NO SHELL,
// so shell metacharacters in an (already-normalized) apex are inert. A MISSING binary degrades to `missing:true` + empty
// output (never a failed run — same ethos as crt.sh-down → zero hosts). Tests inject a FakeRunTool: zero real subprocess.

import { execFile } from "node:child_process";

export interface RunToolResult {
    ok: boolean;
    stdout: string;
    stderr: string;
    /** the binary isn't installed (ENOENT) — the caller degrades to [] instead of erroring */
    missing: boolean;
}

export type RunTool = (bin: string, args: string[], opts?: { timeoutMs?: number; signal?: AbortSignal }) => Promise<RunToolResult>;

/** Runtime RunTool: hardcoded-argv execFile (no shell), 32MB buffer, default 120s timeout. */
export const execFileRunTool: RunTool = (bin, args, opts) =>
    new Promise((resolve) => {
        const child = execFile(
            bin,
            args,
            { timeout: opts?.timeoutMs ?? 120_000, maxBuffer: 32 * 1024 * 1024, ...(opts?.signal ? { signal: opts.signal } : {}) },
            (err, stdout, stderr) => {
                const missing = !!err && (err as NodeJS.ErrnoException).code === "ENOENT"; // binary not installed
                resolve({ ok: !err, stdout: stdout ?? "", stderr: stderr ?? "", missing });
            },
        );
        child.on("error", () => {}); // ENOENT etc. surface via the callback, not an unhandled 'error' event
    });
