// One Burp task at a time. A successful HTTP submission only means queued, not audited.
// Never retry an ambiguous POST: Burp may have accepted it before the connection failed.
import type { BurpIssue } from "./burp.js";

export interface SequentialBurpStatus {
  status: string;
  issues: BurpIssue[];
  errors?: number;
  progress?: number;
  requestsMade?: number;
}

export function burpTaskSucceeded(status: string): boolean {
  return /^(?:audit )?(?:finished|completed|succeeded)(?: successfully)?\.?$/i.test(status.trim());
}

export interface SequentialBurpResult {
  submitted: number;
  completed: number;
  total: number;
  stoppedReason?: string;
  currentTaskId?: string;
}

export interface SequentialBurpOptions<T> {
  items: readonly T[];
  start: (item: T, signal: AbortSignal) => Promise<string>;
  poll: (taskId: string, signal: AbortSignal) => Promise<SequentialBurpStatus>;
  /** Persist even a partial last snapshot before returning on failure. */
  onResult: (snapshot: SequentialBurpStatus, item: T, index: number) => Promise<void>;
  onStart?: (index: number, taskId: string) => void;
  onProgress?: (snapshot: SequentialBurpStatus, index: number) => void;
  onPoll?: () => Promise<void>;
  pollIntervalMs: number;
  taskTimeoutMs: number;
  requestTimeoutMs?: number;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
}

export async function runSequentialBurp<T>(o: SequentialBurpOptions<T>): Promise<SequentialBurpResult> {
  const requestTimeoutMs = o.requestTimeoutMs ?? 30_000;
  for (const n of [o.pollIntervalMs, o.taskTimeoutMs, requestTimeoutMs]) {
    if (!Number.isFinite(n) || n <= 0) throw new Error("Burp polling and timeout values must be positive and finite");
  }
  const now = o.now ?? Date.now;
  const sleep = o.sleep ?? ((ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const result: SequentialBurpResult = { submitted: 0, completed: 0, total: o.items.length };

  for (const [index, item] of o.items.entries()) {
    const deadline = now() + o.taskTimeoutMs;
    let last: SequentialBurpStatus | undefined;
    let saving = false;
    const bounded = async <R>(operation: (signal: AbortSignal) => Promise<R>): Promise<R> => {
      const remaining = deadline - now();
      if (remaining <= 0) throw new Error("task timed out");
      const controller = new AbortController();
      let timer: ReturnType<typeof setTimeout> | undefined;
      try {
        return await Promise.race([
          operation(controller.signal),
          new Promise<never>((_, reject) => {
            timer = setTimeout(() => {
              const error = new Error("Burp operation timed out; no further tasks will be submitted");
              controller.abort(error);
              reject(error);
            }, Math.min(requestTimeoutMs, remaining));
          }),
        ]);
      } finally {
        if (timer) clearTimeout(timer);
      }
    };

    try {
      // Submission, polling and session keepalive all count toward this task's deadline.
      if (o.onPoll) await bounded(() => o.onPoll!());
      const taskId = await bounded((signal) => o.start(item, signal));
      if (!taskId) throw new Error("Burp did not return a task id");
      result.currentTaskId = taskId;
      result.submitted++;
      o.onStart?.(index, taskId);
      for (;;) {
        const remaining = deadline - now();
        if (remaining <= 0) throw new Error("task timed out");
        await sleep(Math.min(o.pollIntervalMs, remaining));
        if (o.onPoll) await bounded(() => o.onPoll!());
        last = await bounded((signal) => o.poll(taskId, signal));
        o.onProgress?.(last, index);
        if ((last.errors ?? 0) > 0 || /\b(?:failed|paused|pausing|cancelled|canceled|aborted|stopped|error)\b/i.test(last.status)) {
          throw new Error(`task ${taskId} stopped: ${last.status} (${last.errors ?? 0} network errors)`);
        }
        if (burpTaskSucceeded(last.status)) break;
        // Unknown and nonterminal statuses never authorize the next submission.
      }
      saving = true;
      await o.onResult(last, item, index);
      result.completed++;
      delete result.currentTaskId;
    } catch (error) {
      result.stoppedReason = String(error);
      if (last && !saving) {
        try { await o.onResult(last, item, index); }
        catch (saveError) { result.stoppedReason += `; saving partial results failed: ${String(saveError)}`; }
      }
      return result;
    }
  }
  return result;
}
