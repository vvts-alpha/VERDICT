// General-purpose impact oracle (deterministic, no LLM). Decides whether an exploit's response shows a "concrete impact".
// Not specific to CTF FLAG{}, but generalized to what carries value directly in real engagements: secrets / file leaks / command output /
// other users' data. The content-side counterpart of effectMarker that promotes a probe's suspected to confirmed (routed through checkLogicEvidence).
// FP suppression is two-stage: (1) exclude documentation placeholders, (2) anti-ambient = exclude anything already present in the baseline (control).
// Same as checkLogicEvidence's "a marker must not appear in the control" principle. The CTF-flag regex applies only when ctx.flagRegex is set (default OFF).

import type { Severity } from "@veritas/core";

export type ImpactKind = "file-leak" | "source-leak" | "secret" | "command-output" | "cross-user" | "ctf-flag";

export interface ImpactContext {
  /** control/baseline response. A marker already present here is treated as ambient and does not fire (FP suppression). */
  baselineBody?: string;
  /** the requested victim ID. If present in the response and the attacker's own ID is not, it's cross-user. */
  requestedIdentity?: string;
  /** the attacker's own ID (so their own data isn't mis-flagged as cross-user). */
  sessionIdentity?: string;
  /** a flag regex passed only for CTF/benchmarks. Default undefined = ctf-flag disabled (don't bring CTF coupling into real engagements). */
  flagRegex?: RegExp;
}

export interface ImpactSignal {
  kind: ImpactKind;
  severity: Severity;
  /** the actual marker in the response that showed the impact (reusable as effectMarker). */
  marker: string;
  detail: string;
}

interface Detector {
  kind: ImpactKind;
  severity: Severity;
  re: RegExp;
  detail: string;
}

// Documentation examples / placeholders (not real secrets).
const PLACEHOLDERS: RegExp[] = [
  /AKIAIOSFODNN7EXAMPLE/i,
  /your[-_]?(api[-_]?)?(key|secret|token)/i,
  /\bexample\b/i,
  /x{8,}/i,
  /\b0{8,}\b/,
  /changeme|placeholder|<your|dummy|sample[-_]?key|test[-_]?key|s3cr3t-example/i,
];

const DETECTORS: Detector[] = [
  // ── file leak ──
  { kind: "file-leak", severity: "high", re: /\broot:.*?:0:0:/, detail: "/etc/passwd contents (root:…:0:0:)" },
  { kind: "file-leak", severity: "high", re: /\[fonts\]|\[extensions\]|for 16-bit app support/i, detail: "win.ini contents" },
  // ── source/config leak ──
  { kind: "source-leak", severity: "high", re: /<\?php[\s\S]{0,30}/, detail: "PHP source disclosure" },
  { kind: "source-leak", severity: "high", re: /\b(DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*[=:]\s*\S{6,}/i, detail: "config/.env secret" },
  // ── secrets ──
  { kind: "secret", severity: "high", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, detail: "private key" },
  { kind: "secret", severity: "high", re: /\bAKIA[0-9A-Z]{16}\b/, detail: "AWS access key id" },
  { kind: "secret", severity: "high", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, detail: "Slack token" },
  { kind: "secret", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/, detail: "Google API key" },
  { kind: "secret", severity: "medium", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/, detail: "JWT" },
  { kind: "secret", severity: "high", re: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@/i, detail: "credentials embedded in URL (user:pass@host)" },
  { kind: "secret", severity: "medium", re: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, detail: "bcrypt password hash" },
  // ── command output (RCE/CMDi evidence) ──
  { kind: "command-output", severity: "high", re: /\buid=\d+\([^)]*\)\s+gid=\d+\(/, detail: "id command output (uid=…gid=…)" },
  { kind: "command-output", severity: "medium", re: /Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i, detail: "Windows dir/command output" },
];

/**
 * Scan the response text and return concrete-impact signals (empty if none). Suppresses FP via placeholder / anti-ambient.
 */
export function impactOracle(responseText: string, ctx: ImpactContext = {}): ImpactSignal[] {
  const body = responseText || "";
  const base = ctx.baselineBody ?? "";
  const out: ImpactSignal[] = [];
  const seen = new Set<string>();
  const emit = (kind: ImpactKind, severity: Severity, rawMarker: string, detail: string): void => {
    const marker = rawMarker.slice(0, 100);
    if (!marker) return;
    if (PLACEHOLDERS.some((p) => p.test(marker))) return; // documentation placeholder
    if (base && base.includes(marker)) return; // anti-ambient: already present in the baseline
    const key = `${kind}:${marker}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, severity, marker, detail });
  };
  for (const d of DETECTORS) {
    const m = d.re.exec(body);
    if (m) emit(d.kind, d.severity, m[0], d.detail);
  }
  // cross-user: the requested victim ID is in the response, the attacker's own ID is not, and it's not in the baseline either.
  if (
    ctx.requestedIdentity &&
    body.includes(ctx.requestedIdentity) &&
    (!ctx.sessionIdentity || !body.includes(ctx.sessionIdentity)) &&
    !base.includes(ctx.requestedIdentity)
  ) {
    out.push({
      kind: "cross-user",
      severity: "high",
      marker: ctx.requestedIdentity.slice(0, 100),
      detail: `response contains the requested victim identity '${ctx.requestedIdentity}' (not the attacker's own) — cross-user object access`,
    });
  }
  // ctf-flag: only when a flagRegex is explicitly passed (default OFF).
  if (ctx.flagRegex) {
    const fm = ctx.flagRegex.exec(body);
    if (fm && !base.includes(fm[0])) out.push({ kind: "ctf-flag", severity: "medium", marker: fm[0].slice(0, 100), detail: "engagement flag pattern matched" });
  }
  return out;
}

/** impact signals on one line (for logs / returning to the LLM). */
export function formatImpact(signals: ReadonlyArray<ImpactSignal>): string {
  return signals.map((s) => `${s.kind}[${s.severity}]: ${s.detail} (${s.marker.slice(0, 40)})`).join("; ");
}
