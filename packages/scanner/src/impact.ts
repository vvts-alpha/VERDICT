// 汎用 impact オラクル(deterministic, LLM 不使用)。exploit の応答が「具体的 impact」を示すかを判定する。
// CTF の FLAG{} 専用ではなく、実エンゲージメントでそのまま価値になる一般化:秘密/ファイル流出/コマンド出力/
// 他ユーザデータ。probe の suspected を confirmed に昇格させる effectMarker の content 版(checkLogicEvidence に通す)。
// FP 抑制は2段: (1) ドキュメント placeholder を除外、(2) anti-ambient = baseline(control)に既出のものは除外。
// checkLogicEvidence の「marker は control に出ない」原則と同じ。CTF flag 正規表現は ctx.flagRegex 指定時のみ(既定 OFF)。

import type { Severity } from "@veritas/core";

export type ImpactKind = "file-leak" | "source-leak" | "secret" | "command-output" | "cross-user" | "ctf-flag";

export interface ImpactContext {
  /** control/baseline 応答。ここに既出のマーカーは ambient とみなし発火しない(誤検知抑制)。 */
  baselineBody?: string;
  /** 要求した被害者 ID。応答に含まれ、かつ攻撃者自身の ID が含まれなければ cross-user。 */
  requestedIdentity?: string;
  /** 攻撃者自身の ID(自分のデータを誤って cross-user 判定しないため)。 */
  sessionIdentity?: string;
  /** CTF/ベンチ時のみ渡すフラグ正規表現。既定 undefined = ctf-flag は無効(実案件に CTF 結合を持ち込まない)。 */
  flagRegex?: RegExp;
}

export interface ImpactSignal {
  kind: ImpactKind;
  severity: Severity;
  /** 応答中で impact を示した実マーカー(effectMarker として再利用可)。 */
  marker: string;
  detail: string;
}

interface Detector {
  kind: ImpactKind;
  severity: Severity;
  re: RegExp;
  detail: string;
}

// ドキュメント例・プレースホルダ(本物の秘密ではない)。
const PLACEHOLDERS: RegExp[] = [
  /AKIAIOSFODNN7EXAMPLE/i,
  /your[-_]?(api[-_]?)?(key|secret|token)/i,
  /\bexample\b/i,
  /x{8,}/i,
  /\b0{8,}\b/,
  /changeme|placeholder|<your|dummy|sample[-_]?key|test[-_]?key|s3cr3t-example/i,
];

const DETECTORS: Detector[] = [
  // ── ファイル流出 ──
  { kind: "file-leak", severity: "high", re: /\broot:.*?:0:0:/, detail: "/etc/passwd contents (root:…:0:0:)" },
  { kind: "file-leak", severity: "high", re: /\[fonts\]|\[extensions\]|for 16-bit app support/i, detail: "win.ini contents" },
  // ── ソース/設定の流出 ──
  { kind: "source-leak", severity: "high", re: /<\?php[\s\S]{0,30}/, detail: "PHP source disclosure" },
  { kind: "source-leak", severity: "high", re: /\b(DB_PASSWORD|SECRET_KEY|DATABASE_URL|AWS_SECRET_ACCESS_KEY|APP_KEY)\s*[=:]\s*\S{6,}/i, detail: "config/.env secret" },
  // ── 秘密 ──
  { kind: "secret", severity: "high", re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/, detail: "private key" },
  { kind: "secret", severity: "high", re: /\bAKIA[0-9A-Z]{16}\b/, detail: "AWS access key id" },
  { kind: "secret", severity: "high", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}/, detail: "Slack token" },
  { kind: "secret", severity: "high", re: /\bAIza[0-9A-Za-z_-]{35}\b/, detail: "Google API key" },
  { kind: "secret", severity: "medium", re: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}/, detail: "JWT" },
  { kind: "secret", severity: "high", re: /\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:[^/\s:@]+@/i, detail: "credentials embedded in URL (user:pass@host)" },
  { kind: "secret", severity: "medium", re: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, detail: "bcrypt password hash" },
  // ── コマンド出力(RCE/CMDi 証跡) ──
  { kind: "command-output", severity: "high", re: /\buid=\d+\([^)]*\)\s+gid=\d+\(/, detail: "id command output (uid=…gid=…)" },
  { kind: "command-output", severity: "medium", re: /Volume Serial Number is [0-9A-F]{4}-[0-9A-F]{4}/i, detail: "Windows dir/command output" },
];

/**
 * 応答テキストを走査し、具体的 impact のシグナルを返す(無ければ空)。placeholder / anti-ambient で FP を抑える。
 */
export function impactOracle(responseText: string, ctx: ImpactContext = {}): ImpactSignal[] {
  const body = responseText || "";
  const base = ctx.baselineBody ?? "";
  const out: ImpactSignal[] = [];
  const seen = new Set<string>();
  const emit = (kind: ImpactKind, severity: Severity, rawMarker: string, detail: string): void => {
    const marker = rawMarker.slice(0, 100);
    if (!marker) return;
    if (PLACEHOLDERS.some((p) => p.test(marker))) return; // ドキュメント placeholder
    if (base && base.includes(marker)) return; // anti-ambient: baseline に既出
    const key = `${kind}:${marker}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ kind, severity, marker, detail });
  };
  for (const d of DETECTORS) {
    const m = d.re.exec(body);
    if (m) emit(d.kind, d.severity, m[0], d.detail);
  }
  // cross-user: 要求した被害者 ID が応答にあり、攻撃者自身の ID が無く、baseline にも無い。
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
  // ctf-flag: 明示的に flagRegex を渡された時のみ(既定 OFF)。
  if (ctx.flagRegex) {
    const fm = ctx.flagRegex.exec(body);
    if (fm && !base.includes(fm[0])) out.push({ kind: "ctf-flag", severity: "medium", marker: fm[0].slice(0, 100), detail: "engagement flag pattern matched" });
  }
  return out;
}

/** impact シグナルを 1 行に(ログ/LLM 返却用)。 */
export function formatImpact(signals: ReadonlyArray<ImpactSignal>): string {
  return signals.map((s) => `${s.kind}[${s.severity}]: ${s.detail} (${s.marker.slice(0, 40)})`).join("; ");
}
