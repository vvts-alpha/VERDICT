// Info レベルのセキュリティヘッダ監査(deterministic, LLM 不使用)。
// 既定リストは編集可能。CLI `header-audit` がレスポンスヘッダを当ててこのリストで判定する。

import type { Severity } from "@veritas/core";

export interface HeaderRule {
  /** --headers で選ぶ短い id */
  key: string;
  /** レスポンスヘッダ名(小文字) */
  header: string;
  severity: Severity;
  title: string;
  /** なぜ重要か(finding description に出す) */
  note: string;
}

/** 既定のセキュリティヘッダ・チェックリスト(ここを編集すればカスタムリストになる)。 */
export const SECURITY_HEADERS: HeaderRule[] = [
  { key: "csp", header: "content-security-policy", severity: "low", title: "Missing Content-Security-Policy", note: "CSP 不在 — XSS/データ注入/クリックジャッキングの多層防御が弱い。" },
  { key: "hsts", header: "strict-transport-security", severity: "low", title: "Missing HSTS", note: "Strict-Transport-Security 不在(TLS 配信時)— ダウングレード/中間者リスク。" },
  { key: "xfo", header: "x-frame-options", severity: "info", title: "Missing X-Frame-Options", note: "X-Frame-Options も CSP frame-ancestors も無し — クリックジャッキング。" },
  { key: "xcto", header: "x-content-type-options", severity: "info", title: "Missing X-Content-Type-Options (nosniff)", note: "nosniff 不在 — MIME スニッフィングによる XSS 補助。" },
  { key: "refpol", header: "referrer-policy", severity: "info", title: "Missing Referrer-Policy", note: "Referrer-Policy 不在 — Referer 経由の情報漏れ。" },
  { key: "permpol", header: "permissions-policy", severity: "info", title: "Missing Permissions-Policy", note: "Permissions-Policy 不在 — 強力なブラウザ機能が制限されていない。" },
];

/** レスポンスヘッダ + URL を rules で監査し、欠落/不十分なルールを返す。 */
export function auditHeaders(
  headers: Record<string, string>,
  url: string,
  rules: HeaderRule[] = SECURITY_HEADERS,
): HeaderRule[] {
  const missing: HeaderRule[] = [];
  for (const r of rules) {
    const value = headers[r.header];
    if (r.key === "xfo") {
      // X-Frame-Options か CSP frame-ancestors のどちらかがあれば OK。
      const csp = headers["content-security-policy"] ?? "";
      if (value || /frame-ancestors/i.test(csp)) continue;
      missing.push(r);
      continue;
    }
    if (r.key === "hsts" && !url.toLowerCase().startsWith("https:")) {
      continue; // 非 TLS には HSTS を要求しない
    }
    if (r.key === "xcto") {
      if ((value ?? "").toLowerCase().includes("nosniff")) continue;
      missing.push(r);
      continue;
    }
    if (!value) missing.push(r);
  }
  return missing;
}
