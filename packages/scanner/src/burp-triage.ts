// Burp の Information/Low/Medium issue は、それ単体だと低レートでも **実脆弱性の入口**(反射点→XSS、
// 外部通信→SSRF、緩い CORS→データ窃取…)になりやすい。verifyImportedBurp は High+ しか再検証しないので、
// それ未満は素通りする。ここはその素通り層を **名前ベースで triage** し、「有望なリードだけ」を浮かび上がらせる
// 純関数(ネットワーク不要)。全部を verify せず、操作者/後段の verify が着目すべき候補を提示するのが目的。

import type { BurpIssue } from "./burp.js";

export type LeadPriority = "high" | "medium" | "low";

export interface BurpLead {
  /** 入口が指す実脆弱性クラス(probe 名と対応) */
  lead: string;
  priority: LeadPriority;
  /** なぜ有望か(1 行) */
  why: string;
  /** 確証のための次アクション(既存 probe ツール等) */
  probe: string;
  /** この lead にマップした Burp issue 名(重複排除済) */
  names: string[];
  /** 該当 issue インスタンス総数(URL ごとに重複する Burp の数え方) */
  count: number;
  /** 代表 URL(最大 5 件) */
  sampleUrls: string[];
}

const PRIORITY_RANK: Record<LeadPriority, number> = { high: 3, medium: 2, low: 1 };

/** issue 名 → リード規則(上から順に最初の一致を採用)。hygiene 系(cookie flag / TLS / charset 等)は
 *  「入口」ではないので **意図的に拾わない**(triage を信号高く保つ)。 */
const LEAD_RULES: Array<{ re: RegExp; lead: string; priority: LeadPriority; why: string; probe: string }> = [
  // ── XSS 系(反射点・stored 反射・DOM sink)= 最有望 ──
  {
    re: /cross-site scripting \(stored\)|input returned in response \(stored\)|stored.*\bxss\b/i,
    lead: "xss-stored",
    priority: "high",
    why: "stored reflection — may render unescaped at another screen/role",
    probe: "probe_stored_xss",
  },
  {
    re: /\bdom\b.*manipulation|dom[\s-]?based|dom data/i,
    lead: "xss-dom",
    priority: "high",
    why: "client-side sink with attacker-influenced source — DOM XSS candidate",
    probe: "probe_dom_xss",
  },
  {
    re: /cross-site scripting \(reflected\)|input returned in response \(reflected\)|reflected.*\bxss\b/i,
    lead: "xss-reflected",
    priority: "high",
    why: "reflection point — payload may break out of its HTML/JS context",
    probe: "probe_xss / probe_dom_xss",
  },
  // ── SSRF / OOB(外部通信が観測された)= 当たりに近い ──
  {
    re: /external service interaction|out-of-band|\bssrf\b|server-side request/i,
    lead: "ssrf",
    priority: "high",
    why: "server reached an external host (DNS/HTTP) — strong SSRF/OOB signal",
    probe: "probe_oob (Collaborator)",
  },
  // ── インジェクション示唆 ──
  {
    re: /suspicious input transformation|sql statement|serialized object|expression language|template/i,
    lead: "injection",
    priority: "medium",
    why: "input transformed/echoed in a dangerous sink — injection candidate",
    probe: "probe_params / probe_oob",
  },
  // ── CORS(緩いオリジン信頼)= クレデンシャル付きならデータ窃取 ──
  {
    re: /cross-origin resource sharing|\bcors\b/i,
    lead: "cors",
    priority: "medium",
    why: "arbitrary/loose origin trusted — cross-site data theft if responses are credentialed",
    probe: "http_request with Origin: https://evil.example then check ACAO/ACAC",
  },
  // ── CSRF(state 変更が anti-CSRF 無し) ──
  {
    re: /cross-site request forgery|\bcsrf\b/i,
    lead: "csrf",
    priority: "medium",
    why: "state-changing request without an anti-CSRF token",
    probe: "probe_csrf",
  },
  // ── オープンリダイレクト / リンク操作 ──
  {
    re: /open redirect|unvalidated redirect|link manipulation/i,
    lead: "open-redirect",
    priority: "medium",
    why: "redirect/link target is user-controlled",
    probe: "probe_redirect",
  },
  // ── 弱い CSP(注入 XSS を止められない=増幅器) ──
  {
    re: /content security policy.*(untrusted script|form hijack|unsafe|allows)/i,
    lead: "csp-weak",
    priority: "medium",
    why: "weak CSP won't block injected script — amplifies any reflected/stored XSS lead",
    probe: "pair with an XSS lead on the same origin",
  },
  // ── アップロード機能(型/パス/拡張子バイパス面) ──
  {
    re: /file upload/i,
    lead: "upload",
    priority: "medium",
    why: "upload surface — content-type / extension / path-traversal bypass to test",
    probe: "manual upload probe (type/path/overwrite)",
  },
  // ── API スペック露出(テスト面が増える) ──
  {
    re: /openapi|swagger|graphql|wsdl|api definition/i,
    lead: "api-surface",
    priority: "medium",
    why: "API spec exposed — enumerate the endpoints it documents and test them",
    probe: "fetch the spec → probe_paths the listed endpoints",
  },
  // ── ソース/設定の開示 ──
  {
    re: /source code disclosure|backup file|\.bak\b|configuration file|directory listing/i,
    lead: "info-disclosure",
    priority: "medium",
    why: "leaked source/config/listing aids targeting and may expose secrets",
    probe: "fetch & review for secrets / hidden endpoints",
  },
  // ── 低優先の手掛かり ──
  {
    re: /private ip address|internal ip/i,
    lead: "recon",
    priority: "low",
    why: "internal host/IP leaked — pair with an SSRF lead",
    probe: "—",
  },
  {
    re: /base64-encoded data in parameter|encoded.*parameter/i,
    lead: "tampering",
    priority: "low",
    why: "encoded param may hide an id/object-ref worth decoding and tampering",
    probe: "decode → probe_params",
  },
  {
    re: /robots\.txt|sitemap|hidden|spider/i,
    lead: "hidden-surface",
    priority: "low",
    why: "may reveal un-linked paths to map",
    probe: "probe_paths",
  },
];

export interface BurpLeadClass {
  lead: string;
  priority: LeadPriority;
  why: string;
  probe: string;
}

/** Burp issue 名(または "[burp] …" を剥がした finding タイトル)→ リード分類。未分類/hygiene は null。
 *  triage の集約と、選択フェーズのヒント表示・確証時の severity 引き上げの両方から使う単一の真実。 */
export function classifyBurpName(name: string): BurpLeadClass | null {
  for (const r of LEAD_RULES) if (r.re.test(name)) return { lead: r.lead, priority: r.priority, why: r.why, probe: r.probe };
  return null;
}

function matchRule(name: string): (typeof LEAD_RULES)[number] | null {
  for (const r of LEAD_RULES) if (r.re.test(name)) return r;
  return null;
}

/** issue の URL(host+path)を組み立てる(triage の表示用、scope 判定は呼び出し側で済ませる前提)。 */
function issueUrl(i: BurpIssue): string {
  try {
    return new URL(i.path || "/", i.host).toString();
  } catch {
    return `${i.host}${i.path || ""}`;
  }
}

/**
 * Burp issue 群(通常は High 未満=verify が触らない層を渡す)を triage し、有望リードを
 * lead クラスごとに集約して priority 降順・count 降順で返す。hygiene 系は除外される。
 */
export function triageBurpInfo(issues: ReadonlyArray<BurpIssue>): BurpLead[] {
  const byLead = new Map<string, BurpLead & { _names: Set<string>; _urls: string[] }>();
  for (const issue of issues) {
    const rule = matchRule(issue.name);
    if (!rule) continue; // hygiene / 未分類は無視
    let agg = byLead.get(rule.lead);
    if (!agg) {
      agg = {
        lead: rule.lead,
        priority: rule.priority,
        why: rule.why,
        probe: rule.probe,
        names: [],
        count: 0,
        sampleUrls: [],
        _names: new Set<string>(),
        _urls: [],
      };
      byLead.set(rule.lead, agg);
    }
    agg.count += 1;
    agg._names.add(issue.name);
    if (agg._urls.length < 5) {
      const u = issueUrl(issue);
      if (!agg._urls.includes(u)) agg._urls.push(u);
    }
  }
  const leads: BurpLead[] = [...byLead.values()].map((a) => ({
    lead: a.lead,
    priority: a.priority,
    why: a.why,
    probe: a.probe,
    names: [...a._names],
    count: a.count,
    sampleUrls: a._urls,
  }));
  leads.sort((x, y) => PRIORITY_RANK[y.priority] - PRIORITY_RANK[x.priority] || y.count - x.count);
  return leads;
}

/** triage 結果を人間可読の複数行に整形(CLI ログ / イベント note 用)。 */
export function formatBurpLeads(leads: ReadonlyArray<BurpLead>): string[] {
  return leads.map(
    (l) =>
      `[${l.priority}] ${l.lead} — ${l.count} issue(s): ${l.why} → ${l.probe}` +
      (l.sampleUrls.length ? `  (e.g. ${l.sampleUrls.slice(0, 3).join(", ")})` : ""),
  );
}
