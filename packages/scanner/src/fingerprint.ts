// 技術スタックのフィンガープリント(deterministic, LLM 不使用)。レスポンスのヘッダ/Cookie/meta/script-src
// から server・middleware・language・framework・CMS・frontend ライブラリの「名前+バージョン」を構造化抽出する。
// 既知脆弱性の照合のうち **JS ライブラリは VULN_JS_LIBS カタログで決定的に**付与し、server/middleware/language は
// バージョンだけ集めて pilot の A06 ステージ(LLM の CVE 知識)が評価する。collect が信頼でき、評価が知識依存。

import { VULN_JS_LIBS, versionLeq } from "./passive.js";

export type TechKind = "server" | "language" | "framework" | "cms" | "frontend-lib";

export interface TechComponent {
  kind: TechKind;
  name: string;
  /** 取れた版(例 "2.4.41")。banner だけで版が無ければ null。 */
  version: string | null;
  /** 検出元(header 名 / "cookie" / "meta generator" / "script src")。 */
  source: string;
  /** 生の手がかり(レポート/証拠の根拠)。 */
  evidence: string;
  /** 既知脆弱版に合致した場合のメモ(JS ライブラリ catalog のみ。空なら未照合=LLM 段で評価)。 */
  knownVuln?: string;
}

export interface TechSample {
  url: string;
  headers: Record<string, string>;
  body: string;
}

/** "Apache/2.4.41 (Ubuntu)" / "nginx/1.18.0" / "PHP/7.4.3" → { name, version } */
function splitBanner(v: string): { name: string; version: string | null } {
  const m = /^([A-Za-z][\w.+-]*?)[/ ]v?(\d+(?:\.\d+){0,3})/.exec(v.trim());
  if (m) return { name: m[1]!, version: m[2]! };
  const first = v.trim().split(/[\s(;,]/)[0] ?? v.trim();
  return { name: first, version: null };
}

// ヘッダ → 種別(banner を splitBanner で名前+版に割る)
const BANNER_HEADERS: { header: string; kind: TechKind }[] = [
  { header: "server", kind: "server" },
  { header: "x-powered-by", kind: "framework" },
  { header: "via", kind: "server" },
];

// 版を直接持つヘッダ(値そのものが版)
const VERSION_VALUE_HEADERS: { header: string; kind: TechKind; name: string }[] = [
  { header: "x-aspnet-version", kind: "framework", name: "ASP.NET" },
  { header: "x-aspnetmvc-version", kind: "framework", name: "ASP.NET MVC" },
  { header: "x-generator", kind: "cms", name: "(generator)" },
];

// Set-Cookie 名 → フレームワーク/言語(版は出ないが「何で出来ているか」が分かる)
const COOKIE_TECH: { re: RegExp; kind: TechKind; name: string }[] = [
  { re: /\bPHPSESSID\b/i, kind: "language", name: "PHP" },
  { re: /\bJSESSIONID\b/i, kind: "language", name: "Java (servlet container)" },
  { re: /\bconnect\.sid\b/i, kind: "framework", name: "Express / Node.js" },
  { re: /\blaravel_session\b/i, kind: "framework", name: "Laravel (PHP)" },
  { re: /\bci_session\b/i, kind: "framework", name: "CodeIgniter (PHP)" },
  { re: /\b_session_id\b/i, kind: "framework", name: "Ruby on Rails" },
  { re: /\bASP\.NET_SessionId\b/i, kind: "framework", name: "ASP.NET" },
  { re: /\bcsrftoken\b/i, kind: "framework", name: "Django" },
];

function scriptRefs(body: string): string[] {
  const out: string[] = [];
  const re = /<script[^>]+src=["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(body)) !== null) if (m[1]) out.push(m[1]);
  return out;
}

/**
 * 1 件以上のレスポンス sample から技術コンポーネントを抽出・重複排除して返す。
 * JS ライブラリは VULN_JS_LIBS と照合し、既知脆弱版なら knownVuln を付ける(決定的)。
 */
export function fingerprintTech(samples: ReadonlyArray<TechSample>): TechComponent[] {
  const byKey = new Map<string, TechComponent>();
  const add = (c: TechComponent): void => {
    const key = `${c.kind}|${c.name.toLowerCase()}|${c.version ?? ""}`;
    if (!byKey.has(key)) byKey.set(key, c);
  };

  for (const s of samples) {
    const h = s.headers;
    // banner ヘッダ(Server / X-Powered-By / Via)
    for (const { header, kind } of BANNER_HEADERS) {
      const v = h[header];
      if (!v) continue;
      // X-Powered-By は "PHP/7.4.3" や "Express" など複数値もある
      for (const part of v.split(",")) {
        const { name, version } = splitBanner(part);
        if (!name) continue;
        add({ kind, name, version, source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // 版が値そのもののヘッダ
    for (const { header, kind, name } of VERSION_VALUE_HEADERS) {
      const v = h[header];
      if (v && /\d/.test(v)) {
        const nm = name === "(generator)" ? splitBanner(v).name || "generator" : name;
        add({ kind, name: nm, version: splitBanner(v).version ?? v.trim().slice(0, 40), source: header, evidence: `${header}: ${v}`.slice(0, 200) });
      }
    }
    // Set-Cookie 名 → フレームワーク家系
    const setCookie = h["set-cookie"] ?? "";
    if (setCookie) {
      for (const c of COOKIE_TECH) {
        if (c.re.test(setCookie)) add({ kind: c.kind, name: c.name, version: null, source: "cookie", evidence: `Set-Cookie name matched ${c.re.source}` });
      }
    }
    // <meta name="generator" content="WordPress 6.4">
    const meta = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(s.body);
    if (meta?.[1]) {
      const { name, version } = splitBanner(meta[1]);
      add({ kind: "cms", name: name || meta[1], version, source: "meta generator", evidence: `<meta generator>: ${meta[1]}`.slice(0, 200) });
    }
    // frontend ライブラリ(script src のファイル名から名前+版。既知脆弱版なら knownVuln)
    for (const ref of scriptRefs(s.body)) {
      for (const lib of VULN_JS_LIBS) {
        const m = lib.re.exec(ref);
        const ver = m?.[1];
        if (!ver) continue;
        add({
          kind: "frontend-lib",
          name: lib.name,
          version: ver,
          source: "script src",
          evidence: ref.slice(0, 200),
          ...(versionLeq(ver, lib.maxVuln) ? { knownVuln: lib.note } : {}),
        });
      }
    }
  }
  return [...byKey.values()];
}

/** TechComponent[] を人間可読の表に整形(LLM プロンプト / レポート用)。 */
export function formatTechInventory(components: ReadonlyArray<TechComponent>): string[] {
  return components.map(
    (c) =>
      `- [${c.kind}] ${c.name}${c.version ? ` ${c.version}` : " (version unknown)"} — via ${c.source}` +
      (c.knownVuln ? `  ⚠ KNOWN: ${c.knownVuln}` : ""),
  );
}
