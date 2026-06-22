// 登録可能ドメイン(eTLD+1)の近似算出。"etld" スコープモードで `*.<登録ドメイン>` を作るのに使う。
//
// ゼロ依存方針のため完全な Public Suffix List は積まず、よく使う複合 ccTLD(co.uk / com.au /
// co.jp ...)の例外表 +「末尾2ラベル」フォールバックで近似する。
// 限界: PSL の網羅ではない(新しい複合 TLD や private suffix は外れうる)。厳密一致が要る現場は
// manifest の scope.inScopeHosts で明示上書きする運用。

/** 末尾2ラベルが「実質 TLD」として機能する複合 ccTLD。これらは3ラベル目までを登録ドメインとみなす。 */
const MULTI_PART_SUFFIXES = new Set([
  // UK
  "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk", "police.uk", "mod.uk",
  // JP
  "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", "ad.jp", "ed.jp", "gr.jp", "lg.jp",
  // AU
  "com.au", "net.au", "org.au", "edu.au", "gov.au", "asn.au", "id.au",
  // NZ
  "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", "school.nz",
  // BR
  "com.br", "net.br", "org.br", "gov.br", "edu.br",
  // CN
  "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
  // KR
  "co.kr", "or.kr", "ne.kr", "re.kr", "go.kr", "ac.kr",
  // IN
  "co.in", "net.in", "org.in", "gen.in", "firm.in", "ind.in", "gov.in", "ac.in", "edu.in", "res.in",
  // ZA
  "co.za", "org.za", "net.za", "gov.za", "ac.za",
  // その他よく見る com.* 系
  "com.mx", "com.tr", "com.ar", "com.sg", "com.hk", "com.tw", "com.my", "com.ph", "com.vn",
  "com.ua", "com.pl", "com.ru", "com.co", "com.pe", "com.eg", "com.sa", "com.br",
]);

/**
 * ホスト名(ポートを含まない hostname)から登録可能ドメイン(eTLD+1)を近似で返す。
 * IPv4 / IPv6 / 単一ラベル(localhost 等)はそのまま返す。
 */
export function registrableDomain(hostname: string): string {
  const h = hostname.toLowerCase().replace(/\.$/, "");
  // IPv4(数字とドットのみ)/ IPv6(コロン入り)/ 単一ラベルはそのまま
  if (h.length === 0 || h.includes(":") || /^[0-9.]+$/.test(h)) return h;
  const labels = h.split(".");
  if (labels.length <= 2) return h;
  const lastTwo = labels.slice(-2).join(".");
  if (MULTI_PART_SUFFIXES.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}
