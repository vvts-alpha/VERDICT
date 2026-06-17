// 依存無しの最小 .env ローダ。CLI 起動時に cwd の .env を読み、まだ未設定の環境変数だけ反映する
// (shell で export 済みの値が優先)。BURP_API / BURP_PROXY 等をファイルで持てるようにする。

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/** .env テキスト → KEY/VALUE。`export` 接頭辞・`#` コメント・前後クォートを許容。最初の `=` で分割。 */
export function parseDotEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m || !m[1]) continue;
    let val = (m[2] ?? "").trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[m[1]] = val;
  }
  return out;
}

/** cwd の .env を読み、未設定の環境変数だけ process.env に反映する。読み込んだキー名を返す。 */
export function loadDotEnv(dir: string = process.cwd(), file = ".env"): string[] {
  const path = join(dir, file);
  if (!existsSync(path)) return [];
  let parsed: Record<string, string>;
  try {
    parsed = parseDotEnv(readFileSync(path, "utf8"));
  } catch {
    return [];
  }
  const loaded: string[] = [];
  for (const [k, v] of Object.entries(parsed)) {
    if (process.env[k] === undefined) {
      process.env[k] = v;
      loaded.push(k);
    }
  }
  return loaded;
}
