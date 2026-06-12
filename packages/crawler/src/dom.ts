// DESIGN §6.4 — DOM 骨格 hash(SPA の「同一 URL だが別画面」を分離する dedup キーの一部)。

import { createHash } from "node:crypto";

/** タグ構造文字列を正規化して 16 桁 hex に。 */
export function hashDomSkeleton(skeleton: string): string {
  const normalized = skeleton.replace(/\s+/g, " ").trim().toLowerCase();
  return createHash("sha256").update(normalized).digest("hex").slice(0, 16);
}
