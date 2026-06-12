// DESIGN §4.4 / §7.1 / §8.2 — カバレッジ台帳の純粋セレクタ(IO なし)。
// orchestrator(M5)・WebUI(M3)・cli が同じロジックを共有する。

import type {
  AssessmentState,
  Coverage,
  Screen,
  ScreenScan,
  ScreenScanStatus,
} from "./types/index.js";

export const DEFAULT_MAX_ATTEMPTS = 3;

const ALL_STATUSES: readonly ScreenScanStatus[] = [
  "queued",
  "scanning",
  "clean",
  "finding",
  "blocked",
  "excluded",
  "error",
];

/** いま着手できる画面か(queued、または再試行枠が残る error)。 */
export function isScannable(scan: ScreenScan, maxAttempts: number = DEFAULT_MAX_ATTEMPTS): boolean {
  return scan.status === "queued" || (scan.status === "error" && scan.attempts < maxAttempts);
}

/** 全画面のカバレッジ集計(§4.4① の coverage_complete 判定もここ)。 */
export function coverage(
  state: Pick<AssessmentState, "screenScans">,
  maxAttempts: number = DEFAULT_MAX_ATTEMPTS,
): Coverage {
  const byStatus = Object.fromEntries(ALL_STATUSES.map((s) => [s, 0])) as Record<
    ScreenScanStatus,
    number
  >;
  let scannable = 0;
  for (const scan of state.screenScans) {
    byStatus[scan.status] += 1;
    if (isScannable(scan, maxAttempts)) scannable += 1;
  }
  const total = state.screenScans.length;
  const terminal = byStatus.clean + byStatus.finding + byStatus.excluded;
  const remaining = total - terminal;
  return { total, byStatus, terminal, remaining, scannable, complete: total > 0 && remaining === 0 };
}

export interface PrioritizedScreen {
  screenId: string;
  score: number;
}

const LABEL_SCORE: Record<string, number> = {
  "idor-candidate": 25,
  "secret-exposure": 22,
  pii: 20,
  "ssrf-candidate": 18,
  auth: 15,
  payment: 15,
};

/** 画面の攻撃妙味スコア(§7.1: auth / payment / object_ref / 機微 labels を優先)。 */
export function scoreScreen(screen: Screen): number {
  let score = 0;
  switch (screen.screenType) {
    case "payment":
      score += 40;
      break;
    case "admin":
      score += 35;
      break;
    case "auth":
      score += 30;
      break;
    case "upload":
      score += 22;
      break;
    case "dashboard":
      score += 12;
      break;
    case "form":
      score += 10;
      break;
    default:
      break;
  }
  for (const label of screen.labels) score += LABEL_SCORE[label] ?? 5;
  for (const param of screen.params) {
    if (param.guessedType === "object_ref") score += 15;
    else if (param.guessedType === "price" || param.guessedType === "qty") score += 12;
    else if (param.guessedType === "id") score += 8;
  }
  if (screen.authState === "post-login") score += 5;
  return score;
}

/**
 * スキャン対象を優先度降順で返す。既定では「いま着手できる」画面のみ(onlyScannable)。
 * orchestrator はこの順でサブエージェントへ dispatch する(§7.1)。
 */
export function prioritizeScreens(
  state: Pick<AssessmentState, "screens" | "screenScans">,
  opts: { maxAttempts?: number; onlyScannable?: boolean } = {},
): PrioritizedScreen[] {
  const onlyScannable = opts.onlyScannable ?? true;
  const maxAttempts = opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS;
  const scanById = new Map(state.screenScans.map((s) => [s.screenId, s] as const));

  const out: PrioritizedScreen[] = [];
  for (const screen of state.screens) {
    if (onlyScannable) {
      const scan = scanById.get(screen.screenId);
      if (!scan || !isScannable(scan, maxAttempts)) continue;
    }
    out.push({ screenId: screen.screenId, score: scoreScreen(screen) });
  }
  out.sort(
    (a, b) => b.score - a.score || (a.screenId < b.screenId ? -1 : a.screenId > b.screenId ? 1 : 0),
  );
  return out;
}
