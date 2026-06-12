// DESIGN §4.4 / §7.1 / §8.2 — Phase2 のカバレッジ台帳。
//
// Screen(§6.6 の Phase1 契約 = screen_inventory.json)は不変の成果物なので汚さない。
// スキャン状態は per-screen の別レコード(ScreenScan)として持ち、
// 「検出した全画面に漏れなくスキャンしきる」ことを構造的に保証する。

export type ScreenScanStatus =
  | "queued" // 検出済・未スキャン(自動エンロール直後)
  | "scanning" // サブエージェントが処理中
  | "clean" // スキャン済・findings なし(terminal)
  | "finding" // スキャン済・findings あり(terminal)
  | "blocked" // 認証/スコープ/handoff 待ちで着手不能(非 terminal)
  | "excluded" // 人間がスキャン対象から除外(terminal)
  | "error"; // 失敗。再試行枠が残る限り再着手可

export interface ScreenScan {
  screenId: string;
  status: ScreenScanStatus;
  /** error からの累積試行回数 */
  attempts: number;
  hypothesisIds: string[];
  findingIds: string[];
  lastError: string | null;
  /** ISO-8601 */
  updatedAt: string;
}

/** coverage() の派生ビュー。WebUI バッジ(§8.2)と停止条件(§4.4①)が読む。 */
export interface Coverage {
  total: number;
  byStatus: Record<ScreenScanStatus, number>;
  /** clean + finding + excluded */
  terminal: number;
  /** total - terminal(queued / scanning / error / blocked の合計) */
  remaining: number;
  /** いま着手できる画面数(queued + 再試行枠の残る error)。blocked / scanning は除く */
  scannable: number;
  /** total > 0 かつ remaining === 0 → coverage_complete(§4.4①) */
  complete: boolean;
}
