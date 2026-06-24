// DESIGN §4.1 / §10 — AssessmentState の SQLite ストア(state.sqlite)。
//
// 設計上の不変条件: すべての状態遷移は append-only な events として追記される。
// 派生コレクション(screens/hypotheses/findings/handoffs)は正規化テーブルに upsert し、
// 同一トランザクション内で対応する StateEvent を必ず記録する。
//
// Node 24 組み込みの node:sqlite を使用 → native 依存なし。同期 API は単一プロセスの
// 作業記憶ストアに最適。

import { DatabaseSync } from "node:sqlite";

import type {
  AssessmentState,
  AssessmentSummary,
  BudgetState,
  Finding,
  HumanHandoff,
  Hypothesis,
  Phase,
  ScopePolicy,
  Screen,
  ScreenScan,
  ScreenScanStatus,
  StateEvent,
  StateEventInput,
  StopReason,
  TargetInput,
} from "./types/index.js";
import { defaultBudget, newAssessmentId } from "./factories.js";

const SCHEMA = `
CREATE TABLE IF NOT EXISTS assessments (
  id          TEXT PRIMARY KEY,
  target      TEXT NOT NULL,   -- JSON TargetInput
  phase       TEXT NOT NULL,
  scope       TEXT NOT NULL,   -- JSON ScopePolicy
  budget      TEXT NOT NULL,   -- JSON BudgetState
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  assessment_id TEXT NOT NULL,
  seq           INTEGER NOT NULL,
  ts            TEXT NOT NULL,
  type          TEXT NOT NULL,
  payload       TEXT NOT NULL, -- JSON
  PRIMARY KEY (assessment_id, seq),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS screens (
  assessment_id TEXT NOT NULL,
  screen_id     TEXT NOT NULL,
  url_template  TEXT NOT NULL,
  auth_state    TEXT NOT NULL,
  screen_type   TEXT NOT NULL,
  data          TEXT NOT NULL, -- JSON Screen
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (assessment_id, screen_id),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS hypotheses (
  assessment_id TEXT NOT NULL,
  id            TEXT NOT NULL,
  screen_id     TEXT NOT NULL,
  class         TEXT NOT NULL,
  status        TEXT NOT NULL,
  data          TEXT NOT NULL, -- JSON Hypothesis
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (assessment_id, id),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
  assessment_id TEXT NOT NULL,
  id            TEXT NOT NULL,
  screen_id     TEXT,
  severity      TEXT NOT NULL,
  data          TEXT NOT NULL, -- JSON Finding
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (assessment_id, id),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS handoffs (
  assessment_id TEXT NOT NULL,
  id            TEXT NOT NULL,
  reason        TEXT NOT NULL,
  status        TEXT NOT NULL,
  data          TEXT NOT NULL, -- JSON HumanHandoff
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (assessment_id, id),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS screen_scans (
  assessment_id TEXT NOT NULL,
  screen_id     TEXT NOT NULL,
  status        TEXT NOT NULL,
  attempts      INTEGER NOT NULL DEFAULT 0,
  data          TEXT NOT NULL, -- JSON ScreenScan
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL,
  PRIMARY KEY (assessment_id, screen_id),
  FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_screens_assessment ON screens(assessment_id);
CREATE INDEX IF NOT EXISTS idx_screen_scans ON screen_scans(assessment_id, status);
CREATE INDEX IF NOT EXISTS idx_hypotheses_screen ON hypotheses(assessment_id, screen_id);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_handoffs_assessment ON handoffs(assessment_id);
`;

interface AssessmentRow {
  id: string;
  target: string;
  phase: string;
  scope: string;
  budget: string;
  created_at: string;
  updated_at: string;
}

export interface CreateAssessmentParams {
  target: TargetInput;
  scope: ScopePolicy;
  /** 省略時は defaultBudget() */
  budget?: BudgetState;
  /** 省略時は newAssessmentId() */
  id?: string;
}

/** id 配列をマージ(重複排除、既存順を保持)。 */
function unionIds(base: string[], add?: string[]): string[] {
  if (!add || add.length === 0) return base;
  return Array.from(new Set([...base, ...add]));
}

export class AssessmentStore {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
    // server と spawn された pilot が同じ state.sqlite を同時に開く。busy_timeout を最初に設定して、
    // WAL 設定/スキーマ適用/書き込みがロックに当たっても即エラーせず待つ(= "database is locked" 回避)。
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec("PRAGMA journal_mode = WAL;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(SCHEMA);
  }

  /** ファイル(または ":memory:")を開き、スキーマを適用したストアを返す。 */
  static open(dbPath: string): AssessmentStore {
    return new AssessmentStore(new DatabaseSync(dbPath));
  }

  close(): void {
    this.db.close();
  }

  // ───────────────────────── mutations ─────────────────────────

  createAssessment(params: CreateAssessmentParams): AssessmentState {
    const id = params.id ?? newAssessmentId();
    const budget = params.budget ?? defaultBudget();
    const phase: Phase = "init";
    const now = new Date().toISOString();

    return this.tx(() => {
      this.db
        .prepare(
          `INSERT INTO assessments(id, target, phase, scope, budget, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          id,
          JSON.stringify(params.target),
          phase,
          JSON.stringify(params.scope),
          JSON.stringify(budget),
          now,
          now,
        );
      this.insertEvent(id, { type: "assessment_created", payload: { id, target: params.target } });

      return {
        id,
        target: params.target,
        phase,
        scope: params.scope,
        budget,
        screens: [],
        screenScans: [],
        hypotheses: [],
        findings: [],
        handoffs: [],
        events: this.readEvents(id),
      };
    });
  }

  /** 任意のイベントを追記(セマンティックなメソッドで表せない自由記述など)。 */
  appendEvent(assessmentId: string, input: StateEventInput): StateEvent {
    return this.tx(() => {
      const ev = this.insertEvent(assessmentId, input);
      this.touch(assessmentId, ev.ts);
      return ev;
    });
  }

  setPhase(assessmentId: string, to: Phase): void {
    this.tx(() => this.setPhaseInternal(assessmentId, to));
  }

  /** pause / resume(WebUI 操作 §8.3)。control_changed イベントを追記。 */
  setPaused(assessmentId: string, paused: boolean, reason?: string): void {
    this.tx(() => {
      this.insertEvent(assessmentId, { type: "control_changed", payload: { paused, reason } });
      this.touch(assessmentId, new Date().toISOString());
    });
  }

  /** 直近の control_changed から pause 中かを返す(crawl/scan ループの軽量チェック用)。 */
  isPaused(assessmentId: string): boolean {
    const row = this.db
      .prepare(
        "SELECT payload FROM events WHERE assessment_id = ? AND type = 'control_changed' ORDER BY seq DESC LIMIT 1",
      )
      .get(assessmentId) as { payload: string } | undefined;
    if (!row) return false;
    try {
      return Boolean((JSON.parse(row.payload) as { paused?: boolean }).paused);
    } catch {
      return false;
    }
  }

  /** halted フェーズへ遷移し、停止理由を halted イベントとして残す。 */
  halt(assessmentId: string, reason: StopReason, detail?: string): void {
    this.tx(() => {
      this.setPhaseInternal(assessmentId, "halted");
      this.insertEvent(assessmentId, { type: "halted", payload: { reason, detail } });
    });
  }

  updateScope(assessmentId: string, scope: ScopePolicy): void {
    this.tx(() => {
      const ts = new Date().toISOString();
      this.db
        .prepare("UPDATE assessments SET scope = ?, updated_at = ? WHERE id = ?")
        .run(JSON.stringify(scope), ts, assessmentId);
      this.insertEvent(assessmentId, { type: "scope_updated", payload: { scope } });
    });
  }

  updateBudget(assessmentId: string, budget: BudgetState): void {
    this.tx(() => {
      const ts = new Date().toISOString();
      this.db
        .prepare("UPDATE assessments SET budget = ?, updated_at = ? WHERE id = ?")
        .run(JSON.stringify(budget), ts, assessmentId);
      this.insertEvent(assessmentId, { type: "budget_updated", payload: { budget } });
    });
  }

  upsertScreen(assessmentId: string, screen: Screen): void {
    this.tx(() => {
      const now = new Date().toISOString();
      const existed = this.exists("screens", "screen_id", assessmentId, screen.screenId);
      this.db
        .prepare(
          `INSERT INTO screens(assessment_id, screen_id, url_template, auth_state, screen_type, data, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, screen_id) DO UPDATE SET
             url_template = excluded.url_template,
             auth_state   = excluded.auth_state,
             screen_type  = excluded.screen_type,
             data         = excluded.data,
             updated_at   = excluded.updated_at`,
        )
        .run(
          assessmentId,
          screen.screenId,
          screen.urlTemplate,
          screen.authState,
          screen.screenType,
          JSON.stringify(screen),
          now,
          now,
        );
      this.insertEvent(
        assessmentId,
        existed
          ? { type: "screen_updated", payload: { screenId: screen.screenId } }
          : { type: "screen_discovered", payload: { screenId: screen.screenId } },
      );
      // カバレッジ台帳へ自動エンロール: 検出した画面は必ず queued で登録され、取りこぼされない。
      // 既にエントリがあれば進捗を壊さないよう何もしない。
      this.db
        .prepare(
          `INSERT INTO screen_scans(assessment_id, screen_id, status, attempts, data, created_at, updated_at)
           VALUES(?, ?, 'queued', 0, ?, ?, ?)
           ON CONFLICT(assessment_id, screen_id) DO NOTHING`,
        )
        .run(
          assessmentId,
          screen.screenId,
          JSON.stringify({
            screenId: screen.screenId,
            status: "queued",
            attempts: 0,
            hypothesisIds: [],
            findingIds: [],
            lastError: null,
            updatedAt: now,
          } satisfies ScreenScan),
          now,
          now,
        );
      this.touch(assessmentId, now);
    });
  }

  upsertHypothesis(assessmentId: string, h: Hypothesis): void {
    this.tx(() => {
      const now = new Date().toISOString();
      const prev = this.db
        .prepare("SELECT status FROM hypotheses WHERE assessment_id = ? AND id = ?")
        .get(assessmentId, h.id) as { status: string } | undefined;
      this.db
        .prepare(
          `INSERT INTO hypotheses(assessment_id, id, screen_id, class, status, data, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, id) DO UPDATE SET
             screen_id  = excluded.screen_id,
             class      = excluded.class,
             status     = excluded.status,
             data       = excluded.data,
             updated_at = excluded.updated_at`,
        )
        .run(assessmentId, h.id, h.screenId, h.class, h.status, JSON.stringify(h), now, now);

      if (!prev) {
        this.insertEvent(assessmentId, {
          type: "hypothesis_created",
          payload: { hypothesisId: h.id, screenId: h.screenId },
        });
      } else if (prev.status !== h.status) {
        this.insertEvent(assessmentId, {
          type: "hypothesis_status_changed",
          payload: { hypothesisId: h.id, from: prev.status as Hypothesis["status"], to: h.status },
        });
      }
      this.touch(assessmentId, now);
    });
  }

  upsertFinding(assessmentId: string, f: Finding): void {
    this.tx(() => {
      const now = new Date().toISOString();
      const existed = this.exists("findings", "id", assessmentId, f.id);
      this.db
        .prepare(
          `INSERT INTO findings(assessment_id, id, screen_id, severity, data, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, id) DO UPDATE SET
             screen_id  = excluded.screen_id,
             severity   = excluded.severity,
             data       = excluded.data,
             updated_at = excluded.updated_at`,
        )
        .run(assessmentId, f.id, f.screenId, f.severity, JSON.stringify(f), now, now);
      if (!existed) {
        this.insertEvent(assessmentId, { type: "finding_created", payload: { findingId: f.id } });
      }
      this.touch(assessmentId, now);
    });
  }

  upsertHandoff(assessmentId: string, ho: HumanHandoff): void {
    this.tx(() => {
      const now = new Date().toISOString();
      const prev = this.db
        .prepare("SELECT status FROM handoffs WHERE assessment_id = ? AND id = ?")
        .get(assessmentId, ho.id) as { status: string } | undefined;
      this.db
        .prepare(
          `INSERT INTO handoffs(assessment_id, id, reason, status, data, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, id) DO UPDATE SET
             reason     = excluded.reason,
             status     = excluded.status,
             data       = excluded.data,
             updated_at = excluded.updated_at`,
        )
        .run(assessmentId, ho.id, ho.reason, ho.status, JSON.stringify(ho), now, now);

      if (!prev) {
        this.insertEvent(assessmentId, {
          type: "handoff_requested",
          payload: { handoffId: ho.id, reason: ho.reason },
        });
      } else if (prev.status !== "resolved" && ho.status === "resolved") {
        this.insertEvent(assessmentId, {
          type: "handoff_resolved",
          payload: { handoffId: ho.id },
        });
      }
      this.touch(assessmentId, now);
    });
  }

  /** カバレッジ台帳のステータス遷移。状態が変われば screen_scan_status_changed を追記。 */
  setScreenScanStatus(
    assessmentId: string,
    screenId: string,
    status: ScreenScanStatus,
    opts: {
      error?: string | null;
      incrementAttempt?: boolean;
      hypothesisIds?: string[];
      findingIds?: string[];
    } = {},
  ): void {
    this.tx(() => {
      const now = new Date().toISOString();
      const row = this.db
        .prepare("SELECT data FROM screen_scans WHERE assessment_id = ? AND screen_id = ?")
        .get(assessmentId, screenId) as { data: string } | undefined;
      const prev: ScreenScan = row
        ? (JSON.parse(row.data) as ScreenScan)
        : {
            screenId,
            status: "queued",
            attempts: 0,
            hypothesisIds: [],
            findingIds: [],
            lastError: null,
            updatedAt: now,
          };
      const next: ScreenScan = {
        screenId,
        status,
        attempts: prev.attempts + (opts.incrementAttempt ? 1 : 0),
        hypothesisIds: unionIds(prev.hypothesisIds, opts.hypothesisIds),
        findingIds: unionIds(prev.findingIds, opts.findingIds),
        lastError: opts.error !== undefined ? opts.error : prev.lastError,
        updatedAt: now,
      };
      this.db
        .prepare(
          `INSERT INTO screen_scans(assessment_id, screen_id, status, attempts, data, created_at, updated_at)
           VALUES(?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(assessment_id, screen_id) DO UPDATE SET
             status = excluded.status,
             attempts = excluded.attempts,
             data = excluded.data,
             updated_at = excluded.updated_at`,
        )
        .run(assessmentId, screenId, next.status, next.attempts, JSON.stringify(next), now, now);
      if (prev.status !== status) {
        this.insertEvent(assessmentId, {
          type: "screen_scan_status_changed",
          payload: { screenId, from: prev.status, to: status },
        });
      }
      this.touch(assessmentId, now);
    });
  }

  // ───────────────────────── reads ─────────────────────────

  loadAssessment(id: string): AssessmentState | null {
    const row = this.db.prepare("SELECT * FROM assessments WHERE id = ?").get(id) as
      | AssessmentRow
      | undefined;
    if (!row) return null;
    return {
      id: row.id,
      target: JSON.parse(row.target) as TargetInput,
      phase: row.phase as Phase,
      scope: JSON.parse(row.scope) as ScopePolicy,
      budget: JSON.parse(row.budget) as BudgetState,
      screens: this.readScreens(id),
      screenScans: this.readScreenScans(id),
      hypotheses: this.readHypotheses(id),
      findings: this.readFindings(id),
      handoffs: this.readHandoffs(id),
      events: this.readEvents(id),
    };
  }

  listAssessments(): AssessmentSummary[] {
    const rows = this.db
      .prepare("SELECT id, phase, target, created_at, updated_at FROM assessments ORDER BY created_at DESC")
      .all() as Array<Pick<AssessmentRow, "id" | "phase" | "target" | "created_at" | "updated_at">>;
    return rows.map((r) => ({
      id: r.id,
      phase: r.phase as Phase,
      target: JSON.parse(r.target) as TargetInput,
      createdAt: r.created_at,
      updatedAt: r.updated_at,
    }));
  }

  // ─────────────────────── private helpers ───────────────────────

  private setPhaseInternal(assessmentId: string, to: Phase): void {
    const row = this.db.prepare("SELECT phase FROM assessments WHERE id = ?").get(assessmentId) as
      | { phase: string }
      | undefined;
    if (!row) throw new Error(`assessment not found: ${assessmentId}`);
    const from = row.phase as Phase;
    const ts = new Date().toISOString();
    this.db.prepare("UPDATE assessments SET phase = ?, updated_at = ? WHERE id = ?").run(to, ts, assessmentId);
    if (from !== to) {
      this.insertEvent(assessmentId, { type: "phase_changed", payload: { from, to } });
    }
  }

  /** トランザクション境界。node:sqlite はネスト非対応なので内部ヘルパは tx を開かない。 */
  private tx<T>(fn: () => T): T {
    this.db.exec("BEGIN");
    try {
      const result = fn();
      this.db.exec("COMMIT");
      return result;
    } catch (err) {
      this.db.exec("ROLLBACK");
      throw err;
    }
  }

  /** seq を採番して events に追記。tx 内から呼ぶこと。 */
  private insertEvent(assessmentId: string, input: StateEventInput): StateEvent {
    const seqRow = this.db
      .prepare("SELECT COALESCE(MAX(seq), 0) + 1 AS n FROM events WHERE assessment_id = ?")
      .get(assessmentId) as { n: number };
    const seq = seqRow.n;
    const ts = new Date().toISOString();
    this.db
      .prepare("INSERT INTO events(assessment_id, seq, ts, type, payload) VALUES(?, ?, ?, ?, ?)")
      .run(assessmentId, seq, ts, input.type, JSON.stringify(input.payload));
    return { seq, ts, ...input } as StateEvent;
  }

  private touch(assessmentId: string, ts: string): void {
    this.db.prepare("UPDATE assessments SET updated_at = ? WHERE id = ?").run(ts, assessmentId);
  }

  private exists(table: string, idCol: string, assessmentId: string, id: string): boolean {
    const row = this.db
      .prepare(`SELECT 1 AS x FROM ${table} WHERE assessment_id = ? AND ${idCol} = ?`)
      .get(assessmentId, id);
    return row !== undefined;
  }

  private readEvents(id: string): StateEvent[] {
    const rows = this.db
      .prepare("SELECT seq, ts, type, payload FROM events WHERE assessment_id = ? ORDER BY seq ASC")
      .all(id) as Array<{ seq: number; ts: string; type: string; payload: string }>;
    return rows.map(
      (r) => ({ seq: r.seq, ts: r.ts, type: r.type, payload: JSON.parse(r.payload) }) as StateEvent,
    );
  }

  private readScreens(id: string): Screen[] {
    const rows = this.db
      .prepare("SELECT data FROM screens WHERE assessment_id = ? ORDER BY screen_id ASC")
      .all(id) as Array<{ data: string }>;
    return rows.map((r) => JSON.parse(r.data) as Screen);
  }

  private readScreenScans(id: string): ScreenScan[] {
    const rows = this.db
      .prepare("SELECT data FROM screen_scans WHERE assessment_id = ? ORDER BY screen_id ASC")
      .all(id) as Array<{ data: string }>;
    return rows.map((r) => JSON.parse(r.data) as ScreenScan);
  }

  private readHypotheses(id: string): Hypothesis[] {
    const rows = this.db
      .prepare("SELECT data FROM hypotheses WHERE assessment_id = ? ORDER BY created_at ASC, id ASC")
      .all(id) as Array<{ data: string }>;
    return rows.map((r) => JSON.parse(r.data) as Hypothesis);
  }

  private readFindings(id: string): Finding[] {
    const rows = this.db
      .prepare("SELECT data FROM findings WHERE assessment_id = ? ORDER BY created_at ASC, id ASC")
      .all(id) as Array<{ data: string }>;
    return rows.map((r) => JSON.parse(r.data) as Finding);
  }

  private readHandoffs(id: string): HumanHandoff[] {
    const rows = this.db
      .prepare("SELECT data FROM handoffs WHERE assessment_id = ? ORDER BY created_at ASC, id ASC")
      .all(id) as Array<{ data: string }>;
    return rows.map((r) => JSON.parse(r.data) as HumanHandoff);
  }
}
