// DESIGN §6.1 / §6.7 — BFS クロール本体。frontier を scope/depth/budget で打ち切り、
// 新規 dedup_key が N 連続ゼロで停止。発見画面は store 経由でカバレッジ台帳に自動エンロール。

import type { AssessmentStore, Screen } from "@veritas/core";
import { recordRequests } from "@veritas/core";
import type { CapturedExchange, CrawlConfig, CrawlResult, CrawlStopReason, Driver, Observation } from "./types.js";
import { InventoryBuilder } from "./inventory.js";
import { apiKey, inferApiCall, isApiExchange } from "./api.js";
import { isInScope, resolveLink } from "./url.js";
import { detectStuck } from "./auth.js";

const DEFAULTS = {
  maxRequests: 300,
  maxScreens: 200,
  maxConsecutiveNoNew: 20,
  maxWallClockMs: 5 * 60 * 1000,
};

interface FrontierItem {
  url: string;
  depth: number;
}

export interface CrawlHooks {
  /** 渡すと、発見画面を upsertScreen(→ カバレッジ台帳に自動エンロール)し phase を phase1_recon に。 */
  store?: AssessmentStore;
  assessmentId?: string;
  onScreen?: (screen: Screen, isNew: boolean) => void;
  /** 2 パス目(認証済み再クロール)で既存画面を引き継ぐ(dedup + screenId 継続)。 */
  seedScreens?: Screen[];
  /** 能動探索(§7.2): 新規画面ごとにブラウザを操作し、発火 API と新 URL を返す。 */
  explore?: (observation: Observation) => Promise<{ apis: CapturedExchange[]; urls: string[] }>;
}

export async function crawl(
  config: CrawlConfig,
  driver: Driver,
  hooks: CrawlHooks = {},
): Promise<CrawlResult> {
  const startedAt = Date.now();
  const maxRequests = config.maxRequests ?? DEFAULTS.maxRequests;
  const maxScreens = config.maxScreens ?? DEFAULTS.maxScreens;
  const maxConsecutiveNoNew = config.maxConsecutiveNoNew ?? DEFAULTS.maxConsecutiveNoNew;
  const maxWallClockMs = config.maxWallClockMs ?? DEFAULTS.maxWallClockMs;

  const inventory = new InventoryBuilder();
  if (hooks.seedScreens) inventory.seed(hooks.seedScreens);
  const visited = new Set<string>();
  const queue: FrontierItem[] = [{ url: config.startUrl, depth: 0 }];
  let visitedCount = 0;
  let consecutiveNoNew = 0;
  let handoffsRaised = 0;
  const handoffUrls = new Set<string>();
  let stopReason: CrawlStopReason = "frontier_empty";

  if (hooks.store && hooks.assessmentId) {
    hooks.store.setPhase(hooks.assessmentId, "phase1_recon");
  }

  while (queue.length > 0) {
    if (visitedCount >= maxRequests) {
      stopReason = "budget_requests";
      break;
    }
    if (inventory.screens().length >= maxScreens) {
      stopReason = "budget_screens";
      break;
    }
    if (Date.now() - startedAt >= maxWallClockMs) {
      stopReason = "wall_clock";
      break;
    }
    if (consecutiveNoNew >= maxConsecutiveNoNew) {
      stopReason = "no_new_screens";
      break;
    }
    if (hooks.store && hooks.assessmentId && hooks.store.isPaused(hooks.assessmentId)) {
      stopReason = "paused";
      break;
    }

    const item = queue.shift()!;
    if (visited.has(item.url)) continue;
    if (!isInScope(item.url, config.scope)) continue;
    visited.add(item.url);

    let observation;
    try {
      observation = await driver.visit(item.url);
    } catch {
      continue; // 取得失敗はスキップ(M1)。詰まり検出/handoff は M6
    }
    visitedCount += 1;

    const { screen, isNew } = inventory.ingest(observation, config.authState ?? "unauth");
    consecutiveNoNew = isNew ? 0 : consecutiveNoNew + 1;
    if (hooks.store && hooks.assessmentId) hooks.store.upsertScreen(hooks.assessmentId, screen);
    hooks.onScreen?.(screen, isNew);

    // 詰まり検出(§6.3): CAPTCHA/MFA/challenge/429 → HumanHandoff 起票。壁の先へは降りない
    // が、フロンティアの他経路は継続(non-blocking)。Cookie 注入はしない。
    const stuck = detectStuck(observation);
    if (stuck) {
      if (hooks.store && hooks.assessmentId && !handoffUrls.has(observation.finalUrl)) {
        handoffUrls.add(observation.finalUrl);
        handoffsRaised += 1;
        hooks.store.upsertHandoff(hooks.assessmentId, {
          id: `ho-${String(handoffsRaised).padStart(3, "0")}`,
          reason: stuck.reason,
          url: observation.finalUrl,
          message: stuck.detail,
          status: "pending",
          createdAt: new Date().toISOString(),
          resolvedAt: null,
        });
      }
      continue;
    }

    if (config.followLinks && item.depth < config.maxDepth) {
      // 能動探索: 新規画面でフォーム送信等を実行し、発火 API を画面へ、新 URL を frontier へ。
      if (isNew && hooks.explore) {
        try {
          const ex = await hooks.explore(observation);
          const have = new Set(screen.apis.map(apiKey));
          for (const cap of ex.apis) {
            if (!isApiExchange(cap)) continue;
            const a = inferApiCall(cap);
            if (!have.has(apiKey(a))) {
              have.add(apiKey(a));
              screen.apis.push(a);
            }
          }
          if (hooks.store && hooks.assessmentId) hooks.store.upsertScreen(hooks.assessmentId, screen);
          for (const u of ex.urls) {
            if (!visited.has(u) && isInScope(u, config.scope)) queue.push({ url: u, depth: item.depth + 1 });
          }
        } catch {
          /* 探索失敗は無視して継続 */
        }
      }
      for (const href of [...observation.links, ...observation.virtualRoutes]) {
        const abs = resolveLink(observation.finalUrl, href);
        if (abs && !visited.has(abs) && isInScope(abs, config.scope)) {
          queue.push({ url: abs, depth: item.depth + 1 });
        }
      }
    }
  }

  if (hooks.store && hooks.assessmentId && visitedCount > 0) {
    const current = hooks.store.loadAssessment(hooks.assessmentId);
    if (current) {
      let host = "";
      try {
        host = new URL(config.startUrl).host;
      } catch {
        /* ignore */
      }
      hooks.store.updateBudget(hooks.assessmentId, recordRequests(current.budget, host, visitedCount));
    }
  }

  const screens = inventory.screens();
  return {
    startUrl: config.startUrl,
    screens,
    stats: {
      visited: visitedCount,
      screens: screens.length,
      apis: screens.reduce((n, s) => n + s.apis.length, 0),
      handoffs: handoffsRaised,
      stopReason,
      elapsedMs: Date.now() - startedAt,
    },
  };
}
