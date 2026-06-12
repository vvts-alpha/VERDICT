// DESIGN §8.2 — サイトツリー(左ペイン)。screens の urlTemplate を URL 階層に畳み込み、
// 各ノードにスキャン状態バッジ(カバレッジ台帳)を載せる純粋関数。

import type { Screen, ScreenScan, ScreenScanStatus, ScreenType } from "./types/index.js";

export interface TreeNode {
  /** 表示ラベル(例 "products", "{id}", "/") */
  segment: string;
  /** 完全な urlTemplate(例 "/products/{id}") */
  path: string;
  /** この path に対応する画面があれば */
  screenId: string | null;
  screenType: ScreenType | null;
  scanStatus: ScreenScanStatus | null;
  children: TreeNode[];
}

interface MutNode {
  segment: string;
  path: string;
  screenId: string | null;
  screenType: ScreenType | null;
  scanStatus: ScreenScanStatus | null;
  children: Map<string, MutNode>;
}

function segmentsOf(urlTemplate: string): string[] {
  if (urlTemplate === "/") return ["/"];
  return urlTemplate.split("/").filter((s) => s.length > 0);
}

function toNodes(children: Map<string, MutNode>): TreeNode[] {
  return [...children.values()]
    .sort((a, b) => (a.segment < b.segment ? -1 : a.segment > b.segment ? 1 : 0))
    .map((n) => ({
      segment: n.segment,
      path: n.path,
      screenId: n.screenId,
      screenType: n.screenType,
      scanStatus: n.scanStatus,
      children: toNodes(n.children),
    }));
}

/** screens(+ カバレッジ台帳)から URL 階層ツリー(forest)を構築。 */
export function buildSiteTree(screens: Screen[], scans: ScreenScan[]): TreeNode[] {
  const statusById = new Map(scans.map((s) => [s.screenId, s.status] as const));
  const roots = new Map<string, MutNode>();

  const ensure = (level: Map<string, MutNode>, segment: string, path: string): MutNode => {
    let node = level.get(segment);
    if (!node) {
      node = { segment, path, screenId: null, screenType: null, scanStatus: null, children: new Map() };
      level.set(segment, node);
    }
    return node;
  };

  for (const screen of screens) {
    let level = roots;
    let acc = "";
    let node: MutNode | null = null;
    for (const seg of segmentsOf(screen.urlTemplate)) {
      acc = seg === "/" ? "/" : `${acc}/${seg}`;
      node = ensure(level, seg, acc);
      level = node.children;
    }
    if (node) {
      node.screenId = screen.screenId;
      node.screenType = screen.screenType;
      node.scanStatus = statusById.get(screen.screenId) ?? null;
    }
  }

  return toNodes(roots);
}
