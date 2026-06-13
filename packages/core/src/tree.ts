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

/** 画面のホスト(observedUrls 優先、無ければ絶対 urlTemplate から)。判らなければ null。 */
function hostOf(screen: Screen): string | null {
  for (const u of screen.observedUrls) {
    try {
      const h = new URL(u).host;
      if (h) return h;
    } catch {
      /* not an absolute URL */
    }
  }
  try {
    const h = new URL(screen.urlTemplate).host;
    if (h) return h;
  } catch {
    /* path-only */
  }
  return null;
}

const ensure = (level: Map<string, MutNode>, segment: string, path: string): MutNode => {
  let node = level.get(segment);
  if (!node) {
    node = { segment, path, screenId: null, screenType: null, scanStatus: null, children: new Map() };
    level.set(segment, node);
  }
  return node;
};

/** screen の urlTemplate を level 以下にパスとして畳み込み、葉に screen を載せる。
 *  prefix は path(=折りたたみキー)の一意化のための接頭辞(マルチドメイン時はホスト名)。
 *  ルート("/")の screen は homeNode(あれば)に直接載せる。 */
function foldPath(
  level: Map<string, MutNode>,
  screen: Screen,
  status: ScreenScanStatus | null,
  prefix: string,
  homeNode: MutNode | null,
): void {
  const segs = segmentsOf(screen.urlTemplate);
  if (homeNode && segs.length === 1 && segs[0] === "/") {
    homeNode.screenId = screen.screenId;
    homeNode.screenType = screen.screenType;
    homeNode.scanStatus = status;
    return;
  }
  let cur = level;
  let acc = prefix;
  let node: MutNode | null = null;
  for (const seg of segs) {
    acc = seg === "/" ? `${prefix}/` : `${acc}/${seg}`;
    node = ensure(cur, seg, acc);
    cur = node.children;
  }
  if (node) {
    node.screenId = screen.screenId;
    node.screenType = screen.screenType;
    node.scanStatus = status;
  }
}

/** screens(+ カバレッジ台帳)から URL 階層ツリー(forest)を構築。
 *  既知ホストが 2 つ以上にまたがる場合はトップをドメインで分ける(API が別ドメインの時に混ざらない)。
 *  単一/不明ホストなら従来どおりパス森(ドメインはステータスバー側で判る)。 */
export function buildSiteTree(screens: Screen[], scans: ScreenScan[]): TreeNode[] {
  const statusById = new Map(scans.map((s) => [s.screenId, s.status] as const));
  const distinctHosts = new Set(screens.map(hostOf).filter((h): h is string => h !== null));
  const groupByHost = distinctHosts.size >= 2;

  const roots = new Map<string, MutNode>();
  for (const screen of screens) {
    const status = statusById.get(screen.screenId) ?? null;
    if (groupByHost) {
      const host = hostOf(screen) ?? "(unknown host)";
      const hostNode = ensure(roots, host, host); // トップ = ドメイン
      foldPath(hostNode.children, screen, status, host, hostNode);
    } else {
      foldPath(roots, screen, status, "", null);
    }
  }

  return toNodes(roots);
}
