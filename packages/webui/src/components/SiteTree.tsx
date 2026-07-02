import { useState } from "react";
import type { TreeNode } from "@veritas/core";
import { useRole } from "../api";

// exclude 対象 = まだスキャンしていない(or 途中/エラーの)画面のみ。clean/finding/suspected は保持する。
const EXCLUDABLE = new Set(["queued", "scanning", "error"]);
function collectExcludable(node: TreeNode, out: string[] = []): string[] {
  if (node.screenId && (node.scanStatus === null || EXCLUDABLE.has(node.scanStatus))) out.push(node.screenId);
  for (const c of node.children) collectExcludable(c, out);
  return out;
}

// 状態 → アクセシビリティ用ラベル(dot の色は CSS が担当)。
const STATUS_LABEL: Record<string, string> = {
  queued: "queued",
  scanning: "scanning",
  clean: "clean",
  finding: "finding",
  suspected: "suspected (needs manual verification)",
  blocked: "blocked",
  excluded: "excluded",
  error: "error",
};

/** この部分木に含まれる finding 画面の数(折りたたみ時のロールアップ表示用)。 */
function countFindings(node: TreeNode): number {
  let n = node.scanStatus === "finding" ? 1 : 0;
  for (const c of node.children) n += countFindings(c);
  return n;
}

function Node({
  node,
  selected,
  onSelect,
  collapsed,
  toggle,
  canWrite,
  onExclude,
}: {
  node: TreeNode;
  selected: string | null;
  onSelect: (id: string) => void;
  collapsed: Set<string>;
  toggle: (path: string) => void;
  canWrite: boolean;
  onExclude: (screenIds: string[], label: string) => void;
}) {
  const isSelected = node.screenId !== null && node.screenId === selected;
  const status = node.scanStatus ?? "";
  const hasChildren = node.children.length > 0;
  const isCollapsed = collapsed.has(node.path);
  // 折りたたみ中の枝に finding があれば件数バッジを出す(展開中は各子が自分で出す)。
  const rolledFindings = hasChildren && isCollapsed ? countFindings(node) : 0;
  // この部分木で除外可能(未スキャン)な画面。親ノードで丸ごと除外できる。
  const excludable = canWrite ? collectExcludable(node) : [];

  return (
    <li>
      <div
        className={`node ${isSelected ? "sel" : ""} ${status}`}
        onClick={() => (node.screenId ? onSelect(node.screenId) : hasChildren && toggle(node.path))}
        data-screen={node.screenId ?? ""}
      >
        {hasChildren ? (
          <button
            type="button"
            className={`twist ${isCollapsed ? "" : "open"}`}
            onClick={(e) => {
              e.stopPropagation();
              toggle(node.path);
            }}
            aria-label={isCollapsed ? "expand" : "collapse"}
          >
            ▸
          </button>
        ) : (
          <span className="twist-spacer" />
        )}
        <span className="dot" title={STATUS_LABEL[status] ?? ""} />
        <span className="seg" {...(/^\{.*\}$/.test(node.segment) ? { "data-dyn": "" } : {})}>
          {node.segment}
        </span>
        {rolledFindings > 0 ? <span className="roll" title={`${rolledFindings} finding(s) inside`}>{rolledFindings}</span> : null}
        {node.screenType ? <span className="stype">{node.screenType}</span> : null}
        {excludable.length > 0 ? (
          <button
            type="button"
            className="tree-exclude"
            title={hasChildren ? `Exclude this branch — ${excludable.length} un-scanned screen(s)` : "Exclude this screen from scanning"}
            onClick={(e) => {
              e.stopPropagation();
              onExclude(excludable, node.path);
            }}
          >
            ⊘{excludable.length > 1 ? ` ${excludable.length}` : ""}
          </button>
        ) : null}
      </div>
      {hasChildren && !isCollapsed ? (
        <ul>
          {node.children.map((child) => (
            <Node key={child.path} node={child} selected={selected} onSelect={onSelect} collapsed={collapsed} toggle={toggle} canWrite={canWrite} onExclude={onExclude} />
          ))}
        </ul>
      ) : null}
    </li>
  );
}

export function SiteTree({
  tree,
  selected,
  onSelect,
  onExclude,
}: {
  tree: TreeNode[];
  selected: string | null;
  onSelect: (id: string) => void;
  onExclude: (screenIds: string[]) => void;
}) {
  const { canWrite } = useRole();
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const toggle = (path: string): void =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  // 複数(部分木)を除外するときだけ確認する。単一画面は即除外。
  const handleExclude = (screenIds: string[], label: string): void => {
    if (screenIds.length > 1 && !window.confirm(`Exclude ${screenIds.length} un-scanned screen(s) under "${label}" from scanning?`)) return;
    onExclude(screenIds);
  };

  return (
    <nav className="tree">
      <div className="pane-title">SITE TREE</div>
      {tree.length === 0 ? (
        <p className="muted">no screens yet — run a crawl</p>
      ) : (
        <ul className="root">
          {tree.map((node) => (
            <Node key={node.path} node={node} selected={selected} onSelect={onSelect} collapsed={collapsed} toggle={toggle} canWrite={canWrite} onExclude={handleExclude} />
          ))}
        </ul>
      )}
    </nav>
  );
}
