import type { TreeNode } from "@veritas/core";

const BADGE: Record<string, string> = {
  queued: "◌",
  scanning: "◐",
  clean: "✓",
  finding: "⚠",
  blocked: "⛔",
  excluded: "—",
  error: "✗",
};

function Node({
  node,
  selected,
  onSelect,
  depth,
}: {
  node: TreeNode;
  selected: string | null;
  onSelect: (id: string) => void;
  depth: number;
}) {
  const isSelected = node.screenId !== null && node.screenId === selected;
  const status = node.scanStatus ?? "";
  return (
    <li>
      <div
        className={`node ${isSelected ? "sel" : ""} ${status}`}
        style={{ paddingLeft: 6 + depth * 14 }}
        onClick={() => node.screenId && onSelect(node.screenId)}
        data-screen={node.screenId ?? ""}
      >
        <span className="badge">{node.scanStatus ? (BADGE[node.scanStatus] ?? "·") : "·"}</span>
        <span className="seg">{node.segment}</span>
        {node.screenType ? <span className="stype">{node.screenType}</span> : null}
      </div>
      {node.children.length > 0 ? (
        <ul>
          {node.children.map((child) => (
            <Node key={child.path} node={child} selected={selected} onSelect={onSelect} depth={depth + 1} />
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
}: {
  tree: TreeNode[];
  selected: string | null;
  onSelect: (id: string) => void;
}) {
  return (
    <nav className="tree">
      <div className="pane-title">SITE TREE</div>
      {tree.length === 0 ? (
        <p className="muted">no screens yet — run a crawl</p>
      ) : (
        <ul className="root">
          {tree.map((node) => (
            <Node key={node.path} node={node} selected={selected} onSelect={onSelect} depth={0} />
          ))}
        </ul>
      )}
    </nav>
  );
}
