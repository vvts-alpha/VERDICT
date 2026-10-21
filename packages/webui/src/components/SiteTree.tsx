import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import type { TreeNode } from "@veritas/core";
import { useRole } from "../api";
import { useT } from "../i18n";
import type { ScreenHonesty } from "./screen-status";
import { Button } from "./ui/button";
import { Badge } from "./ui/badge";

// Exclude targets = only screens not yet scanned (or in-progress/errored). Keep clean/finding/suspected.
const EXCLUDABLE = new Set(["queued", "scanning", "error"]);

// Status → accessibility label (the row's tooltip; the dot's color is handled by CSS).
const STATUS_LABEL: Record<string, string> = {
  queued: "queued",
  scanning: "scanning",
  clean: "clean",
  finding: "finding",
  suspected: "suspected (needs manual verification)",
  unverified: "unverified (inconclusive — check gaps remain)",
  "unknown-records": "status claim — no check records (detail unknown)",
  blocked: "blocked",
  excluded: "excluded",
  error: "error",
};

const DOT_STATUS: Record<string, string> = {
  queued: "bg-muted-foreground/50",
  scanning: "bg-primary animate-pulse",
  clean: "bg-success",
  finding: "bg-warning",
  suspected: "bg-suspected",
  unverified: "bg-warning/60",
  "unknown-records": "border border-muted-foreground/60 bg-transparent",
  blocked: "bg-destructive",
  excluded: "border border-muted-foreground bg-transparent",
  error: "bg-destructive",
};

/** Number of finding screens contained in this subtree (for the rolled-up display when collapsed). */
function countFindings(node: TreeNode): number {
  let n = node.scanStatus === "finding" ? 1 : 0;
  for (const c of node.children) n += countFindings(c);
  return n;
}

/** One DFS over the tree → excludable screen-ids per subtree (replaces per-node subtree walks: O(n) total). */
function buildExcludableMap(tree: TreeNode[]): Map<TreeNode, string[]> {
  const map = new Map<TreeNode, string[]>();
  const walk = (n: TreeNode): string[] => {
    const out: string[] = [];
    if (n.screenId && (n.scanStatus === null || EXCLUDABLE.has(n.scanStatus))) out.push(n.screenId);
    for (const c of n.children) out.push(...walk(c));
    map.set(n, out);
    return out;
  };
  for (const n of tree) walk(n);
  return map;
}

function Node({
  node,
  selected,
  onSelect,
  collapsed,
  toggle,
  canWrite,
  onExclude,
  excludableMap,
  focusPath,
  defaultPath,
  onFocusRow,
  honesty,
}: {
  node: TreeNode;
  selected: string | null;
  onSelect: (id: string) => void;
  collapsed: Set<string>;
  toggle: (path: string) => void;
  canWrite: boolean;
  onExclude: (screenIds: string[], label: string) => void;
  excludableMap: Map<TreeNode, string[]>;
  focusPath: string | null;
  defaultPath: string | undefined;
  onFocusRow: (path: string) => void;
  honesty: Map<string, ScreenHonesty>;
}) {
  const t = useT();
  const isSelected = node.screenId !== null && node.screenId === selected;
  // Ledger-honest status: a raw "clean" with unfulfilled plans/gaps shows unverified; a conclusive
  // claim with no check records shows the neutral unknown-records dot — never green.
  const status = (node.screenId ? honesty.get(node.screenId)?.status : undefined) ?? node.scanStatus ?? "";
  const hasChildren = node.children.length > 0;
  const isCollapsed = collapsed.has(node.path);
  // If a collapsed branch has findings, show a count badge (when expanded, each child shows its own).
  const rolledFindings = hasChildren && isCollapsed ? countFindings(node) : 0;
  // Excludable (un-scanned) screens in this subtree. Can be excluded wholesale from the parent node.
  const excludable = canWrite ? excludableMap.get(node) ?? [] : [];
  // Multi-screen exclusion arms the button instead of a blocking window.confirm — click again within 3s to confirm.
  const [armed, setArmed] = useState(false);
  useEffect(() => {
    if (!armed) return;
    const timer = setTimeout(() => setArmed(false), 3000);
    return () => clearTimeout(timer);
  }, [armed]);

  const activate = (): void => {
    if (node.screenId) onSelect(node.screenId);
    else if (hasChildren) toggle(node.path);
  };
  // Tree keyboard nav: Enter/Space activates; Right expands, Left collapses; Up/Down moves between visible rows.
  const onKey = (e: KeyboardEvent<HTMLDivElement>): void => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      activate();
      return;
    }
    if (e.key === "ArrowRight" && hasChildren && isCollapsed) {
      toggle(node.path);
      return;
    }
    if (e.key === "ArrowLeft" && hasChildren && !isCollapsed) {
      toggle(node.path);
      return;
    }
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      const rows = Array.from(e.currentTarget.closest("[data-site-tree]")?.querySelectorAll<HTMLElement>("[data-treeitem]") ?? []);
      const next = rows[rows.indexOf(e.currentTarget) + (e.key === "ArrowDown" ? 1 : -1)];
      next?.focus();
    }
  };

  return (
    <li role="none">
      <div
        className={`group mx-0.5 my-0.5 flex cursor-pointer select-none items-center gap-2 rounded-md px-2 py-1 hover:bg-muted ${isSelected ? "bg-secondary shadow-[inset_2px_0_0_var(--accent)]" : ""}`}
        data-treeitem=""
        onClick={activate}
        onKeyDown={onKey}
        onFocus={() => onFocusRow(node.path)}
        data-screen={node.screenId ?? ""}
        role="treeitem"
        tabIndex={node.path === (focusPath ?? defaultPath) ? 0 : -1}
        aria-selected={node.screenId ? isSelected : undefined}
        aria-expanded={hasChildren ? !isCollapsed : undefined}
        title={`${node.path}${STATUS_LABEL[status] ? ` — ${t(STATUS_LABEL[status])}` : ""}`}
      >
        {hasChildren ? (
          <Button
            type="button"
            variant="ghost"
            size="icon-xs"
            className="size-4 shrink-0 text-muted-foreground"
            onClick={(e) => {
              e.stopPropagation();
              toggle(node.path);
            }}
            tabIndex={-1}
            aria-label={isCollapsed ? t("expand") : t("collapse")}
          >
            <span className={isCollapsed ? "" : "rotate-90"}>▸</span>
          </Button>
        ) : (
          <span className="w-4 shrink-0" />
        )}
        <span className={`size-2 shrink-0 rounded-full ${DOT_STATUS[status] ?? "bg-border"}`} aria-hidden="true" />
        <span className={`truncate font-mono ${status === "finding" ? "text-warning" : /^\{.*\}$/.test(node.segment) ? "text-muted-foreground italic" : ""}`}>
          {node.segment}
        </span>
        {rolledFindings > 0 ? <Badge className="bg-warning text-on-warning" title={t("{n} finding(s) inside", { n: rolledFindings })}>{rolledFindings}</Badge> : null}
        {node.screenType ? <Badge variant="secondary" className="ml-auto shrink-0 text-[10px]">{node.screenType}</Badge> : null}
        {excludable.length > 0 ? (
          <Button
            type="button"
            variant={armed ? "destructive" : "outline"}
            size="xs"
            className={`ml-auto h-5 text-[10px] ${armed ? "opacity-100" : "opacity-0 group-hover:opacity-100 group-focus-within:opacity-100"}`}
            title={armed ? t("Click again to confirm") : hasChildren ? t("Exclude this branch — {n} un-scanned screen(s)", { n: excludable.length }) : t("Exclude this screen from scanning")}
            onClick={(e) => {
              e.stopPropagation();
              if (excludable.length > 1 && !armed) {
                setArmed(true);
                return;
              }
              onExclude(excludable, node.path);
            }}
            tabIndex={-1}
          >
            {armed ? t("Exclude {n}?", { n: excludable.length }) : `⊘${excludable.length > 1 ? ` ${excludable.length}` : ""}`}
          </Button>
        ) : null}
      </div>
      {hasChildren && !isCollapsed ? (
        <ul role="group" className="ml-4 border-l border-border pl-1">
          {node.children.map((child) => (
            <Node
              key={child.path}
              node={child}
              selected={selected}
              onSelect={onSelect}
              collapsed={collapsed}
              toggle={toggle}
              canWrite={canWrite}
              onExclude={onExclude}
              excludableMap={excludableMap}
              focusPath={focusPath}
              defaultPath={defaultPath}
              onFocusRow={onFocusRow}
              honesty={honesty}
            />
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
  honesty,
}: {
  tree: TreeNode[];
  selected: string | null;
  onSelect: (id: string) => void;
  onExclude: (screenIds: string[]) => void;
  honesty: Map<string, ScreenHonesty>;
}) {
  const { canWrite } = useRole();
  const t = useT();
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  // Roving tabindex: the focused row is the tree's single Tab stop (default = first row).
  const [focusPath, setFocusPath] = useState<string | null>(null);
  const excludableMap = useMemo(() => buildExcludableMap(tree), [tree]);
  const toggle = (path: string): void =>
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });


  return (
    <nav className="min-h-0 min-w-0 flex-1 overflow-auto" data-site-tree="" aria-label={t("Site tree")}>
      <div className="border-b border-border px-3 py-2 text-[11px] uppercase tracking-wide text-muted-foreground">{t("SITE TREE")}</div>
      {tree.length === 0 ? (
        <p className="p-2 text-muted-foreground">{t("no screens yet — run a crawl")}</p>
      ) : (
        <ul className="px-2 py-2" role="tree">
          {tree.map((node) => (
            <Node
              key={node.path}
              node={node}
              selected={selected}
              onSelect={onSelect}
              collapsed={collapsed}
              toggle={toggle}
              canWrite={canWrite}
              onExclude={onExclude}
              excludableMap={excludableMap}
              focusPath={focusPath}
              defaultPath={tree[0]?.path}
              onFocusRow={setFocusPath}
              honesty={honesty}
            />
          ))}
        </ul>
      )}
    </nav>
  );
}
