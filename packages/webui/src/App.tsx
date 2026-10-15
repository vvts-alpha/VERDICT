import { useEffect, useState } from "react";
import type { MouseEvent } from "react";
import type { StateView } from "@veritas/core";
import { postControl, postControlBody, useAssessmentId, useRole, useStateView } from "./api";
import { useDesktopShell } from "./desktop-shell";
import { StatusBar, StatusBarShell } from "./components/StatusBar";
import { HandoffBar } from "./components/HandoffBar";
import { Progress } from "./components/Progress";
import { SiteTree } from "./components/SiteTree";
import { Findings } from "./components/Findings";
import { ScreenView } from "./components/ScreenView";
import { ApiList } from "./components/ApiList";
import { JsAssets } from "./components/JsAssets";
import { Log } from "./components/Log";
import { Scenarios } from "./components/Scenarios";
import { Index } from "./components/Index";
import { Sessions } from "./components/Sessions";
import { Chat } from "./components/Chat";
import { Control } from "./components/Control";
import { LiveView } from "./components/LiveView";
import { Badge } from "./components/ui/badge";
import { ResizableHandle, ResizablePanel, ResizablePanelGroup } from "./components/ui/resizable";
import { useDefaultLayout } from "react-resizable-panels";
import {
  Bug, FileCode2, KeyRound, LayoutGrid, MessageSquare,
  Monitor, Network, ScrollText, SlidersHorizontal, Video, Workflow,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

type Tab = "screen" | "findings" | "scenarios" | "log" | "apis" | "js" | "sessions" | "ask" | "control" | "live";

/** Running inside the Electron desktop shell? (its title bar already carries the VERDICT brand). */
const isDesktop = typeof window !== "undefined" && !!(window as unknown as { verdictDesktop?: unknown }).verdictDesktop;

const TABS: { key: Tab; label: string; icon: LucideIcon; count?: (v: StateView) => number }[] = [
  { key: "screen", label: "Screen", icon: Monitor },
  { key: "findings", label: "Findings", icon: Bug, count: (v) => v.findings.length },
  { key: "scenarios", label: "Scenarios", icon: Workflow },
  { key: "apis", label: "APIs", icon: Network },
  { key: "js", label: "JS", icon: FileCode2, count: (v) => v.jsAssets.length },
  { key: "log", label: "Log", icon: ScrollText, count: (v) => v.events.length },
  { key: "sessions", label: "Sessions", icon: KeyRound },
  { key: "ask", label: "Ask", icon: MessageSquare },
  { key: "live", label: "Live", icon: Video },
  { key: "control", label: "Control", icon: SlidersHorizontal },
];

function topNavCls(active: boolean): string {
  return `inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1.5 text-sm transition-colors ${
    active ? "bg-accent font-medium text-accent-foreground" : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
  }`;
}

function tabCls(active: boolean, danger: boolean): string {
  return `inline-flex shrink-0 items-center gap-1.5 rounded-md px-2.5 py-1 text-sm whitespace-nowrap transition-colors ${
    active
      ? "bg-accent font-medium text-accent-foreground"
      : danger
        ? "text-destructive hover:bg-accent/60"
        : "text-muted-foreground hover:bg-accent/60 hover:text-foreground"
  }`;
}

// DESIGN §8 — top: common nav (brand · Projects · desktop views); status row (target · run metrics ·
// pause/export/conn); then a resizable SITE TREE pane beside a tabbed content area. Desktop Browser/Settings
// open as panes over the tree+content area (status row stays); the assessment DOM stays mounted-but-hidden
// so tab/screen selection, tree expansion, and unsaved form drafts survive the round-trip.
export function App() {
  const id = useAssessmentId();
  const { view, conn } = useStateView(id);
  const desktop = useDesktopShell();
  const { authEnabled } = useRole();
  const desktopNode = desktop && desktop.view !== "main" ? desktop.views[desktop.view] : null;
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("screen");
  // Transient error toast for rejected/dropped control POSTs (they used to fail silently).
  const [notice, setNotice] = useState<string | null>(null);
  useEffect(() => {
    if (!notice) return;
    const t = window.setTimeout(() => setNotice(null), 4500);
    return () => window.clearTimeout(t);
  }, [notice]);
  const ctl = (label: string, p: Promise<true | string>): void => {
    void p.then((r) => {
      if (r !== true) setNotice(`${label} failed — ${r}`);
    });
  };

  // Site-tree pane width persists across reloads (user-adjusted sizes only).
  const { defaultLayout, onLayoutChanged } = useDefaultLayout({
    id: "verdict-shell",
    onlySaveAfterUserInteractions: true,
    storage: window.localStorage,
  });

  // Poll the number of sessions awaiting login → highlight the Sessions tab (a sign the operator's input is needed).
  const [awaitingSessions, setAwaitingSessions] = useState(0);
  useEffect(() => {
    if (!id) return;
    let alive = true;
    const poll = (): void => {
      fetch(`/api/assessments/${encodeURIComponent(id)}/sessions`)
        .then((r) => r.json())
        .then((rs: Array<{ awaiting?: boolean }>) => {
          if (alive) setAwaitingSessions(Array.isArray(rs) ? rs.filter((s) => s.awaiting).length : 0);
        })
        .catch(() => {});
    };
    poll();
    const t = window.setInterval(poll, 3000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, [id]);

  const selectedScreen = view?.screens.find((s) => s.screenId === selected) ?? view?.screens[0];
  const control = (path: string, label = "control") => () => ctl(label, postControl(`/api/assessments/${view!.id}/${path}`));
  // Leaving a desktop view goes through the shell — it can veto (e.g. unsaved Settings edits).
  const goMain = (): boolean => !desktop || desktop.view === "main" || desktop.onNavigate("main");
  const navTo = (t: Tab): void => {
    if (!goMain()) return;
    setTab(t);
  };
  const onSelect = (sid: string): void => {
    if (!goMain()) return;
    setSelected(sid);
    setTab("screen");
  };
  // Projects is a real navigation (list view); through the guard so unsaved Settings can veto first.
  const onProjectsClick = (e: MouseEvent<HTMLAnchorElement>): void => {
    if (!desktop) return; // plain browser: the plain <a href> just works
    e.preventDefault();
    desktop.runGuarded(() => {
      // A run is open → "?"" is a real navigation (also drops the desktop pane with the page). Already at
      // the root → assigning "?" is a same-document no-op, so leave the desktop view explicitly instead.
      if (id) window.location.assign("?");
      else void desktop.onNavigate("main");
    });
  };

  const targetLabel = view ? (view.target.kind === "single_url" ? view.target.url : view.target.path) : null;
  const crumbs = view ? (
    <span className="flex min-w-0 items-baseline gap-2 text-sm">
      <span className="truncate font-medium" title={targetLabel ?? ""}>{targetLabel}</span>
      <span className="shrink-0 font-mono text-xs text-muted-foreground" title={view.id}>run {view.id}</span>
    </span>
  ) : id ? (
    <span className="shrink-0 font-mono text-xs text-muted-foreground" title={id}>run {id}</span>
  ) : (
    // No run open — the top nav and the page heading already name the place; repeating "Projects"/the
    // pane label here only triples it. Keep the row for the conn dot and role badge.
    <span />
  );

  return (
    // h-full (not h-screen): in the desktop shell the 38px title bar already consumed viewport height —
    // 100vh here would overflow the flex-1 container below it and clip the tree/content bottom edge.
    <div className="flex h-full flex-col">
      {/* Common top nav — same row in web and desktop. Desktop-only entries come from the shell context. */}
      <nav className="flex h-11 shrink-0 items-center gap-1 border-b border-border bg-card px-2" aria-label="Main">
        {!isDesktop ? (
          <a href="?" title="VERDICT" className="mr-1 flex shrink-0 items-center px-2" onClick={onProjectsClick}>
            <img className="block h-6 w-auto" src="/verdict-title.png" alt="VERDICT" />
          </a>
        ) : null}
        <a href="?" onClick={onProjectsClick} className={topNavCls(!id && !desktopNode)} aria-current={!id && !desktopNode ? "page" : undefined}>
          <LayoutGrid className="size-4" />
          Projects
        </a>
        {desktop?.nav.map((n) => (
          <button
            key={n.key}
            type="button"
            onClick={() => void desktop.onNavigate(n.key)}
            aria-current={desktop.view === n.key ? "page" : undefined}
            className={topNavCls(desktop.view === n.key)}
          >
            <n.icon className="size-4" />
            {n.label}
          </button>
        ))}
      </nav>

      {/* Status row — stays visible during desktop panes (spec: compact run state must remain). No run →
          it only carries the conn dot; keep it mounted only when auth chrome (role/sign out) needs a home. */}
      {view ? (
        <>
          <StatusBar view={view} conn={conn} onTogglePause={control(view.paused ? "resume" : "pause", "pause/resume")} crumbs={crumbs} />
          <HandoffBar
            handoffs={view.handoffs}
            onResolve={(hid) => ctl("resolve handoff", postControl(`/api/assessments/${view.id}/handoffs/${hid}/resolve`))}
          />
        </>
      ) : id || authEnabled ? (
        <StatusBarShell crumbs={crumbs} conn={id ? conn : undefined} />
      ) : null}

      {/* Working area: [Site Tree | tabs + content]. A desktop pane covers this whole row; the assessment
          DOM stays mounted-but-hidden so selected tab/screen, tree expansion, and unsaved drafts persist. */}
      <div className="relative min-h-0 flex-1">
        <div className={desktopNode ? "hidden" : "flex h-full min-h-0"}>
          {view ? (
            <ResizablePanelGroup
              orientation="horizontal"
              className="h-full"
              defaultLayout={defaultLayout}
              onLayoutChanged={onLayoutChanged}
            >
              {/* SITE TREE — dedicated left pane, independently scrollable, full height under the status row. */}
              <ResizablePanel id="site-tree" defaultSize="280px" minSize="180px" maxSize="520px" className="h-full">
                <aside className="flex h-full flex-col border-r border-border bg-muted/40">
                  <SiteTree
                    tree={view.tree}
                    selected={selectedScreen?.screenId ?? null}
                    onSelect={onSelect}
                    onExclude={(ids) => ctl("exclude screens", postControlBody(`/api/assessments/${view.id}/exclude-screens`, { screenIds: ids }))}
                  />
                </aside>
              </ResizablePanel>
              <ResizableHandle />
              <ResizablePanel id="content" minSize="30%" className="h-full">
                <div className="flex h-full min-w-0 flex-col">
                  <Progress view={view} />
                  {/* View switcher — horizontal tabs, scrollable so every entry stays reachable at narrow widths. */}
                  <nav className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-border px-2 py-1.5" aria-label="Assessment views">
                    {TABS.map((t) => {
                      const badge = t.key === "sessions" ? awaitingSessions : t.count?.(view);
                      const danger = t.key === "sessions" && awaitingSessions > 0;
                      return (
                        <button
                          key={t.key}
                          type="button"
                          onClick={() => navTo(t.key)}
                          aria-current={tab === t.key ? "page" : undefined}
                          className={tabCls(tab === t.key, danger)}
                        >
                          <t.icon className="size-3.5" />
                          {t.label}
                          {badge != null && badge > 0 ? (
                            <Badge variant="secondary" className={danger ? "bg-destructive/15 text-destructive" : ""}>{badge}</Badge>
                          ) : null}
                        </button>
                      );
                    })}
                  </nav>
                  <main className="min-h-0 flex-1 overflow-auto p-4 pb-12">
                    {tab === "screen" ? (
                      <ScreenView
                        view={view}
                        screen={selectedScreen}
                        onExclude={(sid) => ctl("exclude screen", postControl(`/api/assessments/${view.id}/screens/${sid}/exclude`))}
                      />
                    ) : null}
                    {tab === "findings" ? <Findings view={view} onJump={onSelect} /> : null}
                    {tab === "scenarios" ? <Scenarios view={view} onJump={onSelect} /> : null}
                    {tab === "apis" ? <ApiList view={view} onJump={onSelect} /> : null}
                    {tab === "js" ? <JsAssets view={view} /> : null}
                    {tab === "log" ? <Log events={view.events} /> : null}
                    {tab === "sessions" ? <Sessions id={view.id} /> : null}
                    {tab === "live" ? <LiveView id={view.id} /> : null}
                    {tab === "ask" ? <Chat id={view.id} /> : null}
                    {tab === "control" ? <Control view={view} /> : null}
                  </main>
                </div>
              </ResizablePanel>
            </ResizablePanelGroup>
          ) : (
            <main className="min-h-0 flex-1 overflow-auto">
              {!id ? (
                <Index />
              ) : (
                <p className="p-8 text-muted-foreground">Connecting to {id} … ({conn})</p>
              )}
            </main>
          )}
        </div>
        {desktopNode ? <div className="absolute inset-0 z-10 flex flex-col bg-background">{desktopNode}</div> : null}
      </div>
      {notice ? (
        <div className="fixed right-4 bottom-4 z-50 max-w-[420px] rounded-lg border border-destructive bg-destructive/20 px-4 py-2 shadow-lg" role="alert">
          {notice}
        </div>
      ) : null}
    </div>
  );
}
