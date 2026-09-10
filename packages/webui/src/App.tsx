import { useEffect, useState } from "react";
import { postControl, postControlBody, useAssessmentId, useStateView } from "./api";
import { StatusBar } from "./components/StatusBar";
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

type Tab = "screen" | "findings" | "scenarios" | "log" | "apis" | "js" | "sessions" | "ask" | "control" | "live";

// DESIGN §8 — left: SITE TREE (nav) + progress bar; right: tabs: Screen / Findings / Diagnostic log / APIs.
export function App() {
  const id = useAssessmentId();
  const { view, conn } = useStateView(id);
  const [selected, setSelected] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("screen");

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

  if (!id) {
    return <Index />;
  }
  if (!view) {
    return <div className="empty">Connecting to {id} … ({conn})</div>;
  }

  const selectedScreen = view.screens.find((s) => s.screenId === selected) ?? view.screens[0];
  const control = (path: string) => () => void postControl(`/api/assessments/${view.id}/${path}`);
  const onSelect = (sid: string): void => {
    setSelected(sid);
    setTab("screen");
  };

  return (
    <div className="page">
      <StatusBar view={view} conn={conn} onTogglePause={control(view.paused ? "resume" : "pause")} />
      <HandoffBar
        handoffs={view.handoffs}
        onResolve={(hid) => void postControl(`/api/assessments/${view.id}/handoffs/${hid}/resolve`)}
      />
      <Progress view={view} />
      <div className="body">
        <SiteTree
          tree={view.tree}
          selected={selectedScreen?.screenId ?? null}
          onSelect={onSelect}
          onExclude={(ids) => void postControlBody(`/api/assessments/${view.id}/exclude-screens`, { screenIds: ids })}
        />
        <main className="scroll">
          <div className="tabs">
            <button type="button" className={tab === "screen" ? "active" : ""} onClick={() => setTab("screen")}>
              Screen
            </button>
            <button type="button" className={tab === "findings" ? "active" : ""} onClick={() => setTab("findings")}>
              Findings ({view.findings.length})
            </button>
            <button type="button" className={tab === "scenarios" ? "active" : ""} onClick={() => setTab("scenarios")}>
              Scenarios
            </button>
            <button type="button" className={tab === "apis" ? "active" : ""} onClick={() => setTab("apis")}>
              APIs
            </button>
            <button type="button" className={tab === "js" ? "active" : ""} onClick={() => setTab("js")}>
              JS ({view.jsAssets.length})
            </button>
            <button type="button" className={tab === "log" ? "active" : ""} onClick={() => setTab("log")}>
              Log ({view.events.length})
            </button>
            <button
              type="button"
              className={`${tab === "sessions" ? "active" : ""}${awaitingSessions > 0 ? " needs-input" : ""}`}
              onClick={() => setTab("sessions")}
              title={awaitingSessions > 0 ? `${awaitingSessions} session(s) waiting for login` : undefined}
            >
              Sessions{awaitingSessions > 0 ? ` (${awaitingSessions})` : ""}
            </button>
            <button type="button" className={tab === "ask" ? "active" : ""} onClick={() => setTab("ask")}>
              Ask
            </button>
            <button type="button" className={tab === "live" ? "active" : ""} onClick={() => setTab("live")}>
              Live
            </button>
            <button type="button" className={tab === "control" ? "active" : ""} onClick={() => setTab("control")}>
              Control
            </button>
          </div>
          <div className="tabbody">
            {tab === "screen" ? (
              <ScreenView
                view={view}
                screen={selectedScreen}
                onExclude={(sid) => void postControl(`/api/assessments/${view.id}/screens/${sid}/exclude`)}
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
          </div>
        </main>
      </div>
    </div>
  );
}
