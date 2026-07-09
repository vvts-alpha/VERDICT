import { useEffect, useState } from "react";
import { postControl, postControlBody, useAssessmentId, useStateView } from "./api";
import { StatusBar } from "./components/StatusBar";
import { HandoffBar } from "./components/HandoffBar";
import { Progress } from "./components/Progress";
import { SiteTree } from "./components/SiteTree";
import { Findings } from "./components/Findings";
import { ScreenView } from "./components/ScreenView";
import { ApiList } from "./components/ApiList";
import { Log } from "./components/Log";
import { Scenarios } from "./components/Scenarios";
import { Index } from "./components/Index";
import { Sessions } from "./components/Sessions";
import { Chat } from "./components/Chat";
import { AssetTree } from "./components/AssetTree";

type Tab = "screen" | "findings" | "scenarios" | "log" | "apis" | "sessions" | "ask";

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

  // An ASR (Attack Surface Recon) run has its OWN asset view — not the web-assessment tabbed layout. Detect it
  // (its asset_inventory has assets) and render a standalone page; the web-assessment viewer below stays untouched.
  const [isAsr, setIsAsr] = useState<boolean | null>(null);
  useEffect(() => {
    if (!id) return;
    let alive = true;
    fetch(`/api/assessments/${encodeURIComponent(id)}/assets`)
      .then((r) => {
        if (alive) setIsAsr(r.ok); // 200 = an asset_inventory exists = an ASR run (even mid-scan); 404 = web/API run
      })
      .catch(() => {
        if (alive) setIsAsr(false);
      });
    return () => {
      alive = false;
    };
  }, [id]);

  if (!id) {
    return <Index />;
  }
  if (isAsr) {
    // ASR has its OWN full-height viewer (not the web-viewer's .body grid / .scroll / .tabbody, which would cram
    // the asset tree into the 300px SiteTree column). .page is a flex column at 100vh; AssetTree fills the rest.
    return (
      <div className="page">
        <div style={{ display: "flex", alignItems: "center", gap: 12, padding: "9px 14px", borderBottom: "1px solid var(--line)", flex: "0 0 auto" }}>
          <a href="/" style={{ color: "var(--muted)", textDecoration: "none", fontSize: 13 }}>← projects</a>
          <span style={{ fontWeight: 700, color: "#fff" }}>Attack Surface Recon</span>
          <span style={{ color: "var(--muted)", fontSize: 12, fontFamily: "ui-monospace, monospace" }}>{id}</span>
        </div>
        <div style={{ flex: 1, minHeight: 0 }}>
          <AssetTree id={id} />
        </div>
      </div>
    );
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
              🧩 Scenarios
            </button>
            <button type="button" className={tab === "apis" ? "active" : ""} onClick={() => setTab("apis")}>
              APIs
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
              🖥 Sessions{awaitingSessions > 0 ? ` 🔴 ${awaitingSessions}` : ""}
            </button>
            <button type="button" className={tab === "ask" ? "active" : ""} onClick={() => setTab("ask")}>
              💬 Ask
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
            {tab === "log" ? <Log events={view.events} /> : null}
            {tab === "sessions" ? <Sessions id={view.id} /> : null}
            {tab === "ask" ? <Chat id={view.id} /> : null}
          </div>
        </main>
      </div>
    </div>
  );
}
