// "+ New" → choose an assessment mode (Web / LLM / API), then render the mode-specific form.
import { useState, type CSSProperties } from "react";
import { NewAssessment } from "./NewAssessment";
import { RedteamForm } from "./RedteamForm";

type Mode = "web" | "llm" | "api";

const cardStyle: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: 6,
  padding: "18px 16px",
  textAlign: "left",
  cursor: "pointer",
  border: "1px solid var(--border, #333)",
  borderRadius: 10,
  background: "transparent",
  color: "inherit",
  font: "inherit",
  width: "100%",
};

function Card({ emoji, title, desc, onClick }: { emoji: string; title: string; desc: string; onClick: () => void }) {
  return (
    <button type="button" style={cardStyle} onClick={onClick}>
      <span style={{ fontSize: 24 }}>{emoji}</span>
      <span style={{ fontWeight: 600, fontSize: 15 }}>{title}</span>
      <span style={{ opacity: 0.7, fontSize: 13, lineHeight: 1.4 }}>{desc}</span>
    </button>
  );
}

export function NewLauncher({ onCancel }: { onCancel: () => void }) {
  const [mode, setMode] = useState<Mode | null>(null);
  const back = (): void => setMode(null);

  if (mode === "web") return <NewAssessment onCancel={back} />;
  if (mode === "llm") return <RedteamForm onCancel={back} />;
  if (mode === "api") {
    return (
      <div className="newform">
        <div className="nf-row nf-head">
          <h2>API spec assessment</h2>
          <button type="button" className="nf-cancel" onClick={back}>
            ← Back
          </button>
        </div>
        <p>Import an OpenAPI / Swagger spec to seed an API assessment. Available via the CLI for now:</p>
        <pre style={{ padding: 12, borderRadius: 8, background: "rgba(127,127,127,0.12)", overflowX: "auto", fontSize: 13 }}>
          {"veritas spec-import --spec <openapi.json> --url <base-url>\nveritas scan --id <id>  &&  veritas logic --id <id>  &&  veritas report --id <id>"}
        </pre>
        <p style={{ opacity: 0.7 }}>A WebUI form for this is next on the roadmap.</p>
      </div>
    );
  }

  return (
    <div className="newform">
      <div className="nf-row nf-head">
        <h2>New assessment</h2>
        <button type="button" className="nf-cancel" onClick={onCancel}>
          ← Cancel
        </button>
      </div>
      <p style={{ opacity: 0.75, marginTop: 0 }}>What are you assessing?</p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12 }}>
        <Card
          emoji="🌐"
          title="Web / API app"
          desc="Autonomous recon → diagnosis of a web app from one URL (pilot / assess)."
          onClick={() => setMode("web")}
        />
        <Card
          emoji="🤖"
          title="AI assistant (LLM)"
          desc="Red-team a deployed chatbot behind login: confirm canary leaks with evidence (redteam)."
          onClick={() => setMode("llm")}
        />
        <Card
          emoji="🧩"
          title="API spec"
          desc="Import an OpenAPI / Swagger spec to drive an API assessment."
          onClick={() => setMode("api")}
        />
      </div>
    </div>
  );
}
