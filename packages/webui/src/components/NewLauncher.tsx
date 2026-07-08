// "+ New" → choose an assessment mode (Web / LLM / API), then render the mode-specific form.
import { useState, type ReactNode } from "react";
import { NewAssessment } from "./NewAssessment";
import { RedteamForm } from "./RedteamForm";

type Mode = "web" | "llm" | "api";

// Lucide-style single-color outline icons — stroke = currentColor, sized/colored via CSS (.mode-ic).
const svg = {
  viewBox: "0 0 24 24",
  fill: "none",
  stroke: "currentColor",
  strokeWidth: 1.75,
  strokeLinecap: "round",
  strokeLinejoin: "round",
} as const;

function GlobeIcon() {
  return (
    <svg {...svg}>
      <circle cx="12" cy="12" r="10" />
      <path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20" />
      <path d="M2 12h20" />
    </svg>
  );
}
function BotIcon() {
  return (
    <svg {...svg}>
      <path d="M12 8V4H8" />
      <rect width="16" height="12" x="4" y="8" rx="2" />
      <path d="M2 14h2" />
      <path d="M20 14h2" />
      <path d="M15 13v2" />
      <path d="M9 13v2" />
    </svg>
  );
}
function BracesIcon() {
  return (
    <svg {...svg}>
      <path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1" />
      <path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1" />
    </svg>
  );
}

function Card({ icon, title, desc, onClick }: { icon: ReactNode; title: string; desc: string; onClick: () => void }) {
  return (
    <button type="button" className="mode-card" onClick={onClick}>
      <span className="mode-ic">{icon}</span>
      <span className="mode-t">{title}</span>
      <span className="mode-d">{desc}</span>
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
        <pre className="mode-cli">
          {"veritas spec-import --spec <openapi.json> --url <base-url>\nveritas scan --id <id>  &&  veritas logic --id <id>  &&  veritas report --id <id>"}
        </pre>
        <p className="mode-prompt">A WebUI form for this is next on the roadmap.</p>
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
      <p className="mode-prompt">What are you assessing?</p>
      <div className="mode-grid">
        <Card
          icon={<GlobeIcon />}
          title="Web / API app"
          desc="Autonomous recon → diagnosis of a web app from one URL."
          onClick={() => setMode("web")}
        />
        <Card
          icon={<BotIcon />}
          title="AI assistant"
          desc="Red-team a deployed chatbot: confirm canary leaks with evidence."
          onClick={() => setMode("llm")}
        />
        <Card
          icon={<BracesIcon />}
          title="API spec"
          desc="Import an OpenAPI / Swagger spec to drive an API assessment."
          onClick={() => setMode("api")}
        />
      </div>
    </div>
  );
}
