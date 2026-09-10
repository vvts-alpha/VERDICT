// "+ New" → choose an assessment mode (Web / API), then render the mode-specific form.
// (The autonomous LLM/AI-assistant red-team lives in the CLI — `veritas redteam` — and is intentionally not
//  surfaced here; VERDICT's WebUI is the autonomous web/API pentest surface. The operator-assisted LLM tool is
//  a separate project.)
import { useState, type ReactNode } from "react";
import { NewAssessment } from "./NewAssessment";

type Mode = "web";

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
function BracesIcon() {
  return (
    <svg {...svg}>
      <path d="M8 3H7a2 2 0 0 0-2 2v5a2 2 0 0 1-2 2 2 2 0 0 1 2 2v5c0 1.1.9 2 2 2h1" />
      <path d="M16 21h1a2 2 0 0 0 2-2v-5c0-1.1.9-2 2-2a2 2 0 0 1-2-2V5a2 2 0 0 0-2-2h-1" />
    </svg>
  );
}
function Card({ icon, title, desc, onClick, disabled = false }: { icon: ReactNode; title: string; desc: string; onClick?: () => void; disabled?: boolean }) {
  return (
    <button type="button" className="mode-card" onClick={onClick} disabled={disabled}>
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
          icon={<BracesIcon />}
          title="API spec"
          desc="Coming Soon"
          disabled
        />
      </div>
    </div>
  );
}
