// "+ New" → choose an assessment mode (Web / API), then render the mode-specific form.
// (The autonomous LLM/AI-assistant red-team lives in the CLI — `veritas redteam` — and is intentionally not
//  surfaced here; VERDICT's WebUI is the autonomous web/API pentest surface. The operator-assisted LLM tool is
//  a separate project.)
import { useState, type ReactNode } from "react";
import { ArrowLeft } from "lucide-react";
import { NewAssessment, type LaunchInput } from "./NewAssessment";
import { Button } from "./ui/button";

type Mode = "web";

// Lucide-style single-color outline icons — stroke = currentColor, sized/colored by the mode button.
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
    <button type="button" className="flex min-h-36 flex-col items-start gap-3 rounded-xl border border-border bg-card p-5 text-left transition-colors hover:border-primary hover:bg-muted focus-visible:ring-2 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50" onClick={onClick} disabled={disabled}>
      <span className="text-primary [&_svg]:size-8">{icon}</span>
      <span className="text-sm font-semibold">{title}</span>
      <span className="text-xs text-muted-foreground">{desc}</span>
    </button>
  );
}

export function NewLauncher({ onCancel, initial }: { onCancel: () => void; initial?: LaunchInput }) {
  // A duplicate skips the mode picker — the run's own command/spec decides which form opens.
  const [mode, setMode] = useState<Mode | null>(initial ? "web" : null);
  const back = (): void => setMode(null);

  if (mode === "web") return <NewAssessment onCancel={initial ? onCancel : back} apiSpec={!!initial?.spec} initial={initial} />;

  return (
    <div className="space-y-5 pb-10">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h2 className="text-base font-semibold">New assessment</h2>
        <Button type="button" variant="ghost" onClick={onCancel}><ArrowLeft /> Cancel</Button>
      </div>
      <p className="text-xs text-muted-foreground">What are you assessing?</p>
      <div className="grid grid-cols-[repeat(auto-fit,minmax(190px,1fr))] gap-3">
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
