// New ASR (Attack Surface Recon) run → POST /api/run { command: "asr" } → navigate to the run's asset viewer.
// ASR is its own assessment type (a domain's hosts, not screens/findings), with its own launch form + viewer.
// Uses the shared form design system (.nf-field / .nf-checks / .nf-launch) so it matches the web/API forms.
import { useState } from "react";

export function NewAsr({ onCancel }: { onCancel: () => void }) {
  const [domain, setDomain] = useState("");
  const [outOfScope, setOutOfScope] = useState("");
  const [maxHosts, setMaxHosts] = useState("200");
  const [screenshot, setScreenshot] = useState(false);
  const [paths, setPaths] = useState(false);
  const [triage, setTriage] = useState(false);
  const [brute, setBrute] = useState(false);
  const [passiveTools, setPassiveTools] = useState(true);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const launch = async (): Promise<void> => {
    const d = domain.trim();
    if (!d) {
      setErr("domain is required — e.g. *.example.com");
      return;
    }
    const apex = d.replace(/^\*\./, "").replace(/\.$/, "");
    setBusy(true);
    setErr(null);
    const options: Record<string, unknown> = { domain: d, screenshot, paths, triage, brute };
    if (!passiveTools) options.noTools = true; // skip subfinder (e.g. when its feeds are unreachable → it just hangs)
    if (outOfScope.trim()) options.outOfScope = outOfScope.trim();
    if (maxHosts.trim()) options.maxHosts = Number.parseInt(maxHosts, 10);
    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command: "asr", manifest: { target: `https://${apex}` }, options }),
      });
      const data = (await res.json()) as { id?: string; error?: string };
      if (!res.ok || !data.id) {
        setErr(data.error ?? `launch failed (${res.status})`);
        setBusy(false);
        return;
      }
      window.location.search = `?id=${encodeURIComponent(data.id)}`;
    } catch {
      setErr("launch failed");
      setBusy(false);
    }
  };

  return (
    <div className="newform">
      <div className="nf-row nf-head">
        <h2>Attack Surface Recon</h2>
        <button type="button" className="nf-cancel" onClick={onCancel}>
          ← Back
        </button>
      </div>
      <p className="mode-prompt">Map a domain's hosts (crt.sh + subfinder + optional active brute → DNS → liveness), flag recon findings, then score &amp; triage attack targets.</p>

      <label className="nf-field">
        <span>Domain — wildcard or apex</span>
        <input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="*.example.com" autoFocus />
      </label>
      <label className="nf-field">
        <span>Out of scope — comma-separated carve-outs</span>
        <input value={outOfScope} onChange={(e) => setOutOfScope(e.target.value)} placeholder="blog.example.com, thirdparty.example.com" />
      </label>
      <label className="nf-field nf-inline">
        <span>Max hosts</span>
        <input value={maxHosts} onChange={(e) => setMaxHosts(e.target.value)} inputMode="numeric" />
      </label>

      <div className="nf-checks">
        <label title="Passive OSINT via subfinder (auto if installed). Uncheck if its feeds are unreachable (it would just hang for ~45s).">
          <input type="checkbox" checked={passiveTools} onChange={(e) => setPassiveTools(e.target.checked)} /> passive tools
        </label>
        <label title="ACTIVE DNS brute of a bundled ~130-word subdomain list (dnsx if installed, else native node:dns). The reliable path when crt.sh/subfinder can't reach the network. Sends DNS queries — opt-in.">
          <input type="checkbox" checked={brute} onChange={(e) => setBrute(e.target.checked)} /> active brute
        </label>
        <label title="capture each live host's homepage">
          <input type="checkbox" checked={screenshot} onChange={(e) => setScreenshot(e.target.checked)} /> screenshot
        </label>
        <label title="probe /.git, /.env, /actuator, swagger… on live hosts (more traffic per host)">
          <input type="checkbox" checked={paths} onChange={(e) => setPaths(e.target.checked)} /> curated paths
        </label>
        <label title="Claude classifies the top-scoring hosts (category + attack angle)">
          <input type="checkbox" checked={triage} onChange={(e) => setTriage(e.target.checked)} /> AI triage
        </label>
      </div>

      {err ? <p className="nf-err">{err}</p> : null}
      <div className="nf-actions">
        <button type="button" className="nf-launch" disabled={busy} onClick={() => void launch()}>
          {busy ? "Launching…" : "▶ Launch ASR"}
        </button>
      </div>
      <p className="mode-prompt" style={{ marginTop: 16 }}>
        Authorized targets only. crt.sh + subfinder are passive OSINT; active brute + liveness / path probes touch DNS / the hosts (scope-gated, rate-limited).
      </p>
    </div>
  );
}
