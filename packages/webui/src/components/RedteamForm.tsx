// LLM / AI-assistant red-team form → POST /api/run (command "redteam") → navigate to the launched run.
// The canary must be planted out-of-band by the operator in the assistant's system prompt / custom instructions.
import { useState } from "react";

export function RedteamForm({ onCancel }: { onCancel: () => void }) {
  const [chatUrl, setChatUrl] = useState("");
  const [canary, setCanary] = useState("");
  const [headed, setHeaded] = useState(true); // headed by default: the operator may need to log in / watch the chat
  const [maxReplays, setMaxReplays] = useState("");
  const [composer, setComposer] = useState("");
  const [send, setSend] = useState("");
  const [newChat, setNewChat] = useState("");
  const [fileInput, setFileInput] = useState("");
  const [transcript, setTranscript] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  // Client-side high-entropy canary — VERDICT-CANARY-<128-bit hex> (matches the CLI's generateCanary).
  const genCanary = (): void => {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    setCanary(`VERDICT-CANARY-${hex}`);
  };

  const submit = async (): Promise<void> => {
    if (!chatUrl.trim()) {
      setErr("Chat UI URL is required");
      return;
    }
    try {
      const u = new URL(chatUrl.trim());
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error();
    } catch {
      setErr(`Chat URL must start with http:// or https:// (e.g. https://${chatUrl.trim()})`);
      return;
    }
    if (!canary.trim()) {
      setErr("A canary is required — plant it out-of-band in the assistant's system prompt / custom instructions, then paste it here (or Generate one and seed it).");
      return;
    }
    setErr(null);
    setBusy(true);

    const assistant: Record<string, string> = { chatUrl: chatUrl.trim(), canary: canary.trim() };
    if (composer.trim()) assistant.composerSelector = composer.trim();
    if (send.trim()) assistant.sendSelector = send.trim();
    if (newChat.trim()) assistant.newChatSelector = newChat.trim();
    if (fileInput.trim()) assistant.fileInputSelector = fileInput.trim();
    if (transcript.trim()) assistant.transcriptSelector = transcript.trim();

    const manifest: Record<string, unknown> = { target: chatUrl.trim(), assistant };
    const options: Record<string, unknown> = {};
    if (headed) options.headed = true;
    if (maxReplays.trim()) options.maxReplays = Number.parseInt(maxReplays, 10);

    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command: "redteam", manifest, options }),
      });
      const data = (await res.json()) as { id?: string; error?: string };
      if (!res.ok || !data.id) {
        setErr(data.error ?? `launch failed (${res.status})`);
        setBusy(false);
        return;
      }
      window.location.search = `?id=${encodeURIComponent(data.id)}`;
    } catch {
      setErr("Can't reach server");
      setBusy(false);
    }
  };

  return (
    <div className="newform">
      <div className="nf-row nf-head">
        <h2>AI assistant red-team</h2>
        <button type="button" className="nf-cancel" onClick={onCancel}>
          ← Back
        </button>
      </div>

      <label className="nf-field">
        <span>Chat UI URL *</span>
        <input value={chatUrl} onChange={(e) => setChatUrl(e.target.value)} placeholder="https://your-bot.example/chat" />
      </label>

      <label className="nf-field nf-wide">
        <span>Canary * — plant this in the assistant's system prompt / custom instructions first, then paste it here</span>
        <div style={{ display: "flex", gap: 8 }}>
          <input value={canary} onChange={(e) => setCanary(e.target.value)} placeholder="VERDICT-CANARY-…" style={{ flex: 1 }} />
          <button type="button" onClick={genCanary}>
            generate
          </button>
        </div>
      </label>

      <div className="nf-checks">
        <label>
          <input type="checkbox" checked={headed} onChange={(e) => setHeaded(e.target.checked)} /> headed (watch the chat / log in manually)
        </label>
        <label className="nf-field nf-inline">
          <span>max replays</span>
          <input value={maxReplays} onChange={(e) => setMaxReplays(e.target.value)} placeholder="2" inputMode="numeric" />
        </label>
      </div>

      <details className="nf-section">
        <summary>Selectors (optional — override the adapter's auto-discovery when it misfires)</summary>
        <div className="nf-grid">
          <label className="nf-field">
            <span>Composer</span>
            <input value={composer} onChange={(e) => setComposer(e.target.value)} placeholder="textarea" />
          </label>
          <label className="nf-field">
            <span>Send button</span>
            <input value={send} onChange={(e) => setSend(e.target.value)} placeholder="button[type='submit']" />
          </label>
          <label className="nf-field">
            <span>New chat</span>
            <input value={newChat} onChange={(e) => setNewChat(e.target.value)} placeholder="[data-testid*='new-chat' i]" />
          </label>
          <label className="nf-field">
            <span>File input</span>
            <input value={fileInput} onChange={(e) => setFileInput(e.target.value)} placeholder="input[type='file']" />
          </label>
          <label className="nf-field">
            <span>Transcript container</span>
            <input value={transcript} onChange={(e) => setTranscript(e.target.value)} placeholder="[role='log']" />
          </label>
        </div>
      </details>

      {err ? <p className="nf-err">{err}</p> : null}
      <div className="nf-row nf-actions">
        <button type="button" className="nf-launch" disabled={busy} onClick={() => void submit()}>
          {busy ? "Launching…" : "▶ Launch redteam"}
        </button>
      </div>
    </div>
  );
}
