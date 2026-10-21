// LLM / AI-assistant red-team form → POST /api/run (command "redteam") → navigate to the launched run.
// The canary must be planted out-of-band by the operator in the assistant's system prompt / custom instructions.
import { useState } from "react";
import { ArrowLeft, Play } from "lucide-react";
import { Disclosure } from "./Disclosure";
import { useT } from "../i18n";
import { Button } from "./ui/button";
import { Checkbox } from "./ui/checkbox";
import { Input } from "./ui/input";

export function RedteamForm({ onCancel }: { onCancel: () => void }) {
  const t = useT();
  const [chatUrl, setChatUrl] = useState("");
  const [canary, setCanary] = useState("");
  const [attended, setAttended] = useState(false); // open the chat in the WebUI Sessions tab (manual login / watch)
  const [headed, setHeaded] = useState(false);
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
      setErr(t("Chat UI URL is required"));
      return;
    }
    try {
      const u = new URL(chatUrl.trim());
      if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error();
    } catch {
      setErr(t("Chat URL must start with http:// or https:// (e.g. https://{url})", { url: chatUrl.trim() }));
      return;
    }
    if (!canary.trim()) {
      setErr(t("A canary is required — plant it out-of-band in the assistant's system prompt / custom instructions, then paste it here (or Generate one and seed it)."));
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
    if (attended) options.attended = true; // screencast into the Sessions tab (manual login gate before probes)
    else if (headed) options.headed = true;
    if (maxReplays.trim()) options.maxReplays = Number.parseInt(maxReplays, 10);

    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ command: "redteam", manifest, options }),
      });
      const data = (await res.json()) as { id?: string; error?: string };
      if (!res.ok || !data.id) {
        setErr(data.error ?? t("launch failed ({status})", { status: res.status }));
        setBusy(false);
        return;
      }
      window.location.search = `?id=${encodeURIComponent(data.id)}`;
    } catch {
      setErr(t("Can't reach server"));
      setBusy(false);
    }
  };

  return (
    <div className="space-y-3 pb-10">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <h2 className="text-base font-semibold">{t("AI assistant red-team")}</h2>
        <Button type="button" variant="ghost" onClick={onCancel}>
          <ArrowLeft /> {t("Back")}
        </Button>
      </div>

      <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
        <span>{t("Chat UI URL *")}</span>
        <Input value={chatUrl} onChange={(e) => setChatUrl(e.target.value)} placeholder="https://your-bot.example/chat" />
      </label>

      <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
        <span>{t("Canary * — plant this in the assistant's system prompt / custom instructions first, then paste it here")}</span>
        <div className="flex gap-2">
          <Input className="flex-1" value={canary} onChange={(e) => setCanary(e.target.value)} placeholder="VERDICT-CANARY-…" />
          <Button type="button" onClick={genCanary}>
            {t("generate")}
          </Button>
        </div>
      </label>

      <div className="my-3 flex flex-wrap items-center gap-4 [&_label]:inline-flex [&_label]:items-center [&_label]:gap-2">
        <label title={t("screencast the chat into the Sessions tab: log into the chatbot manually, then click Done to start the probes")}>
          <Checkbox checked={attended} onCheckedChange={(checked) => setAttended(checked === true)} /> {t("open in browser (log in / watch in the Sessions tab)")}
        </label>
        <label title={t("open a real browser window on the runner — only useful when running locally with a display")}>
          <Checkbox checked={headed} onCheckedChange={(checked) => setHeaded(checked === true)} /> {t("headed window")}
        </label>
        <label className="flex items-center gap-2 text-xs [&_input]:w-20">
          <span>{t("max replays")}</span>
          <Input value={maxReplays} onChange={(e) => setMaxReplays(e.target.value)} placeholder="2" inputMode="numeric" />
        </label>
      </div>

      <Disclosure title={t("Selectors (optional — override the adapter's auto-discovery when it misfires)")}>
        <div className="grid grid-cols-1 gap-x-4 sm:grid-cols-2">
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>{t("Composer")}</span>
            <Input value={composer} onChange={(e) => setComposer(e.target.value)} placeholder="textarea" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>{t("Send button")}</span>
            <Input value={send} onChange={(e) => setSend(e.target.value)} placeholder="button[type='submit']" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>{t("New chat")}</span>
            <Input value={newChat} onChange={(e) => setNewChat(e.target.value)} placeholder="[data-testid*='new-chat' i]" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>{t("File input")}</span>
            <Input value={fileInput} onChange={(e) => setFileInput(e.target.value)} placeholder="input[type='file']" />
          </label>
          <label className="my-2 flex flex-col gap-1 text-xs [&>span]:text-muted-foreground">
            <span>{t("Transcript container")}</span>
            <Input value={transcript} onChange={(e) => setTranscript(e.target.value)} placeholder="[role='log']" />
          </label>
        </div>
      </Disclosure>

      {err ? <p role="alert" className="text-destructive">{err}</p> : null}
      <div className="mt-5 flex gap-3">
        <Button type="button" disabled={busy} onClick={() => void submit()}>
          {busy ? t("Launching…") : <><Play /> {t("Launch redteam")}</>}
        </Button>
      </div>
    </div>
  );
}
