// 💬 Ask — a read-only Q&A over this assessment (findings/screens/scope). Uses the configured LLM
// (desktop Settings / VERDICT_LLM_*), not a hardcoded Claude CLI spawn.
// POST the conversation to /api/assessments/:id/chat and show the answer. History is persisted server-side
// (runs/<id>/chat.json) and loaded on mount, so past exchanges survive a reload.
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useRole } from "../api";
import { useT } from "../i18n";
import { Button } from "./ui/button";
import { Textarea } from "./ui/textarea";

interface Msg {
  role: "user" | "assistant";
  content: string;
}

export function Chat({ id }: { id: string }) {
  const { canWrite } = useRole();
  const t = useT();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

  // Load the persisted conversation on mount (survives reload).
  useEffect(() => {
    let alive = true;
    fetch(`/api/assessments/${encodeURIComponent(id)}/chat`)
      .then((r) => r.json())
      .then((d: { messages?: Msg[] }) => {
        if (alive && Array.isArray(d.messages)) setMessages(d.messages);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [id]);

  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, busy]);

  const send = async (): Promise<void> => {
    const q = input.trim();
    if (!q || busy) return;
    const next: Msg[] = [...messages, { role: "user", content: q }];
    setMessages(next);
    setInput("");
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch(`/api/assessments/${encodeURIComponent(id)}/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ messages: next }),
      });
      const data = (await res.json()) as { answer?: string; error?: string };
      if (!res.ok || !data.answer) setErr(data.error ?? t("chat failed ({status})", { status: res.status }));
      else setMessages((m) => [...m, { role: "assistant", content: data.answer! }]);
    } catch {
      setErr(t("Can't reach server"));
    }
    setBusy(false);
  };

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-1 flex-col gap-3 overflow-y-auto p-1">
        {messages.length === 0 ? (
          <p className="p-4 text-muted-foreground">
            {t("Ask about this assessment — findings, risk, coverage, scope.")}
            <br />
            {t("e.g. “Why is f-001 high?” · “Summarize the auth posture” · “Which screens weren’t tested?”")}
          </p>
        ) : (
          messages.map((m, i) => (
            <div key={i} className={`flex max-w-[80%] flex-col gap-1 ${m.role === "user" ? "self-end items-end" : "self-start"}`}>
              <span className="text-[10px] uppercase tracking-wide text-muted-foreground">{m.role === "user" ? t("You") : "VERDICT"}</span>
              <div className={`break-words whitespace-pre-wrap rounded-lg px-3 py-2 ${m.role === "user" ? "bg-accent text-accent-foreground" : "border border-border bg-card"}`}>{m.content}</div>
            </div>
          ))
        )}
        {busy ? (
          <div className="flex max-w-[80%] flex-col gap-1 self-start">
            <span className="text-[10px] uppercase tracking-wide text-muted-foreground">VERDICT</span>
            <div className="rounded-lg border border-border bg-card px-3 py-2 text-muted-foreground italic">{t("… thinking")}</div>
          </div>
        ) : null}
        {err ? <p role="alert" className="text-destructive">{err}</p> : null}
        <div ref={endRef} />
      </div>
      {canWrite ? (
        <div className="mt-2 flex gap-2 border-t border-border pt-3">
          <Textarea
            className="min-h-16 flex-1 resize-y bg-inset"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e: KeyboardEvent<HTMLTextAreaElement>) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                void send();
              }
            }}
            placeholder={t("Ask a question…  (Ctrl/Cmd+Enter to send)")}
            rows={2}
          />
          <Button type="button" disabled={busy || !input.trim()} onClick={() => void send()}>{busy ? "…" : t("Send")}</Button>
        </div>
      ) : (
        <p className="px-3 py-2 text-muted-foreground">
          {t("Ask is read-only for viewers — sign in as operator to use it.")}
        </p>
      )}
    </div>
  );
}
