// 💬 Ask — a read-only Q&A that asks Claude about this assessment (findings/screens/scope).
// POST the conversation history to /api/assessments/:id/chat and show the answer. History is held client-side.
import { useEffect, useRef, useState, type KeyboardEvent } from "react";
import { useRole } from "../api";

interface Msg {
  role: "user" | "assistant";
  content: string;
}

export function Chat({ id }: { id: string }) {
  const { canWrite } = useRole();
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const endRef = useRef<HTMLDivElement>(null);

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
      if (!res.ok || !data.answer) setErr(data.error ?? `chat failed (${res.status})`);
      else setMessages((m) => [...m, { role: "assistant", content: data.answer! }]);
    } catch {
      setErr("Can't reach server");
    }
    setBusy(false);
  };

  return (
    <div className="chat">
      <div className="chat-log">
        {messages.length === 0 ? (
          <p className="idxempty">
            Ask about this assessment — findings, risk, coverage, scope.
            <br />
            e.g. “Why is f-001 high?” · “Summarize the auth posture” · “Which screens weren’t tested?”
          </p>
        ) : (
          messages.map((m, i) => (
            <div key={i} className={`chat-msg ${m.role}`}>
              <span className="chat-who">{m.role === "user" ? "You" : "VERDICT"}</span>
              <div className="chat-body">{m.content}</div>
            </div>
          ))
        )}
        {busy ? (
          <div className="chat-msg assistant">
            <span className="chat-who">VERDICT</span>
            <div className="chat-body chat-think">… thinking</div>
          </div>
        ) : null}
        {err ? <p className="nf-err">{err}</p> : null}
        <div ref={endRef} />
      </div>
      {canWrite ? (
        <div className="chat-input">
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={(e: KeyboardEvent<HTMLTextAreaElement>) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                void send();
              }
            }}
            placeholder="Ask a question…  (Ctrl/Cmd+Enter to send)"
            rows={2}
          />
          <button type="button" disabled={busy || !input.trim()} onClick={() => void send()}>
            {busy ? "…" : "Send"}
          </button>
        </div>
      ) : (
        <p className="muted" style={{ padding: "8px 12px" }}>
          Ask is read-only for viewers — sign in as operator to use it.
        </p>
      )}
    </div>
  );
}
