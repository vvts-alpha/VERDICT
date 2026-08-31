import { useEffect, useRef } from "react";
import type { HumanHandoff } from "@veritas/core";
import { useRole } from "../api";

const SHOW_BROWSER = "verdict-show-browser";

function isDesktop(): boolean {
  return typeof window !== "undefined" && !!(window as unknown as { verdictDesktop?: unknown }).verdictDesktop;
}

function openInBrowser(url: string, handoffId: string): void {
  window.dispatchEvent(new CustomEvent(SHOW_BROWSER, { detail: { url, handoffId } }));
}

function isBrowserHandoff(h: HumanHandoff): h is HumanHandoff & { url: string } {
  return (h.reason === "captcha" || h.reason === "auth") && !!h.url;
}

// DESIGN §6.3 / §8.3 — human handoff notice. After the human finishes logging in via the live browser, they press "continue".
// In the desktop app, captcha/auth walls auto-open the in-app Browser tab (real Chromium, no Playwright fingerprint).
export function HandoffBar({ handoffs, onResolve }: { handoffs: HumanHandoff[]; onResolve: (id: string) => void }) {
  const { canWrite } = useRole();
  const pending = handoffs.filter((h) => h.status === "pending");
  const opened = useRef(new Set<string>());

  useEffect(() => {
    const pendingIds = new Set(pending.map((h) => h.id));
    for (const id of [...opened.current]) {
      if (!pendingIds.has(id)) opened.current.delete(id);
    }
    if (!isDesktop() || !canWrite) return;
    const first = pending.find(isBrowserHandoff);
    if (!first?.url || opened.current.has(first.id)) return;
    opened.current.add(first.id);
    openInBrowser(first.url, first.id);
  }, [pending, canWrite]);

  if (pending.length === 0) return null;
  const desktop = isDesktop();
  return (
    <div className="handoffs">
      {pending.map((h) => (
        <div key={h.id} className="handoff">
          <span className="hicon">🔐</span>
          <span className="htext">
            Needs human [{h.reason}]: <b className="mono">{h.url ?? ""}</b> — {h.message}
            {desktop && isBrowserHandoff(h)
              ? " — log in / clear CAPTCHA in the Browser tab, then Capture session → Logged in → continue."
              : ""}
          </span>
          {canWrite && desktop && isBrowserHandoff(h) ? (
            <button type="button" onClick={() => openInBrowser(h.url, h.id)} title="Open this URL in the in-app Browser tab">
              Open in Browser
            </button>
          ) : null}
          {canWrite ? (
            <button type="button" onClick={() => onResolve(h.id)}>
              Logged in → continue
            </button>
          ) : null}
        </div>
      ))}
    </div>
  );
}
