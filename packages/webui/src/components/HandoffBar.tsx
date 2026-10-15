import { useEffect, useRef } from "react";
import type { HumanHandoff } from "@veritas/core";
import { useRole } from "../api";
import { Button } from "./ui/button";

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
    <div className="border-b border-warning bg-warning/15">
      {pending.map((h) => (
        <div key={h.id} className="flex items-center gap-3 px-3 py-2">
          <span aria-hidden="true">🔐</span>
          <span className="flex-1 text-warning">
            Needs human [{h.reason}]: <b className="font-mono">{h.url ?? ""}</b> — {h.message}
            {desktop && isBrowserHandoff(h)
              ? " — log in / clear CAPTCHA in the Browser tab, then Capture session → Logged in → continue."
              : ""}
          </span>
          {canWrite && desktop && isBrowserHandoff(h) ? (
            <Button type="button" size="sm" onClick={() => openInBrowser(h.url, h.id)} title="Open this URL in the in-app Browser tab">Open in Browser</Button>
          ) : null}
          {/* One "continue" verb per flow: when the attended browser is the path, its own
              "Logged in → continue" injects the captured session AND resolves — the bar's
              resolve-only action must not look the same. On the web there is no attended
              browser, so the resolve button stays the primary continue. */}
          {canWrite ? (
            desktop && isBrowserHandoff(h) ? (
              <Button type="button" variant="outline" size="sm" onClick={() => onResolve(h.id)} title="Resolve without capturing/applying a session">Resolve without session</Button>
            ) : (
              <Button type="button" size="sm" onClick={() => onResolve(h.id)}>Logged in → continue</Button>
            )
          ) : null}
        </div>
      ))}
    </div>
  );
}
