import type { HumanHandoff } from "@veritas/core";
import { useRole } from "../api";

// DESIGN §6.3 / §8.3 — 人間ハンドオフ通知。人間が生ブラウザでログイン完了後「続行」を押す。
export function HandoffBar({ handoffs, onResolve }: { handoffs: HumanHandoff[]; onResolve: (id: string) => void }) {
  const { canWrite } = useRole();
  const pending = handoffs.filter((h) => h.status === "pending");
  if (pending.length === 0) return null;
  return (
    <div className="handoffs">
      {pending.map((h) => (
        <div key={h.id} className="handoff">
          <span className="hicon">🔐</span>
          <span className="htext">
            Needs human [{h.reason}]: <b className="mono">{h.url ?? ""}</b> — {h.message}
          </span>
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
