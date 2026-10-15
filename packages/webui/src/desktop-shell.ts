// The Electron desktop shell injects its own top-level views (attended Browser, Settings) into the shared
// top nav through this context. In a plain browser the context is absent and nothing desktop renders.
import { createContext, useContext } from "react";
import type { ReactNode } from "react";
import type { LucideIcon } from "lucide-react";

export interface DesktopShell {
  /** Active desktop view key; "main" = the assessment UI (projects list / run view). */
  view: string;
  /**
   * Ask the shell to switch views. Returns false when a leave-guard vetoes the change
   * (e.g. unsaved Settings edits — the confirm bar stays up). Callers must NOT change
   * their own selection state when it returns false.
   */
  onNavigate: (view: string) => boolean;
  /**
   * Run an arbitrary action through the active view's leave-guard. Returns false when vetoed;
   * the action is then stored and executed once the user confirms the discard — so "discard →
   * continue to the originally chosen destination" holds even for non-view actions (links).
   */
  runGuarded: (fn: () => void) => boolean;
  /** Top-nav entries (Browser / Settings — "main" is covered by Projects). */
  nav: { key: string; label: string; icon: LucideIcon }[];
  /** Content node per non-"main" view key. Mounted only while the view is active. */
  views: Record<string, ReactNode>;
}

export const DesktopShellContext = createContext<DesktopShell | null>(null);

export function useDesktopShell(): DesktopShell | null {
  return useContext(DesktopShellContext);
}
