# WebUI conventions

**Canonical reference: the web/API assessment viewer** (`App.tsx`, `StatusBar.tsx`, `Progress.tsx`, `Log.tsx`, and `Index.tsx`). Reuse its shared components and shadcn/ui primitives for the sidebar, header, progress, logs, exports, and project rows. Theme tokens live in `packages/webui/src/styles.css`; desktop uses the same stylesheet plus platform-only `desktop.css`.

Read these rules before building a view and verify the finished UI against the checklist below.

---

## Rule 0 — reuse, don't reimplement

- Shared header/export/report/role/log **live in `StatusBar.tsx` and `Log.tsx`**. Import them. If you catch
  yourself writing a second assessment `<header>` or Export menu, stop — extract or reuse instead.
- Anything header-common (a new breadcrumb behaviour, a new trailing control) goes into `StatusBarShell`
  **once**, so both viewers get it. Never patch one header and not the other. Run metrics (phase, screens,
  tokens…) belong to `RunStats` (`StatusBar.tsx`), not the header.
- `webui` imports from `@veritas/core` **types-only** (it's bundled by Vite, not Node). Contract types live only
  in core — never redeclare `Screen`/`Finding`/`Phase` in `webui`.

## The shared vocabulary of parts

| Part | Component / markup | Rule |
|---|---|---|
| Header | `StatusBarShell` (`StatusBar.tsx`) | Every assessment view renders through it. Slots below. |
| Top nav | `App.tsx` `<nav aria-label="Main">` | Brand (web only — the desktop title bar carries it) · Projects · desktop entries (Electron: Browser/Settings via `DesktopShellContext.nav`). A single horizontal strip above the status row. |
| Site Tree pane | `App.tsx` `<aside>` inside `ResizablePanel` | The left pane is the site tree and nothing else — it runs from under the status row to the window bottom and scrolls independently. Width is user-resizable via `ResizableHandle` (keyboard arrows work; double-click resets; persists in localStorage; default ≈280px). Rows carry a full-path `title` so truncated deep paths are always inspectable; badges use `shrink-0` so they never crush the label. |
| Desktop views | `DesktopShellContext` (`desktop-shell.ts`) | Electron publishes Browser/Settings via the context. `onNavigate`/`runGuarded` return false when a leave-guard vetoes (unsaved Settings); the vetoed destination is remembered so confirming "Discard" continues to it. Desktop panes overlay the tree+content area while the status row stays — and the assessment DOM stays mounted-but-hidden so tab/screen selection, tree expansion, and unsaved New-form drafts survive (never persist credential drafts to storage). The attended browser's native `WebContentsView` is a WINDOW child, not page DOM — `attended-browser.ts` destroys it on any non-same-document host navigation (reload/redirects included) and actively `webContents.close()`s it; an in-flight `open` is generation-guarded so a racing close can't be lost. |
| Run metrics | `RunStats` (`StatusBar.tsx`) | A compact inline line inside the status row — phase · tested · findings · unfinished first, the rest after. No stat cards. |
| Report export | `ReportLinks` (`StatusBar.tsx`) | The Report block (HTML/PDF/Markdown/Findings CSV) is shared. Every Export menu leads with it. |
| Export menu | `DownloadMenu` with shadcn `DropdownMenu` | Labels group report/inventory/import; links remain real GET downloads. |
| Progress | `Progress` | Coloured status segments sum to 100%; muted metadata describes the state. A single-colour generic progress bar cannot replace it. |
| Log | `Log` component | **Newest-first**, capped (see Log rules). |
| View nav | horizontal tab strip in `App.tsx` | `overflow-x-auto` so every entry stays reachable at narrow widths; counts render as a `Badge`; Sessions shows the awaiting-login cue; live views mount only while selected. |
| Project row | `Index.tsx` shadcn `Table` | Target link is keyboard-accessible; type/phase badges, numeric cells, per-type action verb remain. |
| Pills | shadcn `Badge`, `SeverityBadge` | Phase, severity, verdict and connectivity use distinct semantic tokens; map dynamic values to complete Tailwind class names. |
| Forms | shadcn `Button`, `Input`, `Textarea`, `Checkbox`, `NativeSelect` | Keep native form/keyboard semantics; mode cards use Lucide-style outline icons. |
| Role / auth | `useRole()` → `{authEnabled, role, canWrite}` | Rendered by `StatusBarShell` — don't re-derive. |

## Page skeleton (full-page view)

```
full-height flex column
 ├─ top nav                        // brand (web) · Projects · Browser/Settings (Electron)
 ├─ <StatusBarShell …/>            // status row — target · run id · RunStats · actions · export · role · conn
 ├─ [HandoffBar]                   // if the view has handoffs
 └─ row (remaining height)
     ├─ <aside>                    // SITE TREE only — independent scroll, resizable
     └─ column
         ├─ <Progress …/>          // segmented progress + meta
         ├─ tab strip              // view switcher — horizontal, overflow-x-auto
         └─ main (scrollable)      // the selected view's content
   // a desktop pane (Browser/Settings) overlays the row; tree+tabs hide, status row stays
```

## Header (`StatusBarShell`) — fixed slot order

```
{breadcrumbs} · «single flex spacer» · {actions} · {exportMenu} · [role badge] · [sign out] · ● {conn}
```

- **Right-alignment is owned by the single `ml-auto` spacer.** Everything after it
  (actions · export · role · sign out · conn) is the right-hand group. Do **not** add `ml-auto` to individual
  trailing controls — that was the bug that left Export/sign-out mis-aligned.
- **`{crumbs}`** carries the run context — target URL/path + `run <id>` (just `Projects` on the dashboard,
  the view label on a desktop pane). The brand logo lives in the top nav, not here.
- **`{stats}`** is `RunStats` — the run's metrics as a compact inline line: `phase` · `tested x/y` ·
  `findings` · `unfinished` first (the attention-bearing numbers), then screens · excluded · tokens ·
  handoffs. Items are `shrink-0` and the line truncates rather than wraps; each item carries a `title=`
  tooltip. Attention-bearing values (`findings`, `unfinished`, `excluded`, `handoffs`) turn `text-warning`
  when non-zero.
- **`conn`** is `"connecting" | "open" | "closed"` (`ConnState`) — never invent other words. A view without a
  WebSocket (e.g. the dashboard) passes no `conn`.
- A view without a pause/handoff simply passes no `actions` — the spacer still right-aligns the rest.

## Phase vocabulary — the `Phase` enum, nothing else

`Phase = init | phase1_recon | phase1_label | phase2_scan | phase2_burpscan | report | done | halted`
(`core/types/phase.ts`).

- **The stat strip's Phase card shows a real `Phase` value.** The **terminal/success phase is `report`** — this is
  what the pilot sets when it finishes (`run.ts`), and what a completed run shows. **Never `done`** for a
  successful run, and never ad-hoc words (`discovering`, `probing`, `scanning`, `complete`) in the phase field.
- Client-side progress must use the stored `Phase` value.
- Descriptive progress text (e.g. "▶ now: /orders", "probing 40/200 hosts") is allowed and is
  separate from the phase field — but keep it descriptive, not a fake phase.

## Export / Report

- **Every Export menu leads with the shared `ReportLinks` block** (Report → HTML · PDF · Markdown · Findings
  CSV), which points at `/api/assessments/<id>/report?format=…`. This works for any run whose findings are in
  the store, so **a view must persist its findings to the store**
  for its Report to be non-empty. A Report link that yields an empty report is a bug, not a feature.
- After the Report block, add view-specific sections (`DropdownMenuLabel` + real links), e.g. "Screen inventory". Reuse `DownloadMenu`; do not duplicate its entries.
- Trigger label: `Export / Import` (Download icon) when the menu offers an import (operator), else `Export`.

## Log

- **Newest-first.** Render `[...items].reverse()` — the current activity is on top. (See `Log.tsx`.)
- **Capped to the most recent 300**, matching the store projection (`core/view.ts` → `events.slice(-300)`).
  A client-side log slices `.slice(-300)` before rendering. Never dump the unbounded history.
- The Log nav item shows the visible count as a badge: `Log {logLines.length}`.

## View navigation (tab strip)

- Views are the horizontal tab strip at the top of the content column in `App.tsx` — plain buttons driving
  a controlled `tab` state, not shadcn `Tabs` triggers. Preserve the selected screen and live WebSocket
  mount/unmount behaviour (inactive views are not rendered, so their streams release).
- The strip is `overflow-x-auto` with `whitespace-nowrap` items — at narrow widths every entry stays
  reachable by scrolling; nothing wraps or disappears.
- Items that have a quantity carry it as a `Badge`: `Findings {n}`, `Log {n}`.
- Only render tabs the view actually has; keep the Sessions waiting-for-login cue (badge + destructive text)
  visible.

## Dashboard (project list, `Index.tsx`)

- One `TableRow` per run: Target (name + sub), type/phase badges, numeric Screens / Findings, Updated, ID, action. The target name is a real focusable link, even when the row also responds to mouse clicks.
- **Findings count = the store's finding count** (`state.findings.length`). A view whose findings live only in a
  side file will read **0 here** — persist to the store so the dashboard is truthful.
- Idle-run action is `Resume` (Play icon); running-run action is `Stop` (Square icon). Unsupported legacy run types are hidden and cannot be resumed.


## Terminology & colour

- **No unexplained jargon** in on-screen chrome. Prefer plain words; if a domain term is unavoidable
  (`live`, `passive`, `CT`), attach a `title=` tooltip. (Removed already: `apex`→`domain`; `AI triage`→`AI
  triage lead` with a "not a confirmed finding" tooltip.)
- **Colour comes from shared theme tokens** in `styles.css`: `bg-background`, `bg-card`, `text-primary`, `text-muted-foreground`, `border-border`, `text-success`, `text-warning`, `text-destructive` etc. Never hardcode a hex accent. Severity is semantic and separate from the accent. Existing root tokens are bridged through `@theme inline`; do not use `--muted` as a shadcn surface or `--accent` as a shadcn hover background.
- Tailwind scans literal class names. Map phase/severity/status to complete static class names rather than interpolating `bg-${value}`.
- **Icons**: `lucide-react` outline icons (`stroke="currentColor"`), sized via utilities. No decorative/AI emoji (🤖 etc.).
- Prefer shared shadcn primitives and Tailwind utilities to one-off component CSS. `desktop.css` is for `-webkit-app-region` only; the attended browser's isolated start page is a separate HTML document.

## Data & polling

- Poll assessment data on a `window.setInterval` (3–4 s) inside a `useEffect` with an `alive` guard and
  `clearInterval` cleanup (see `Index`, `App`). Don't hand-roll a different cadence.
- URL carries the run: `?id=<id>` (`useAssessmentId`). No id → the project list (`Index`).

## Verification — before you say a view is done

The mistakes this doc prevents were all "claimed matching without checking". So the last step is not optional:

1. `pnpm --filter @veritas/webui build` and `pnpm --filter @veritas/desktop build` — both must build. Typecheck both renderers.
2. **Serve it and look.** Screenshot the WebUI and desktop view; open the Export menu; read the header text back. Diff each
   element against the checklist below. "I changed the code" is not "I verified the output".
3. If it renders blank, capture `console`/`pageerror` — a runtime throw (e.g. a required field your data omits)
   reads identically to a layout bug until you look at the console.

### Conformance checklist

- [ ] Assessment view renders through `StatusBarShell`; trailing controls right-aligned by one flex spacer.
- [ ] `RunStats` leads with phase/tested/findings/unfinished; phase is a `Phase` enum value; terminal run shows `report`, not `done`.
- [ ] Every metric is self-explanatory or tooltipped.
- [ ] Export leads with the shared `ReportLinks`; Report actually renders (findings are in the store).
- [ ] Log is newest-first and capped at 300; the tab badge shows the count.
- [ ] Tab strip carries quantity badges; all tabs reachable at 900px; live views release their streams when not selected.
- [ ] Site Tree is a dedicated left pane (resizable, persisted); rows expose the full path via `title`; desktop panes leave it mounted-but-hidden.
- [ ] Colours are semantic tokens; no hardcoded accent; icons are outline, no new decorative emoji.
- [ ] Site tree arrows/Enter/Space and single Tab stop, chat Ctrl/Cmd+Enter, Sessions canvas key forwarding, and desktop Settings unsaved-close guard still work.
- [ ] Dashboard row shows a truthful findings count (findings persisted to the store).
- [ ] Built, served, screenshotted, and diffed against this list.

---
