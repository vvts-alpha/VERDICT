# WebUI conventions

**Canonical reference: the web/API assessment viewer** (`App.tsx` + `StatusBar.tsx` + `Progress.tsx` +
`Log.tsx` + `Index.tsx`). It is the oldest, most-reviewed surface. **Every other view — ASR today, and any
new assessment type or feature tomorrow — conforms to it.** When a new view needs header / progress / log /
export / tabs / a project row, it does **not** reinvent them: it renders the same shared component, or (if the
shape genuinely differs) the same markup + CSS classes so the two are byte-consistent.

This file exists because ASR drifted from the web viewer (different header, invented phase words, out-of-order
log, a different Export with no Report) and each divergence had to be caught by eye, repeatedly. A written,
checkable rulebook turns "does it match?" from a vibe into a diff. **Read this before building any UI; check a
finished view against the checklist at the bottom before saying it's done.**

---

## Rule 0 — reuse, don't reimplement

- Shared header/export/report/role/log **live in `StatusBar.tsx` and `Log.tsx`**. Import them. If you catch
  yourself writing a second `<header>` or a second Export `<details>`, stop — extract or reuse instead.
- Anything header-common (a new metric slot behaviour, a new trailing control) goes into `StatusBarShell`
  **once**, so both viewers get it. Never patch one header and not the other.
- `webui` imports from `@veritas/core` **types-only** (it's bundled by Vite, not Node). Contract types live only
  in core — never redeclare `Screen`/`Finding`/`Asset`/`Phase` in `webui`.

## The shared vocabulary of parts

| Part | Component / markup | Rule |
|---|---|---|
| Header | `StatusBarShell` (`StatusBar.tsx`) | Every full-page view renders through it. Slots below. |
| Report export | `ReportLinks` (`StatusBar.tsx`) | The Report block (HTML/PDF/Markdown/Findings CSV) is shared. Every Export menu leads with it. |
| Export menu | `<details className="dl"><summary>⬇ Export…</summary><div className="dl-menu">…` | `.dl-h` section headers; links/buttons under each. |
| Progress | `.progress > .pbar (.pseg…) + .pmeta.muted` | Coloured segments summing to 100%; one muted meta line. |
| Log | `Log` component / `.log > .logline.lt-<type> > .log-ts + .log-msg` | **Newest-first**, capped (see Log rules). |
| Tabs | `.tabs > button(.active)` + `.tabbody` | Label carries a count: `Findings ({n})`. |
| Project row | `Index.tsx` `.idxtable` | `typepill`, `phasepill`, numeric cells, per-type action verb. |
| Pills | `.typepill.<type>`, `.phasepill.<phase>`, `.bandpill.band-<band>` | Phase pill class = the raw `Phase` value. |
| Forms | `.newform` / `.nf-field` / `.nf-checks` / `.nf-launch` | Mode cards use Lucide-style outline icons (`.mode-ic`). |
| Role / auth | `useRole()` → `{authEnabled, role, canWrite}`; `.rolebadge`, `.logout` | Rendered by `StatusBarShell` / `Index` head — don't re-derive. |

## Page skeleton (full-page view)

```
.page
 ├─ <StatusBarShell …/>            // header — shared chrome
 ├─ [HandoffBar]                   // if the view has handoffs
 ├─ .progress                      // progress bar + meta
 └─ .body
     ├─ <left nav>                 // SiteTree (web) / AssetTree (asr) — a tree, bordered right
     └─ main.scroll
         ├─ .tabs                  // tab buttons with counts
         └─ .tabbody               // active tab content
```

## Header (`StatusBarShell`) — fixed slot order

```
brand logo · [rolebadge] · {metrics} · «sb-spacer» · {actions} · {exportMenu} · [sign out] · ● {conn}
```

- **Right-alignment is owned by the single `.sb-spacer` (`margin-left:auto`).** Everything after it
  (actions · export · sign out · conn) is the right-hand group. Do **not** add `margin-left:auto` to individual
  trailing controls — that was the bug that left Export/sign-out mis-aligned.
- **`{metrics}` always starts with `phase: <b>{phase}</b>`.** After that, view-specific metric spans are fine
  (screens/scanned/tokens for web; hosts/live/findings for ASR) **provided each is self-explanatory or has a
  `title=` tooltip.** No bare jargon (`apex`, `passive`, `live`, `CT`) without a tooltip.
- **`conn`** is `"connecting" | "open" | "closed"` (`ConnState`) — never invent other words.
- A view without a pause/handoff simply passes no `actions` — the spacer still right-aligns the rest.

## Phase vocabulary — the `Phase` enum, nothing else

`Phase = init | phase1_recon | phase1_label | phase2_scan | phase2_burpscan | report | done | halted`
(`core/types/phase.ts`).

- **The header's phase field shows a real `Phase` value.** The **terminal/success phase is `report`** — this is
  what the pilot sets when it finishes (`run.ts`), and what a completed run shows. **Never `done`** for a
  successful run, and never ad-hoc words (`discovering`, `probing`, `scanning`, `complete`) in the phase field.
- A view that derives progress client-side must still map to enum values. ASR does this by carrying the store
  phase on `AssetInventory.phase` (`phase1_recon` while mapping → `report` when complete) and reading
  `inv.phase` — it does **not** invent its own phase words.
- Descriptive progress text in `.pmeta` (e.g. "▶ now: /orders", "probing 40/200 hosts") is allowed and is
  separate from the phase field — but keep it descriptive, not a fake phase.

## Export / Report

- **Every Export menu leads with the shared `ReportLinks` block** (Report → HTML · PDF · Markdown · Findings
  CSV), which points at `/api/assessments/<id>/report?format=…`. This works for any run whose findings are in
  the store, so **a view must persist its findings to the store** (recon findings included — see the ASR note)
  for its Report to be non-empty. A Report link that yields an empty report is a bug, not a feature.
- After the Report block, add view-specific sections (`.dl-h` header + links), e.g. web's "Screen inventory",
  ASR's "Attack surface". Same `.dl` / `.dl-menu` markup throughout.
- Summary label: `⬇ Export / Import` when the menu offers an import (operator), else `⬇ Export`.

## Log

- **Newest-first.** Render `[...items].reverse()` — the current activity is on top. (Both `Log.tsx` and
  `AsrLog.tsx` do this; don't ship a bottom-appending log.)
- **Capped to the most recent 300**, matching the store projection (`core/view.ts` → `events.slice(-300)`).
  A client-side log slices `.slice(-300)` before rendering. Never dump the unbounded history.
- Tab label reflects the visible count: `Log ({logLines.length})`.

## Tabs

- `.tabs > button` with `className={tab===k ? "active" : ""}`; body in `.tabbody`.
- Tab labels that have a quantity carry it: `Findings ({n})`, `Assets ({n})`, `Log ({n})`.
- Only render tabs the view actually has (ASR has Host/Assets/Findings/Log — not Scenarios/APIs/Sessions/Ask).

## Dashboard (project list, `Index.tsx`)

- One `.idxtable` row per run: Target (name + sub), `typepill`, `phasepill` (class = raw phase), numeric
  Screens / Findings (`.num`, `.hasf` when > 0), Updated, ID, action.
- **Findings count = the store's finding count** (`state.findings.length`). A view whose findings live only in a
  side file will read **0 here** — persist to the store so the dashboard is truthful (this is why ASR now
  upserts recon findings).
- Idle-run action is `▶ Resume` for **all** types (running → `◼ Stop`). A per-type behavioural nuance (ASR's
  resume re-scans from scratch rather than continuing) goes in a `title=` tooltip — **not** a different label.

## Terminology & colour

- **No unexplained jargon** in on-screen chrome. Prefer plain words; if a domain term is unavoidable
  (`live`, `passive`, `CT`), attach a `title=` tooltip. (Removed already: `apex`→`domain`; `AI triage`→`AI
  triage lead` with a "not a confirmed finding" tooltip.)
- **Colour comes from tokens** — `var(--accent) / --ok / --warn / --err / --muted / --line / --panel`. Never
  hardcode a hex accent (the dark-purple ASR panels were a drift; they now use `--accent`). Severity/band
  colour is semantic and separate from the accent.
- **Icons**: Lucide-style single-color outline, `stroke="currentColor"`, sized via CSS (see `NewLauncher`
  `.mode-ic`). No decorative/AI emoji (🤖 etc.). (The web viewer's tab emoji 🧩/🖥/💬 are pre-existing; don't add
  more, and don't copy them into new views.)

## Data & polling

- Poll assessment data on a `window.setInterval` (3–4 s) inside a `useEffect` with an `alive` guard and
  `clearInterval` cleanup (see `Index`, `App`, `AsrView`). Don't hand-roll a different cadence.
- URL carries the run: `?id=<id>` (`useAssessmentId`). No id → the project list (`Index`).

## Verification — before you say a view is done

The mistakes this doc prevents were all "claimed matching without checking". So the last step is not optional:

1. `pnpm --filter @veritas/webui build` — it must build.
2. **Serve it and look.** Screenshot the view; open the Export menu; read the header text back. Diff each
   element against the checklist below. "I changed the code" is not "I verified the output".
3. If it renders blank, capture `console`/`pageerror` — a runtime throw (e.g. a required field your data omits)
   reads identically to a layout bug until you look at the console.

### Conformance checklist

- [ ] Renders through `StatusBarShell`; trailing controls right-aligned by the single `.sb-spacer`.
- [ ] Header metrics start with `phase:`; phase is a `Phase` enum value; terminal run shows `report`, not `done`.
- [ ] Every header metric is self-explanatory or tooltipped.
- [ ] Export leads with the shared `ReportLinks`; Report actually renders (findings are in the store).
- [ ] Log is newest-first and capped at 300; tab shows the count.
- [ ] Tabs use `.tabs`/`.active`/`.tabbody`; quantity labels carry `({n})`.
- [ ] Colours are tokens; no hardcoded accent; icons are outline, no decorative emoji.
- [ ] Dashboard row shows a truthful findings count (findings persisted to the store).
- [ ] Built, served, screenshotted, and diffed against this list.

---

## ASR conformance (status)

ASR (`AsrView.tsx` + `AssetTree/AssetTable/AssetFindings/AsrLog`) was brought onto these rules:

- Header → shared `StatusBarShell`; right-aligned via `.sb-spacer`; `phase` reads `inv.phase`
  (`phase1_recon` → `report`), never `done`/`discovering`/`probing`.
- Export → leads with the shared `ReportLinks`; `cmdAsr` persists recon findings to the store (as `suspected`
  leads, never hand-`confirmed`) so the Report and the dashboard findings count are populated.
- Log → `AsrLog` newest-first, `.slice(-300)`.
- De-purpled to `--accent`; `apex`→`domain`; `AI triage`→`AI triage lead` (tooltip); jargon tooltipped.
- Left tree kept (AssetTree); Assets tab added as a sortable table (`AssetTable`).
