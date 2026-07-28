# Putting this on a branch

I can read `Krilliac/DuetOS` but I cannot push to it — my GitHub access here is
read-only, so there is no commit/branch tool on my side. This bundle is
branch-ready; the commands below are what a code session (or you) runs.

Suggested branch name: **`design/aurora-shell`**

## From this bundle

```bash
cd /path/to/duetos
git checkout main && git pull
git checkout -b design/aurora-shell

mkdir -p docs/aurora-theme
cp -R design_handoff_duetos_aurora/. docs/aurora-theme/

git add docs/aurora-theme
git commit -m "docs(design): Aurora shell redesign — handoff package

Glossy-glass shell redesign in the Win7 Aero lineage crossed with modern
Fluent layout: 44px glass titlebars, centred island taskbar, Start,
quick settings, notification centre, sign-in and boot screens, plus nine
app surfaces (Task Manager, Kernel Log, Inspect, Files, Settings,
Terminal, Notepad, Calculator, GFX Demo).

Dual accent keeps its meaning (native / Win32 PE peer) and is now fully
user-customisable with HSL editing and user presets.

- docs/aurora-theme/DuetOS Aurora.dc.html   new design (open in a browser)
- docs/aurora-theme/DuetOS Current.dc.html  recreation of today's Duet theme
- docs/aurora-theme/IMPLEMENTATION.md       kernel file-by-file plan
- docs/aurora-theme/README.md               full spec: tokens, metrics, behaviour"

git push -u origin design/aurora-shell
```

Then open a PR against `main` titled **"Aurora shell redesign (design handoff)"**.

## Where it lands

`docs/aurora-theme/` sits next to the existing `docs/duet-theme/prototype/`, which
is the same pattern the current Duet theme used for its handoff — so the repo keeps
one folder per design generation.

## For the code session picking this up

Read in this order:

1. `docs/aurora-theme/README.md` — the design spec (tokens, per-screen metrics,
   interaction rules).
2. `docs/aurora-theme/IMPLEMENTATION.md` — the phase plan against real kernel
   files, including the compositor blending work the glass needs and the
   1024 × 768 metric table.
3. Open `DuetOS Aurora.dc.html` in a browser next to
   `DuetOS Current.dc.html` for a before/after; the toolbar at the top switches
   Desktop / Sign in / Boot and dark ↔ light.

Start with phase 1 (`theme.h` fields) — it is inert until phase 2 uses it, so it
merges without touching the shipped look.

## Note on the HTML

Both `.dc.html` files are self-contained design references: open directly in a
browser, no build step. They pull Instrument Sans + JetBrains Mono from Google
Fonts and reference this project's design-system stylesheet; if you want them fully
offline in the repo, say so and I will inline everything into single files.
