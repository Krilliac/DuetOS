# DuetOS Desktop Redesign — Handoff Package

This folder contains everything Claude Code needs to integrate the redesigned desktop into the live DuetOS repo.

## Contents

| File | Purpose |
|---|---|
| `CLAUDE_CODE_PROMPT.md` | The prompt to paste into Claude Code. Start here. |
| `duetos-desktop-prototype.html` | **Single-file interactive prototype.** Open in any browser — no internet required. Drag windows, click Start, toggle the Tweaks button (right side of toolbar) to flip through every theme/accent/layout combination. This is the visual source of truth. |
| `source/` | Un-bundled prototype source — one file per concern (chrome, taskbar, start menu, wallpapers, etc). Reference this when porting individual features. |

## How to use this on mobile

1. Upload this whole folder (or the zip) to a Claude Code conversation in your DuetOS repo.
2. Paste the contents of `CLAUDE_CODE_PROMPT.md` as your first message.
3. Claude Code will run through Phase 1 → 9, stopping after each phase for your approval.

## Design summary

- **Personality:** refined, confident, calm. The "Duet" name → two interlocking arcs as the logomark and two accent colors (teal = native DuetOS, amber = Win32 PE peer) that visually distinguish ABIs throughout the UI.
- **Era:** Win7/10 grammar (bottom taskbar with Start | search | pinned | tray | clock; Start menu with pinned grid + recents) rendered in DuetOS's own visual language — no Microsoft chrome lifted verbatim.
- **Themes:** `slate` (dark, default), `light`, `classic`. Five accent palettes. Three wallpapers (`duet-arcs`, `topo`, `syscalls`).
- **Apps fully designed:** Task Manager (Processes/Performance/ABI peers/Startup), Kernel Log (filterable tail), Inspect/Disassembler (PE32+ sections + disasm + syscall sites). Other apps (Calc, Notepad, Files, Registry, GFX, Shell) are stubbed in the Start menu.

## Don't port the tweaks panel

`source/tweaks-panel.jsx` is a design-tool overlay that lets the prototype switch themes live. It has no place in the real shell — every setting it exposes should be moved to a real Settings → Personalization page (Phase 7 of the prompt).
