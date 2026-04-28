# Claude Code prompt — wire the new DuetOS desktop into the live OS

You are working in the **DuetOS** repository (a from-scratch x86_64 OS that hosts a native ABI alongside a Win32 PE peer ABI; existing themes are "Classic" and "Slate10", cycled by Ctrl+Alt+Y). I have a finished HTML/React prototype of a redesigned desktop that I want integrated into the real compositor and userland shell, not just dropped in as a webview.

The prototype is bundled as a single file: **`duetos-desktop-prototype.html`** in this folder. Open it in any browser to see the target design — it's interactive (drag windows, click Start, toggle Tweaks). The Tweaks panel exposes every variation the design supports (theme, accent, wallpaper, taskbar position, density, Start state, widgets) so you can see exactly what each token controls.

If you need the un-bundled source (one file per concern), the originals are in this folder too:
- `desktop.html` — entry; pinned React 18 + Babel
- `desktop-app.jsx` — root, window-manager state, tweaks wiring
- `desktop-windows.jsx` — window chrome + Task Manager / Kernel Log / Inspect
- `desktop-taskbar.jsx` — taskbar (bottom/top/left/right), Start button, search pill, running-app dots, widget pill, tray, clock
- `desktop-startmenu.jsx` — Start menu (pinned grid + recommended + recents + footer)
- `desktop-wallpaper.jsx` — three wallpapers (`duet-arcs`, `topo`, `syscalls`)
- `desktop-icons.jsx` — `DuetMark` logomark + line-icon set
- `desktop-data.jsx` — fixture data (replace with live syscalls)
- `tweaks-panel.jsx` — design-tool only, **do not port**

## Your job

Land this design as a **first-class DuetOS theme + shell** named `Duet` (alongside `Classic` and `Slate10`), driven by the real kernel and compositor, with the existing apps (Task Manager, Kernel Log, Inspect/Disassembler, Calculator, Notepad, Files, Registry Editor, GFX Demo, Windowed Hello) wearing the new chrome. Ctrl+Alt+Y must cycle Classic → Slate10 → **Duet**.

## Phases (do them in this order; pause after each for review)

### Phase 1 — read the prototype, write a design spec
1. Open `duetos-desktop-prototype.html` in your sandboxed browser. Walk every Tweaks combination. Read every JSX file.
2. Produce `docs/duet-theme-spec.md` capturing:
   - Color tokens (the `--bg-1/2`, `--chrome/-2/-3`, `--line/-2`, `--ink/-2/-3`, `--accent`, `--accent-2`, `--hover`, `--press`, `--shadow` set per `slate`/`light`/`classic` mode) — translate each to the kernel's existing color struct.
   - Type stack: Inter (UI) + JetBrains Mono (kernel/inspect/log). Note exact sizes used (10/10.5/11/11.5/12/14/18) and weights.
   - Window chrome: 30 px titlebar (26 px in compact), 1 px border, 6 px radius (0 maximized), gradient on focus, traffic-button widths 46×titlebar, red-hover close.
   - Taskbar: 44 px (compact 38 px), 4 positions, accent-rail "show desktop" sliver, indicator dot under running apps (2 px tall, 8/14 px wide based on focus).
   - Start menu: 520×540, 14/18 px header, search pill, 3-col pinned grid, 2-col recommended, recents column, user/power footer.
   - The DuetMark logomark — two counter-rotating arcs; spec the geometry.
   - Wallpaper: arcs / topo / syscalls — describe so the GFX team can render them in the framebuffer.
3. Stop. Show me the spec.

### Phase 2 — kernel/compositor color & token plumbing
1. Locate the existing theme system (search for `Slate10`, `Classic`, the Ctrl+Alt+Y handler, and any `theme.h`/`theme.c`/`theme.rs` equivalent). Confirm with me before editing.
2. Add a `Duet` theme entry that exposes every token from the spec. Match the existing struct shape exactly — do not refactor the theme system in this phase.
3. Wire Ctrl+Alt+Y to cycle to it third.
4. Ship a screenshot diff (before/after `Slate10` boot) and stop.

### Phase 3 — window chrome
1. Find the compositor's titlebar/border draw routine.
2. Reimplement to match spec: focus gradient, square buttons, red close hover, 6 px radius unless maximized, dimmed-by-3% unfocused window.
3. The titlebar must support an optional **subtitle slot** (used by Inspect to show `PE32+ · x86_64` and by Kernel Log to show `/sys/klog · live`) — wire that into the window-create syscall (likely needs a new field; keep ABI back-compat).
4. Stop and show before/after.

### Phase 4 — taskbar shell
1. Locate the current shell process. Reimplement (or fork as `duet-shell`) to match the prototype:
   - Bottom by default; honor a `~/.config/duet/shell.toml` `taskbar.position` key (`bottom|top|left|right`).
   - Start button, search pill, pinned apps, running-app rail with focus dots, widget pill (CPU% + compositor fps polled from `/proc/stat` and the compositor presenter), system tray, clock.
   - The widget pill numbers must be **live**, not faked.
2. Pinned list reads from `~/.config/duet/shell.toml` `taskbar.pinned = ["taskmgr","klog","inspect","calc","note","files"]`.
3. Stop and demo.

### Phase 5 — Start menu
1. Real app enumeration from `/usr/share/applications/*.desktop` (or whatever DuetOS uses — check first).
2. Recents list reads the loader's PE-execution log. Recommended list shows top-3 by recency × frequency.
3. Search bar must actually search apps **and** the syscall table (`/sys/syscalls`) — typing `58` or `WIN_CREATE` should surface that syscall and offer "Open in Inspect".
4. Footer "Power" hits the real shutdown/reboot/lock paths.

### Phase 6 — port the three apps
For each, the prototype is the **visual + interaction reference**; the data is **live from the kernel**:
- **Task Manager** (`taskmgr.duet`) — Processes tab from `/proc`. ABI badge (NATIVE / WIN32 PE / LINUX) from the loader's per-process metadata. Performance tab pulls 4-core history from a 60-sample ring buffer in the kernel (add a `/proc/cpuhist` if absent). ABI peers tab groups by ABI. Startup tab reads boot timing from the kernel's boot-trace ring.
- **Kernel Log** (`klog.duet`) — `tail -F /sys/klog`. Filter + level toggles must work against the real ring. Live cursor when at tail.
- **Inspect** (`inspect.duet`) — open `/bin/windows-kill.exe` or any PE the user picks. PE parser already exists in the loader; expose its parsed sections, imports, and disasm via a new `/sys/inspect/<pid_or_path>` interface. Highlight syscall sites by cross-referencing call targets against the syscall thunk table.

Each app: build behind the new chrome, route through the new theme tokens, wire keyboard shortcuts (Ctrl+F filter in Kernel Log, Ctrl+G goto-address in Inspect, F5 refresh in Task Manager).

### Phase 7 — wallpapers in the framebuffer
1. Add a wallpaper subsystem (if there isn't one already). Three built-ins: `duet-arcs`, `topo`, `syscalls`.
2. `duet-arcs` and `topo` render as SVG-equivalent path strokes into the framebuffer at boot. `syscalls` is a hex-grid blit using the actual loaded syscall numbers as input — re-renders if the syscall table changes.
3. Settings → Personalization picker.

### Phase 8 — desktop widgets
- Analog clock widget and kernel-stats widget from the prototype.
- They must be real compositor windows with `WS_NOACTIVATE | WS_TOPMOST_DESKTOP` (or the DuetOS equivalents). Right-click → close.

### Phase 9 — cleanup
- Add a `make duet-theme-screenshots` target that boots into QEMU, takes screenshots of the desktop / Start menu / each of the three apps, and saves them to `docs/screenshots/duet/`. Update README.

## Rules

- **Never invent kernel APIs.** If you need data the kernel doesn't expose, propose the new syscall/procfs entry in your reply and wait for approval.
- **Stay ABI-compatible.** Window-create, theme-get, etc. — additive only.
- **Match the prototype's visual numbers exactly** (paddings, font sizes, border radii, column widths). The spec is the source of truth — if the prototype and spec disagree, fix the spec to match the prototype.
- **No emoji in UI strings.** No gradient backgrounds in chrome (gradients are reserved for wallpaper + focus titlebar only).
- **Keep `Classic` and `Slate10` working.** This is additive.
- After each phase, stop, summarize what you did, and wait for me to greenlight Phase N+1.

Start with Phase 1.
