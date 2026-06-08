# In-Kernel Apps

> **Audience:** Kernel hackers, UI / shell contributors
>
> **Execution context:** Kernel — apps run as kernel tasks, draw via the
> [UI Toolkit](../subsystems/UI-Toolkit.md), accept input from the
> compositor
>
> **Maturity:** v0 — 23 apps wired, ranging from one-screen demos to
> functional editors

## Overview

DuetOS ships a set of small, kernel-resident applications under
[`kernel/apps/`](../../kernel/apps/). They serve three purposes:

1. **Boot-out-of-the-box experience.** A user reaching the desktop after a
   first boot can already interact with the system before any userland
   PE / ELF binary has been installed.
2. **Live verification of subsystems.** Each app exercises a kernel
   subsystem end-to-end — the file browser exercises FAT32, the device
   manager exercises ACPI + PCI, the debugger app exercises `kernel/debug/`.
   Boot smoke profiles drive these apps to verify the subsystems' wiring
   without relying on a PE binary.
3. **Reference UI patterns.** The native apps establish the conventions
   userland apps inherit when they want to call the
   [Native-Apps](../tooling/Native-Apps.md) UI surface.

Every app follows the same lifecycle:

```cpp
void XxxInit(WindowHandle h);   // register window chrome, allocate state
void XxxTick(...);              // poll for input, advance state
void XxxRedraw(...);            // paint into the chrome's client rect
void XxxShutdown();             // free state (rare — apps are session-lived)
```

The compositor invokes the right callback in response to window events. The
shell can spawn an app by name; the [Start Menu](Start-Menu.md) is the
end-user entry point.

## App Catalogue

Apps marked **v0** are scaffolded but missing significant functionality
(noted per row). The rest are functional within their stated scope.

> **Counting note:** the three app-related counts across the wiki count
> different things, so they differ on purpose. This catalogue's "23
> apps" counts **launchable apps** wired into `boot_bringup.cpp`
> (`settings` is one row even though it has five `SettingsXxxInit`
> sub-page TUs). [AppWidgets](../subsystems/AppWidgets.md)'s "28 of 33"
> counts **apps migrated to the widget library** out of the migration
> set. [Native Apps](../tooling/Native-Apps.md)'s "57 native apps"
> counts **all `kernel/apps/` translation units** (every TU, including
> helpers like `dbg_core` / `notes_persist` and the five
> `settings_*` sub-pages), the migration target for splitting apps
> out into standalone ELF binaries — not distinct launchable apps.

### Productivity

| App | Source | What it does | Subsystems touched |
|-----|--------|--------------|--------------------|
| **calculator** | [`calculator.cpp`](../../kernel/apps/calculator.cpp) | Calculator with on-screen 4×5 keypad. Fixed-point decimals (×10⁶, no FPU) — `.` and `1/4=0.25` work; integer scientific/bitwise/memory functions (keyboard-driven); CE (Clear Entry) distinct from C; multi-radix hex/bin/oct preview band; display clipped to the window. | UI, keyboard |
| **calendar** | [`calendar.cpp`](../../kernel/apps/calendar.cpp) | Month/week view with the configured timezone. | [time/timezone](Time.md) |
| **clock** | [`clock.cpp`](../../kernel/apps/clock.cpp) | Real-time clock with uptime side panel. | [timekeeper](Time.md) |
| **charmap** | [`charmap.cpp`](../../kernel/apps/charmap.cpp) | Unicode glyph picker; click-to-clipboard. | UI, clipboard, [util/unicode](Util.md) |
| **notes** | [`notes.cpp`](../../kernel/apps/notes.cpp) + [`notes_persist.cpp`](../../kernel/apps/notes_persist.cpp) | 4 KiB text editor with on-disk persistence to FAT32 `NOTES.TXT`. | FAT32, keyboard, clipboard |
| **trash** | [`trash.h`](../../kernel/apps/trash.h) | Recycle-bin UI for files moved out of the file browser. v0. | FS |

### File / Image / Hex

| App | Source | What it does | Subsystems touched |
|-----|--------|--------------|--------------------|
| **files** | [`files.cpp`](../../kernel/apps/files.cpp) | FAT32 browser; double-click `.TXT` opens in notes. Subdirectory descent (Enter / double-click) + parent-ascent (Backspace) + `[`/`]` back-forward history; letters do filename **type-ahead** (not view-switch — those are toolbar buttons); modified-date column from FAT `WrtDate`. | [VFS](../filesystem/VFS.md), [FAT32](../filesystem/FAT32.md) |
| **hexview** | [`hexview.cpp`](../../kernel/apps/hexview.cpp) | Hex + ASCII viewer for any file the FS exposes. | VFS |
| **imageview** | [`imageview.cpp`](../../kernel/apps/imageview.cpp) | Decodes PNG / JPEG / BMP / TGA, paints fitted to chrome. | [util image codecs](Util.md) |

### System / Settings

| App | Source | What it does | Subsystems touched |
|-----|--------|--------------|--------------------|
| **about** | [`about.cpp`](../../kernel/apps/about.cpp) | CPU model + memory + uptime banner. | ACPI, [arch/rtc](../kernel/Time.md) |
| **devicemgr** | [`devicemgr.h`](../../kernel/apps/devicemgr.h) | Collapsible class-grouped device tree from PCI + USB enumeration. PCI devices are grouped by base class (`BRIDGE`, `DISPLAY`, `STORAGE`, `SERBUS`, etc.); each group shows a `[-]/[+] CLASS (N)` header. Leaf columns: BUS:DV.F, VID:DID, human-readable NAME (vendor + PCI subclass), STATUS (OK / no-driver), DRIVER (class-inferred — no driver-binding registry). Keyboard: Up/Down navigate rows, Enter/Space toggle group expand/collapse. | [PCI](../drivers/PCIe-Enumeration.md), [USB](../drivers/USB.md) |
| **settings** | [`settings.cpp`](../../kernel/apps/settings.cpp) (+ `settings_datetime`, `settings_display`, `settings_keyboard`, `settings_mouse`, `settings_sound`) | Multi-page settings panel: time + display theme + input + audio. **DateTime (panel 5):** `S` sets the RTC; `N` toggles NTP auto-sync — when enabled, fires one live `NetNtpQuery` and writes the RTC on reply; persisted as `datetime.ntp` in `SESSION.CFG`. **Mouse (panel 4):** `B` toggles primary/secondary button swap — swaps the Left/Right bits in every `MousePacket` before routing, takes effect immediately; persisted as `mouse.btnswap`. **Sound:** master-volume level bar (`+`/`-` ±5%, `V` mute) backed by the audio backend's software gain stage; level + mute persist via `SESSION.CFG`. All knobs (mouse dblclick/sens/btnswap, kbd rate/delay/layout, sound cues/volume/muted, timezone, datetime.ntp, calc memory, imageview last file) round-trip through `SESSION.CFG` via `kernel/core/session_restore.cpp`. | time, net, gpu, input, audio |
| **sysmon** | [`sysmon.h`](../../kernel/apps/sysmon.h) | CPU % + memory + per-task histogram. | scheduler stats |
| **taskman** | [`taskman.h`](../../kernel/apps/taskman.h) | Process / thread lister with kill. Columns: PID/NAME/STATE/CPU%/TICKS/**MEM** (per-process mapped KiB via `mm::AddressSpaceUserPageCount`). Clickable column-header sort with asc/desc `^`/`v` indicator (S-key still cycles). | scheduler, [mm](../mm/Memory-Management.md) |
| **netstatus** | [`netstatus.h`](../../kernel/apps/netstatus.h) | Live interface stats (RX/TX bytes, link state). | [network stack](../networking/Network-Stack.md) |
| **firewall** | [`firewall.cpp`](../../kernel/apps/firewall.cpp) | ACL editor for `kernel/net/` rules. | network stack |
| **terminal** | [`terminal.cpp`](../../kernel/apps/terminal.cpp) / [`terminal.h`](../../kernel/apps/terminal.h) | Windowed terminal emulator — a character-cell grid that mirrors the live kernel shell session byte-for-byte, parses VT/ANSI via `util/vt_parser`, and routes keystrokes back through `ShellFeedChar`/`ShellSubmit`. | kernel shell, [framebuffer console](../subsystems/UI-Toolkit.md), util/vt_parser |

### Debug / Demo

| App | Source | What it does | Subsystems touched |
|-----|--------|--------------|--------------------|
| **dbg** | [`dbg.cpp`](../../kernel/apps/dbg.cpp) (+ `dbg_core.cpp`, `dbg_render.cpp`) | Interactive debugger UI — process list, memory hex window, register view, breakpoint table, mini disassembly, watch panel, syscall-scan results. | `kernel/debug/` namespace |
| **gfxdemo** | [`gfxdemo.cpp`](../../kernel/apps/gfxdemo.cpp) + [`gfxdemo_modes.cpp`](../../kernel/apps/gfxdemo_modes.cpp) + [`gfxdemo_modes_vk.cpp`](../../kernel/apps/gfxdemo_modes_vk.cpp) | Mode gallery exercising the framebuffer primitives + Vulkan rasterizer. VK-CUBE renders a depth-tested Gouraud-shaded cube through `vkCmdDrawIndexed` with the v1 vertex format. | [framebuffer](../subsystems/UI-Toolkit.md), [Vulkan ICD](../subsystems/Vulkan-ICD.md) |
| **screenshot** | [`screenshot.cpp`](../../kernel/apps/screenshot.cpp) | Captures the live framebuffer to a BMP saved on FAT32. | framebuffer, [util/bmp](Util.md) |

### Help / Notification / Misc

| App | Source | What it does | Subsystems touched |
|-----|--------|--------------|--------------------|
| **help** | [`help.h`](../../kernel/apps/help.h) | Bundled help text for every keyboard shortcut. | UI |
| **notify_center** | [`notify_center.cpp`](../../kernel/apps/notify_center.cpp) | Toast / banner history dashboard. | UI (notify subsystem) |
| **browser** | [`browser.h`](../../kernel/apps/browser.h) | Web-browser UI + HTTP fetch/render pipeline. Address bar **auto-focuses on open** (icon + start-menu launch paths) so keyboard URL entry works without a click. | networking |

## Launching

Three entry points; they all converge on the same `XxxInit()`:

- **Start menu** — see [Start Menu](Start-Menu.md) for the app
  registration mechanism. Apps register a name + icon + launch callback
  at kernel init time.
- **Shell command** — the shell dispatches `<app-name>` to the app's
  Start-menu entry. Example: `taskman`, `files`, `settings`.
- **Keyboard chord** — a handful of apps have system-wide chord bindings
  (e.g. Ctrl-Alt-T for taskman) defined in
  [`kernel/drivers/input/`](../../kernel/drivers/input/).

## Window Conventions

Every app gets a `WindowHandle` from the compositor. The
[UI Toolkit](../subsystems/UI-Toolkit.md) supplies:

- Chrome (border, title, close box, resize edges)
- Button widget registry (`WidgetRegisterButton` → opaque `id`)
- Tooltip slot per widget
- Z-order management (top-most, raise on click)

Apps **must not**:

- Touch the framebuffer outside their chrome's client rect.
- Spin while drawing — `Tick` returns quickly; long work goes on a
  worker task.
- Allocate persistent state across boot without going through FAT32 or
  the registry. The `notes` app is the reference for the "save what the
  user typed" pattern.

## Persistence Patterns

Apps that persist user state choose one of two paths:

- **FAT32 file** (notes, screenshot) — write through `KFile`, throttle
  to avoid drumming the FS on every keystroke.
- **Registry sidecar** (settings) — write through the registry
  subsystem; the sidecar pool throttles writes to the hive file. See
  [Win32 Registry](../subsystems/Win32-Registry.md).

The two persistence stores share one boot-time consistency check: if the
registry hive can't load, the registry boots with defaults; if a FAT32
write fails the app surfaces a notification and keeps the state in
memory.

## Threading Model

Each app's `Init` / `Tick` / `Redraw` callbacks run on the **compositor
thread**. That means:

- Long work (image decode, file read, hex region scan) goes on a worker
  task — apps that need this use the `Workpool` from
  [`kernel/sched/workpool.cpp`](../../kernel/sched/workpool.cpp).
- Cross-app state sharing is rare and explicit (e.g. clipboard, notify
  center). Apps don't reach into each other's data.

## Known Limits / GAPs

- **browser** — HTTP fetch/render pipeline is live; address bar
  auto-focuses on open (F-032). Multi-tab and persistent history UI are
  next-slice work.
- **calculator** — fixed-point decimals (×10⁶, no FPU) landed (F-010):
  `.` and `1/4=0.25` work, CE distinct from C (F-012), display clipped
  (F-051). Bitwise/sqrt/factorial operate on the truncated integer part
  (only meaningful on integers). Scientific functions beyond the 4×5
  grid remain keyboard-only.
- **devicemgr** — Collapsible class tree (F-027) and NAME/STATUS/DRIVER columns
  (F-026) are both landed. DRIVER is class-inferred until a real driver-binding
  registry exists on the device record. Admin actions (uninstall, NIC reset)
  are next-slice work.
- **sysmon / taskman** — taskman shows per-process MEM + clickable
  column sort (F-024/F-025); sysmon has a live system CPU sparkline
  (F-022) AND per-core CPU% via the public `SchedStatsReadCpu(cpu)`
  accessor (F-023). Admin actions are next-slice.
- **settings/display** — runtime resolution selector landed (F-029) via
  virtio-gpu scanout re-setup + a 10s revert-timeout; mode list
  800×600 / 1024×768 / 1280×720 / 1280×1024. See
  [Graphics-Drivers](../drivers/Graphics-Drivers.md).
- **settings/sound** — software master-volume gain stage (F-030); level
  + mute persist via `SESSION.CFG`. Gain is write-time (the v0 backend
  has no DMA-read hook / HDA codec amp control).
- **trash** — Restore / Permanent-Delete / Empty all wired through real
  FAT32 rename/delete with Y-confirm (F-020).
- **notes** — atomic save is best-effort (write then rename); a real
  journal is on the roadmap.
- **files (ramfs)** — `files.cpp:2343` carries a `GAP:` marker: the
  ramfs backend is read-only (`constinit`), so the file browser's
  delete action only notifies "ramfs is read-only". A writable
  backend would route it through `RamfsUnlink` + a rescan.
- **terminal** — windowed shell mirror is live, but routing Win32
  console PEs through the widget and drag-selection are out of scope
  for v0 (recorded in the Toaru port plan, not as `// GAP:` markers
  since there are no callers today — see the header comment around
  `terminal.h:60`). Copy uses the Ctrl+Shift+C "copy visible
  viewport" path instead.

## Capability / Privilege Surface

Kernel apps run as kernel tasks and are **not** cap-gated the way a
ring-3 PE / ELF is — they are trusted, in-kernel code. The
capability model applies at the syscall boundary to guest binaries;
these apps call kernel subsystems directly. When an app surfaces a
guest-facing resource (the file browser's FS view, the firewall's
ACL editor), the underlying kernel subsystem still enforces its own
invariants. See [Capabilities](../security/Capabilities.md) and
[Subsystem Isolation](Subsystem-Isolation.md).

## Related Pages

- [Start Menu](Start-Menu.md) — registration + launch
- [UI Toolkit](../subsystems/UI-Toolkit.md) — chrome, widgets, theme
- [Native Apps](../tooling/Native-Apps.md) — userland ports of the
  same UI patterns
- [Shell Commands](../reference/Shell-Commands.md) — shell ↔ app
  dispatch
