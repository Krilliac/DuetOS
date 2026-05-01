# End-user feature gaps v0

_Type: Observation + Decision (gap inventory)._
_Last updated: 2026-05-01._

## Status — landed slices

| Date | Item | Effect |
|------|------|--------|
| 2026-05-01 | P0 #5 Settings panel | `kernel/apps/settings.{h,cpp}` — theme prev/next/HighContrast/Default, opacity ±, TZ ±, LOG OUT, plus a readout pane (theme name, opacity, UTC + LOCAL clocks, TZ offset, user list). Reachable via Start menu and `t/h/-/+/0` keys. New `ThemeRole::Settings`; every theme palette extended. |
| 2026-05-01 | P3 #25 Notifications | `kernel/drivers/video/notify.{h,cpp}` — single-slot toast painted bottom-right above the taskbar, decays on the 1 Hz compose tick. Public API: `NotifyShow(text)`, `NotifyShowFor(text, ttl_ticks)`. Wired into theme-cycle hotkeys, Notes copy/paste, lock-screen, magnifier toggle. |
| 2026-05-01 | P1 #10 Lock screen | Ctrl+Alt+K reopens the GUI login gate via `AuthLogout` + `LoginStart(Gui)`. Bound separately from Ctrl+Alt+L (taskbar drag-lock) so existing chord muscle memory is intact. |
| 2026-05-01 | P1 #8 Clipboard wired into Notes | `NotesCopyToClipboard` / `NotesPasteFromClipboard` use the existing kernel clipboard (`WindowClipboardSetText`, exposed to Win32 PEs via OpenClipboard). Bound to Ctrl+C / Ctrl+V; Ctrl+C falls through to ShellInterrupt when Notes isn't focused. |
| 2026-05-01 | P1 #11 Account management | Settings panel grew a `USERS:` readout listing every account (name + role) and a `LOG OUT` button. Read-only for v0; mutations remain shell-command driven (`useradd`, `passwd`). |
| 2026-05-01 | P3 #23 Time zone | `kernel/time/timezone.{h,cpp}` — signed minutes offset ([-12 h, +14 h], 30-min steps). Settings shows UTC + LOCAL clocks and the live offset; TZ ± buttons step it. No zoneinfo, no DST, no persistence — documented limits. |
| 2026-05-01 | P3 #21 Accessibility (magnifier) | `kernel/drivers/video/magnifier.{h,cpp}` — Ctrl+Alt+M toggles a 200×150 inset at top-right showing 2× nearest-neighbour zoom around the cursor. Drops to bottom-right when cursor is in top-right quadrant so it never occludes its own source. Direct framebuffer reads via `FramebufferGet().virt`. |
| 2026-05-01 | P0 #1 Notes save / load | `kernel/apps/notes_persist.cpp` (new TU) + `kernel/apps/notes_internal.h` (private detail surface) — `NotesSave()` and `NotesLoad()` round-trip the live buffer through `Fat32CreateAtPath` / `Fat32DeleteAtPath` / `Fat32ReadFile` against `NOTES.TXT` on the FAT32 root volume. Wired to Ctrl+S / Ctrl+O when Notes is the active window (`kernel/core/main.cpp`). Boot self-test (`NotesPersistSelfTest`) runs after FAT32 probe and validates a save → load round-trip on a known marker. GAP: non-atomic save (delete-then-create); revisit when FS journaling lands. **The "blocked on FAT32 write" entry in this file was stale — the kernel-side write path was already complete; only app wiring was missing.** |

## Status — blocked on infrastructure

These items have a real user-visible gap, but a meaningful
implementation is gated on driver / firmware / protocol work
that the gap entry alone can't unblock. Listed with the blocker
so a future slice that lands the prerequisite knows to come back
and finish the user-facing tier.

| Item | Blocker | What lands when the blocker is gone |
|------|---------|------------------------------------|
| P0 #2 Audio output | Intel HDA codec discovery + CORB/RIRB stream programming (probe-only today; `kernel/drivers/audio/audio.cpp:43`) | Settings volume slider, system beep/chime on notifications, WAV / OGG playback app |
| P0 #4 Wi-Fi connect-to-SSID | Per-vendor firmware loader (does not exist) + 802.11 MLME state machine; `iwlwifi/rtl88xx/bcm43xx` are chip-ID-probe-only | Network flyout SSID picker, Settings → Network → Wi-Fi tab, captive-portal handler |
| P2 #12 Multi-monitor / resolution change | Per-vendor GPU drivers (Intel/AMD/NVIDIA all probe-only per `render-drivers-v6.md`); EDID parser; mode-set negotiation | Settings → Display tab with resolution / refresh-rate / monitor layout |
| P2 #13 Brightness | ACPI EC driver (does not exist) + per-vendor backlight register paths | Settings brightness slider; Fn-key brightness hotkeys |
| P2 #14 Battery + ACPI suspend | ACPI AML interpreter (only static tables parsed today); EC battery status registers; S3 / S0ix wake plumbing | Battery icon in tray, Settings → Power, lid-close suspend |
| P2 #15 Software install / app discovery | Persistent FS (FAT32 write) for the install root + a package manifest format | Start menu enumerates `/disk/apps/`; "Install from file…" dialog |
| P2 #16 Disk installer | FAT32 write + GPT write + bootloader copy | Installer app that lays DuetOS down on an NVMe partition |
| P2 #17 System updater | Code-signing infrastructure + A/B kernel-slot layout | "Check for updates" surface; rollback |
| P2 #18 Bluetooth | Host-controller (HCI) driver + L2CAP / RFCOMM / GATT stack | Pair mouse / keyboard / headset / phone |
| P2 #19 Printer | USB printer class driver + IPP / PostScript / raster pipeline | Print from Notes |
| P2 #20 Webcam | UVC USB-Video class driver | Camera app, video calls |
| P3 #26 Persistent log viewer | FAT32 write so the `klog` ring can survive reboot | `journalctl`-style history viewer |
| P3 #27 Session restore | FAT32 write for window-position / open-app state | Desktop comes back the way the user left it |

## Status — deferred

These are tractable but each one is the "wrong size" for a
single-session slice. Listed so a future block of work can
schedule them.

| Item | Reason | Rough effort |
|------|--------|--------------|
| P0 #3 USB mouse | xHCI HID class needs report-descriptor parsing for mouse-class endpoints; the keyboard-class path landed in `xhci-hid-keyboard-v0.md` and is the template. No QEMU emulation of USB mouse — has to be tested on physical HW post-merge. | 200-300 LOC |
| P1 #6 Terminal emulator | Kernel shell is wired to a single global console (ConsoleWrite). A windowed terminal needs a console-multiplex refactor so the shell takes a per-session sink. | Multi-session refactor |
| P1 #7 Image / PDF / media viewers | Each format needs its own parser + frame loop. Image viewer is the smallest (PNG / BMP, ~500 LOC each). PDF is huge. Audio / video need P0 #2 first. | One-per-format |
| P1 #9 Screenshot tool | tmpfs slot cap is 512 bytes/slot × 16 slots = 8 KiB total, far below a 1024×768 framebuffer (~3 MiB). Real screenshot save is gated on FAT32 write (P0 #1). | Wait for #1 |
| P3 #21 Accessibility | Magnifier landed (this commit). Screen reader needs an AT-SPI-equivalent kernel surface; on-screen keyboard needs >32 widget slots (today's cap; bump first). | Per-primitive |
| P3 #22 IME / non-Latin input | Input-method framework refactor; PS/2 + xHCI HID drivers currently hardcode US layout. | Input refactor |
| P3 #24 Locale / language switching | UI strings live in C++ literals across every `kernel/apps/*.cpp`. A string-table layer with id → text indirection is the prerequisite. | Refactor across all apps |

## Why

## Why

DuetOS now boots to a desktop, runs Win32 PE binaries (118 smoke
apps, 93.7 % pass per `smoke-pe-suite-v23.md`), reaches the public
internet over wired Ethernet, and ships nine kernel-resident apps.
The internal-ABI roadmap is well-tracked in `subsystems-status.md`
— Linux syscall counts, NT facade truthfulness, FS journaling, SMP
scheduler, IOMMU. What that file does **not** capture is the
landscape from the other side of the screen: "what would someone
using DuetOS for an afternoon notice is missing?".

This file is that landscape. It is an inventory, not a roadmap.
Each item names the kernel/userland surface that owns the gap so a
future slice can pick one without re-deriving the field.

**Out of scope, deliberately:** internal-ABI gaps already enumerated in
`subsystems-status.md`. Cross-reference, don't duplicate.

## P0 — workflow blockers (a fresh user hits these in the first 5 minutes)

### 1. Persistent file save / load [LANDED for Notes 2026-05-01]
- **Today:** Notes save / load is wired against the FAT32 root
  volume — Ctrl+S writes the live buffer to `NOTES.TXT`, Ctrl+O
  loads it back. Implementation in
  `kernel/apps/notes_persist.cpp`; uses
  `Fat32CreateAtPath` / `Fat32DeleteAtPath` / `Fat32ReadFile`
  directly. Boot self-test (`NotesPersistSelfTest`) round-trips
  a known marker after FAT32 probe. The kernel-side write path
  (`Fat32WriteInPlace`, `Fat32AppendAtPath`, `SYS_FILE_WRITE`,
  `SYS_FILE_CREATE`, cap-gated by `kCapFsWrite`) had already
  landed before this entry was opened — the gap was app wiring.
- **Still missing:** `kernel/apps/files.{h,cpp}` is still
  read-only (no copy / move / delete UI). `userland/libs/*`
  doesn't have a file-open-dialog primitive. Other apps
  (Settings, Calculator, Clock) don't persist any state yet.
- **Owners:** `kernel/apps/files.{h,cpp}` for the file-manager
  UI; userland for the dialog primitive.

### 2. Audio output [BLOCKED on HDA codec/stream]
- **Today:** `kernel/drivers/audio/audio.cpp` does HDA register
  probe only ("v0 probing here is read-only" comment near line 43);
  only `kernel/drivers/audio/pcspk.cpp` produces sound.
- **Expected:** a beep, a tone generator, a WAV file plays.
- **Owners:** `kernel/drivers/audio/`. No userland mixer / volume
  service yet.

### 3. USB mouse [DEFERRED — xHCI HID extension]
- **Today:** PS/2 mouse works (interrupt handler, cursor moves).
  USB HID class is probe-only — no report-descriptor parsing for
  mouse-class endpoints. See `xhci-hid-keyboard-v0.md` for the
  keyboard parallel that *did* land.
- **Expected:** plug in an external USB mouse, cursor moves.
- **Owners:** `kernel/drivers/usb/class/hid*`.

### 4. Wi-Fi connect-to-SSID [BLOCKED on firmware loader + MLME]
- **Today:** `iwlwifi`, `rtl88xx`, `bcm43xx` are chip-ID-probe-only
  shells (`wireless-drivers-v0.md`) with `firmware_pending=true`.
  The network flyout panel (`network-flyout-panel-v0.md`)
  honestly displays "no driver".
- **Expected:** open the flyout, pick an SSID, type a password,
  get DHCP.
- **Owners:** `kernel/drivers/net/wireless/`, plus a
  firmware-loader subsystem (does not exist).

### 5. Settings panel [LANDED 2026-05-01]
- **Today (2026-05-01):** v0 landed. New kernel app at
  `kernel/apps/settings.{h,cpp}` registers a window under
  `ThemeRole::Settings`, exposes six buttons (THEME PREV / NEXT,
  OPACITY -/+, HIGH CTRST, DEFAULT) plus a readout pane (theme
  name, active-window opacity hex, wall-clock from RtcRead,
  build banner). Reachable from Start menu → SETTINGS, or
  keyboard chars `t`/`h`/`-`/`+`/`0` while focused. Mutations
  flow through the existing `Theme*` and `WindowSetOpacity`
  APIs — no new authoritative state. Boot self-test asserts
  char dispatch + theme round-trip + id-range gating.
- **Still missing:** Display brightness (no backlight driver).
  Sound (no audio driver). Keyboard layout (US hardcoded).
  Time zone (UTC only). Language (English hardcoded). Wi-Fi
  picker (no driver). Bluetooth pairing. Printer setup. Power
  settings.
- **Owners:** `kernel/apps/settings.{h,cpp}` (extend), plus the
  per-surface drivers when they land.

## P1 — common app expectations (hit in the first hour)

### 6. Terminal emulator (userland shell) [DEFERRED — console multiplex refactor]
- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
  `userland/shell/` is a stub ELF; no real shell binary.
- **Expected:** a windowed terminal app that runs commands as a
  user-mode process.
- **Owners:** `userland/shell/`, plus a PTY layer (does not exist).

### 7. Image / PDF / media viewers [DEFERRED — per-format parsers + storage]
- **Today:** none. `mini_browser` is a smoke test, not a default
  browser app (`mini-browser-runs-on-duetos-v0.md`).
- **Expected:** image viewer (PNG/JPEG), PDF reader, audio/video
  player. Likely Win32 PE apps once GDI/D3D acceleration improves,
  or native kernel-resident apps.
- **Owners:** new `kernel/apps/imgview.{h,cpp}` etc., or PE apps
  installed under `userland/apps/`.

### 8. Clipboard + drag-and-drop wired into apps [LANDED 2026-05-01]
- **Today:** clipboard smoke tests exist; no kernel app uses the
  surface.
- **Expected:** Ctrl+C in Notes, Ctrl+V in another window or in
  the kernel shell.
- **Owners:** `kernel/apps/notes.cpp` and clipboard syscall hookup.

### 9. Screenshot tool [BLOCKED on FAT32 write]
- **Today:** none. PrintScreen is unbound.
- **Expected:** PrtSc captures the framebuffer to a file in
  `/disk/screenshots/`.
- **Owners:** new `kernel/apps/screenshot.{h,cpp}` + framebuffer
  reader (already used by gfxdemo).

### 10. Lock screen / screensaver [LANDED 2026-05-01]
- **Today:** none. Single hardcoded `admin/admin` + `guest`
  credentials in `kernel/core/main.cpp`.
- **Expected:** screen locks after idle, or on Win+L.
- **Owners:** `kernel/security/auth*`, plus an idle-timer hook.

### 11. Account management [LANDED (read-only UI) 2026-05-01]
- **Today:** hardcoded credentials in `kernel/core/main.cpp`. No
  account creation / password change / multi-user switch.
- **Expected:** a Users panel (under Settings) — add user, change
  password, switch active session.
- **Owners:** `kernel/security/auth*`, `kernel/proc/process.cpp`
  (uid/gid model does not exist).

## P2 — system-wide expectations (day-two, or first contact with real hardware)

### 12. Multi-monitor / runtime resolution change [BLOCKED on vendor GPU drivers + EDID]
- **Today:** single linear framebuffer; mode set at boot via Bochs
  VBE; no EDID parse; no hot-plug detect.
- **Expected:** plug HDMI, get a second screen; change resolution
  from Settings.
- **Owners:** `kernel/drivers/gpu/` (per-vendor BAR programming,
  EDID), framebuffer driver layout.

### 13. Brightness / volume hotkeys [BLOCKED on EC + audio drivers]
- **Today:** no backlight driver, no audio output → Fn-keys are
  dead.
- **Expected:** laptop brightness keys dim the panel; volume keys
  change a master mixer.
- **Owners:** ACPI EC driver (does not exist) + audio mixer.

### 14. Battery + power management [BLOCKED on ACPI AML interpreter]
- **Today:** `kernel/drivers/power/power.cpp:36` flags
  `backend_is_stub = true`. ACPI battery state is "unknown" — no
  AML interpreter, no EC query. No suspend/resume.
- **Expected:** battery icon in tray, sleep on lid close, S3
  resume.
- **Owners:** `kernel/drivers/power/`, `kernel/acpi/` (AML).

### 15. Software install / app discovery [BLOCKED on FAT32 write]
- **Today:** apps ship inside the kernel ISO. No external install
  path.
- **Expected:** a way to add apps without recompiling — even a
  basic "drop a PE in /disk/apps/, see it in Start".
- **Owners:** Start-menu enumeration over `/disk/apps/`, plus a
  package format. Neither exists.

### 16. Disk installer [BLOCKED on FAT32 + GPT write]
- **Today:** boots from ISO only. Live system; no install.
- **Expected:** an installer app that lays down DuetOS on an NVMe
  partition and boots from disk next time.
- **Owners:** new installer; depends on FAT32 write + GPT write +
  bootloader copy.

### 17. System updater [BLOCKED on signing infra + A/B kernel slots]
- **Today:** none. No A/B kernel slots, no kexec, no signed-update
  path.
- **Expected:** a "check for updates" surface, ideally with
  rollback.
- **Owners:** boot/, plus a network-fetch + verify pipeline.

### 18. Bluetooth [BLOCKED on HCI driver + L2CAP/RFCOMM/GATT]
- **Today:** no host-controller driver, no stack.
- **Expected:** pair a mouse, keyboard, headset, or phone.
- **Owners:** new `kernel/drivers/bluetooth/`.

### 19. Printer [BLOCKED on USB print class + IPP/PostScript]
- **Today:** no USB printer class, no IPP client.
- **Expected:** print a text file from Notes.
- **Owners:** `kernel/drivers/usb/class/printer.cpp` (does not
  exist) + a print-spooler service.

### 20. Webcam [BLOCKED on UVC class driver]
- **Today:** UVC class enumerated in `kernel/drivers/usb/usb.h` but
  no driver.
- **Expected:** a Camera app shows live frames; video calls work.
- **Owners:** `kernel/drivers/usb/class/uvc.cpp` (does not exist).

## P3 — accessibility, locale, and quality-of-life

### 21. Accessibility stack [PARTIAL — magnifier landed 2026-05-01]
- **Today:** HighContrast theme exists (WCAG AAA palette per
  `desktop-chrome-polish-v0.md`); nothing else.
- **Expected:** screen reader, magnifier, on-screen keyboard,
  large-text mode beyond a single theme.
- **Owners:** new accessibility service.

### 22. IME / non-Latin input [DEFERRED — input framework refactor]
- **Today:** US keyboard layout hardcoded in PS/2 + xHCI HID
  drivers.
- **Expected:** keyboard-layout switcher, IME for CJK.
- **Owners:** input subsystem.

### 23. Time zone + DST [LANDED (offset only) 2026-05-01]
- **Today:** all times UTC; no zoneinfo. RTC read at boot.
  `clock_settime` honored (cap-gated) per `subsystems-status.md`.
- **Expected:** Settings → Time & Region picks a zone.
- **Owners:** `kernel/time/`, plus a zoneinfo data file.

### 24. Locale / language switching [DEFERRED — string-table refactor]
- **Today:** UI strings hardcoded English in kernel C++ literals.
- **Expected:** Settings → Language switches the desktop.
- **Owners:** every kernel app (`kernel/apps/*.cpp`) — a string
  table layer needed first.

### 25. Notifications [LANDED 2026-05-01]
- **Today:** apps can write to taskbar tabs; no notification
  surface.
- **Expected:** a transient toast in the corner ("file saved",
  "battery low").
- **Owners:** new compositor surface in `kernel/drivers/video/`.

### 26. Persistent log viewer / crash report UI [BLOCKED on FAT32 write]
- **Today:** klog ring lives in RAM and is lost on reboot
  (`klog-overhaul.md`); panic dumps go to serial. Log Viewer app
  shows the live ring.
- **Expected:** a `journalctl`-style history that survives reboot;
  a crash-report dialog that points at the dump.
- **Owners:** `kernel/log/`, `kernel/diag/crash-dump`, plus FS
  persistence for the ring.

### 27. Session restore [BLOCKED on FAT32 write]
- **Today:** window positions and open apps are forgotten across
  reboot.
- **Expected:** desktop comes back the way the user left it.
- **Owners:** `kernel/drivers/video/window_manager*`, plus FS
  persistence.

## Status pre-amble (for future updates)

Nothing in this file is a commitment to ship. It's a prioritized
to-pick-from menu for future slices. When a slice lands, move the
relevant item into a "Landed" subsection at the top and reference
the commit hash + the new knowledge file that documents the work,
the same way `subsystems-status.md` §10 does.

## Resume prompt

> Read `.claude/knowledge/feature-gaps-end-user-v0.md`. Pick the
> highest-priority unaddressed item that fits the session's energy
> budget (P0 first, P1 next). Add a status row at the top of this
> file when the slice lands; if the work warrants its own
> knowledge file, link it from the row.
