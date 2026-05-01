# End-user feature gaps v0

_Type: Observation + Decision (gap inventory)._
_Last updated: 2026-05-01._

## Status — landed slices

| Date | Item | Commit | Effect |
|------|------|--------|--------|
| 2026-05-01 | P0 #5 Settings panel v0 | _this commit_ | New `kernel/apps/settings.{h,cpp}` aggregates theme cycle/prev/next, direct HighContrast preset, Default reset, opacity step ±, plus live readouts for theme name, active-window opacity, RTC wall clock, and a build banner. Wired into Start menu (`SETTINGS`) and the keyboard / mouse routers. New `ThemeRole::Settings` (kCount → 8); every theme palette extended with a Settings title + client. Boot self-test asserts char dispatch table, theme-cycle round-trip, and id-range gating. |

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

### 1. Persistent file save / load
- **Today:** `kernel/apps/notes.{h,cpp}` is keyboard-driven scratch
  text — no save path, no load. `kernel/apps/files.{h,cpp}` is
  read-only over ramfs and a read-only `/disk` mount (FAT32 read
  landed; write didn't — see `storage-and-filesystem-roadmap.md`).
- **Expected:** edit a note, reboot, note is still there.
- **Owners:** `kernel/apps/notes.{h,cpp}`, `kernel/fs/fat32.h` (write
  path), `userland/libs/*` (no file-open dialog primitive).

### 2. Audio output
- **Today:** `kernel/drivers/audio/audio.cpp` does HDA register
  probe only ("v0 probing here is read-only" comment near line 43);
  only `kernel/drivers/audio/pcspk.cpp` produces sound.
- **Expected:** a beep, a tone generator, a WAV file plays.
- **Owners:** `kernel/drivers/audio/`. No userland mixer / volume
  service yet.

### 3. USB mouse
- **Today:** PS/2 mouse works (interrupt handler, cursor moves).
  USB HID class is probe-only — no report-descriptor parsing for
  mouse-class endpoints. See `xhci-hid-keyboard-v0.md` for the
  keyboard parallel that *did* land.
- **Expected:** plug in an external USB mouse, cursor moves.
- **Owners:** `kernel/drivers/usb/class/hid*`.

### 4. Wi-Fi connect-to-SSID
- **Today:** `iwlwifi`, `rtl88xx`, `bcm43xx` are chip-ID-probe-only
  shells (`wireless-drivers-v0.md`) with `firmware_pending=true`.
  The network flyout panel (`network-flyout-panel-v0.md`)
  honestly displays "no driver".
- **Expected:** open the flyout, pick an SSID, type a password,
  get DHCP.
- **Owners:** `kernel/drivers/net/wireless/`, plus a
  firmware-loader subsystem (does not exist).

### 5. Settings panel
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

### 6. Terminal emulator (userland shell)
- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
  `userland/shell/` is a stub ELF; no real shell binary.
- **Expected:** a windowed terminal app that runs commands as a
  user-mode process.
- **Owners:** `userland/shell/`, plus a PTY layer (does not exist).

### 7. Image / PDF / media viewers
- **Today:** none. `mini_browser` is a smoke test, not a default
  browser app (`mini-browser-runs-on-duetos-v0.md`).
- **Expected:** image viewer (PNG/JPEG), PDF reader, audio/video
  player. Likely Win32 PE apps once GDI/D3D acceleration improves,
  or native kernel-resident apps.
- **Owners:** new `kernel/apps/imgview.{h,cpp}` etc., or PE apps
  installed under `userland/apps/`.

### 8. Clipboard + drag-and-drop wired into apps
- **Today:** clipboard smoke tests exist; no kernel app uses the
  surface.
- **Expected:** Ctrl+C in Notes, Ctrl+V in another window or in
  the kernel shell.
- **Owners:** `kernel/apps/notes.cpp` and clipboard syscall hookup.

### 9. Screenshot tool
- **Today:** none. PrintScreen is unbound.
- **Expected:** PrtSc captures the framebuffer to a file in
  `/disk/screenshots/`.
- **Owners:** new `kernel/apps/screenshot.{h,cpp}` + framebuffer
  reader (already used by gfxdemo).

### 10. Lock screen / screensaver
- **Today:** none. Single hardcoded `admin/admin` + `guest`
  credentials in `kernel/core/main.cpp`.
- **Expected:** screen locks after idle, or on Win+L.
- **Owners:** `kernel/security/auth*`, plus an idle-timer hook.

### 11. Account management
- **Today:** hardcoded credentials in `kernel/core/main.cpp`. No
  account creation / password change / multi-user switch.
- **Expected:** a Users panel (under Settings) — add user, change
  password, switch active session.
- **Owners:** `kernel/security/auth*`, `kernel/proc/process.cpp`
  (uid/gid model does not exist).

## P2 — system-wide expectations (day-two, or first contact with real hardware)

### 12. Multi-monitor / runtime resolution change
- **Today:** single linear framebuffer; mode set at boot via Bochs
  VBE; no EDID parse; no hot-plug detect.
- **Expected:** plug HDMI, get a second screen; change resolution
  from Settings.
- **Owners:** `kernel/drivers/gpu/` (per-vendor BAR programming,
  EDID), framebuffer driver layout.

### 13. Brightness / volume hotkeys
- **Today:** no backlight driver, no audio output → Fn-keys are
  dead.
- **Expected:** laptop brightness keys dim the panel; volume keys
  change a master mixer.
- **Owners:** ACPI EC driver (does not exist) + audio mixer.

### 14. Battery + power management
- **Today:** `kernel/drivers/power/power.cpp:36` flags
  `backend_is_stub = true`. ACPI battery state is "unknown" — no
  AML interpreter, no EC query. No suspend/resume.
- **Expected:** battery icon in tray, sleep on lid close, S3
  resume.
- **Owners:** `kernel/drivers/power/`, `kernel/acpi/` (AML).

### 15. Software install / app discovery
- **Today:** apps ship inside the kernel ISO. No external install
  path.
- **Expected:** a way to add apps without recompiling — even a
  basic "drop a PE in /disk/apps/, see it in Start".
- **Owners:** Start-menu enumeration over `/disk/apps/`, plus a
  package format. Neither exists.

### 16. Disk installer
- **Today:** boots from ISO only. Live system; no install.
- **Expected:** an installer app that lays down DuetOS on an NVMe
  partition and boots from disk next time.
- **Owners:** new installer; depends on FAT32 write + GPT write +
  bootloader copy.

### 17. System updater
- **Today:** none. No A/B kernel slots, no kexec, no signed-update
  path.
- **Expected:** a "check for updates" surface, ideally with
  rollback.
- **Owners:** boot/, plus a network-fetch + verify pipeline.

### 18. Bluetooth
- **Today:** no host-controller driver, no stack.
- **Expected:** pair a mouse, keyboard, headset, or phone.
- **Owners:** new `kernel/drivers/bluetooth/`.

### 19. Printer
- **Today:** no USB printer class, no IPP client.
- **Expected:** print a text file from Notes.
- **Owners:** `kernel/drivers/usb/class/printer.cpp` (does not
  exist) + a print-spooler service.

### 20. Webcam
- **Today:** UVC class enumerated in `kernel/drivers/usb/usb.h` but
  no driver.
- **Expected:** a Camera app shows live frames; video calls work.
- **Owners:** `kernel/drivers/usb/class/uvc.cpp` (does not exist).

## P3 — accessibility, locale, and quality-of-life

### 21. Accessibility stack
- **Today:** HighContrast theme exists (WCAG AAA palette per
  `desktop-chrome-polish-v0.md`); nothing else.
- **Expected:** screen reader, magnifier, on-screen keyboard,
  large-text mode beyond a single theme.
- **Owners:** new accessibility service.

### 22. IME / non-Latin input
- **Today:** US keyboard layout hardcoded in PS/2 + xHCI HID
  drivers.
- **Expected:** keyboard-layout switcher, IME for CJK.
- **Owners:** input subsystem.

### 23. Time zone + DST
- **Today:** all times UTC; no zoneinfo. RTC read at boot.
  `clock_settime` honored (cap-gated) per `subsystems-status.md`.
- **Expected:** Settings → Time & Region picks a zone.
- **Owners:** `kernel/time/`, plus a zoneinfo data file.

### 24. Locale / language switching
- **Today:** UI strings hardcoded English in kernel C++ literals.
- **Expected:** Settings → Language switches the desktop.
- **Owners:** every kernel app (`kernel/apps/*.cpp`) — a string
  table layer needed first.

### 25. Notifications
- **Today:** apps can write to taskbar tabs; no notification
  surface.
- **Expected:** a transient toast in the corner ("file saved",
  "battery low").
- **Owners:** new compositor surface in `kernel/drivers/video/`.

### 26. Persistent log viewer / crash report UI
- **Today:** klog ring lives in RAM and is lost on reboot
  (`klog-overhaul.md`); panic dumps go to serial. Log Viewer app
  shows the live ring.
- **Expected:** a `journalctl`-style history that survives reboot;
  a crash-report dialog that points at the dump.
- **Owners:** `kernel/log/`, `kernel/diag/crash-dump`, plus FS
  persistence for the ring.

### 27. Session restore
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
