# End-user feature gaps v0

_Type: Observation + Decision (gap inventory)._
_Last updated: 2026-05-01._

## Status — landed slices

| Date | Item | Effect |
|------|------|--------|
| 2026-05-01 | P2 #12 EDID parser (one of the three blockers) | `kernel/drivers/gpu/edid.{h,cpp}` — clean-room VESA E-EDID 1.3/1.4 base-block parser + `edid_selftest.cpp` 5-fixture boot self-test (1080p digital + analog 1024 + bad-checksum + short-buffer + bad-header) + `monitor` shell command. Pure compute, no DMA, no DDC dependency. Caught a `refresh_mhz` unit bug while landing (formula was missing a factor of 1000; host-side test fixture asserted `>= 59900 && <= 60100` for a 60.000 Hz mode and rejected the 60-Hz integer truncation). See `.claude/knowledge/edid-parser-v0.md`. |
| 2026-05-01 | P0 #4 Wi-Fi loopback test + host fuzz harness (verifies the previously-HW-only-testable control tier) | `kernel/net/wireless/test/{fake_ap,loopback_driver,wireless_e2e_test}.{h,cpp}` — software AP peer + fake `WirelessDeviceOps` driver + 4-case boot self-test. **Success case asserts TK and GTK match byte-for-byte between AP and STA endpoints** (proves PRF / nonces / PMK / MAC ordering all agree across both sides of the handshake). Wrong-PSK rejection, replay-counter rejection, MIC-tamper rejection. **Bugs caught while landing this slice:** (1) PBKDF2 KAT had wrong reference value (kernel impl was correct; test fixture was wrong); (2) `WirelessDeliverEapol` never sent M2/M4 — fixed by adding `SendEapolFrame` op + auto-build paths in wdev. Also `tests/fuzz/` — standalone Makefile + `host_shim/` + 5 libFuzzer drivers (beacon, eapol, iwl_fw, rtl_fw, bcm_fw) under ASan+UBSan. ~95M total executions in ~225s, **zero crashes**. See `.claude/knowledge/wireless-loopback-and-fuzz-v0.md`. |
| 2026-05-01 | P0 #4 Wi-Fi control tier (Phases 2/4/5/6/7 — HW-untested) | Full wireless control tier: `kernel/net/wireless/wifi_diag.{h,cpp}` (512-event diag ring, panic-dumped, exposed via `wifi diag` shell command) + crypto primitives (`crypto/sha1.cpp` SHA-1, `sha256.cpp` SHA-256, `hmac.cpp` HMAC-SHA1/SHA256, `pbkdf2.cpp` PBKDF2-WPA, `prf.cpp` 802.11 PRF + KDF-SHA256, all KAT-verified at boot) + `eapol.{h,cpp}` (EAPOL-Key frame parse/build/MIC patch/MIC verify) + `fourway.{h,cpp}` (WPA2 4-way handshake state machine — PMK→PTK derivation, M1/M3 processing, M2/M4 build, GTK KDE extraction, replay-counter validation; full handshake KAT-tested with synthetic AP) + `wdev.{h,cpp}` (cfg80211-equivalent WirelessDevice + ops vtable, scan-result dedupe, key-install dispatch on M3) + `mlme.{h,cpp}` (auth/assoc/deauth frame builders + MlmeConnect/Disconnect/ScanAndWait flow + default RSN IE) + per-vendor upload state machines (`iwlwifi_upload.{h,cpp}` Intel CSR reset → NicInit → section walk → ALIVE wait, `rtl88xx_upload.{h,cpp}` Realtek FWDL → page write → CHKSUM_RPT → H2C_INIT, `bcm43xx_upload.{h,cpp}` Broadcom stop-MAC → SHM upload → start-ucode) + `iwlwifi_rings.{h,cpp}` (TFD/RBD ring scaffolds). 13 new boot self-tests gated by `DUETOS_BOOT_SELFTESTS`; every register write + every state transition recorded to wifi-diag ring; ring dumped from panic handler. **HW runtime untested** — every per-vendor section-copy short-circuits to `Unsupported` until DMA-coherent allocation lands. See `.claude/knowledge/wireless-control-tier-v0.md`. |
| 2026-05-01 | P0 #4 Wi-Fi Phase 3 — 802.11 frame headers + beacon parser | `kernel/net/wireless/ieee80211.h` (frame-control bits, type/subtype enums, capability bits, 35 IE IDs + 4 ID extensions, 12 cipher suites, 12 AKM suites, OUI helpers) + `kernel/net/wireless/beacon.{h,cpp}` (`BeaconParse` walker producing `BeaconParsed` with SSID / channel / capability / supported-rate / RSN-cipher-AKM views, security-taxonomy derivation across Open / WEP / WPA / WPA2 / WPA3 / Wpa2Ent / Wpa3Ent). Boot self-test exercises 5 frame variants: positive WPA2-PSK on channel 6, data-frame rejection, short-frame rejection, hidden-SSID handling, WPA3-SAE classification. See `.claude/knowledge/ieee80211-beacon-parser-v0.md`. |
| 2026-05-01 | P0 #4 Wi-Fi Phase 1b — rtl88xx + bcm43xx envelope parsers | `kernel/drivers/net/rtl88xx_fw.{h,cpp}` (rtlwifi/rtw88/rtw89 32-byte header walker + signature classification covering 8192c/8192d/8723b/8723d/8821/8812/8814/8822b/8852a + tolerant ramcodesize bytes-vs-kbytes detection) + `kernel/drivers/net/bcm43xx_fw.{h,cpp}` (b43 record-stream walker — `'u'`/`'p'`/`'i'` types with 8-byte big-endian header + bounded 8-record table + truncation handling). Both wired into respective BringUp paths: parse on FwLoad hit, set `Ready` on success / `Incompatible` on parse failure. Boot self-tests cover positive cases for each silicon family + bad-signature/bad-type/short-header/length-overflow negative cases. See `.claude/knowledge/wireless-fw-parsers-v0.md`. |
| 2026-05-01 | P0 #4 Wi-Fi (parser half of firmware-loader blocker) | `kernel/drivers/net/iwlwifi_fw.{h,cpp}` — TLV walker for the Intel iwlwifi microcode envelope (zero/magic preamble validation, 64-byte name, ver/build, INST/DATA/INIT/INIT_DATA/SEC_RT/SecureSecRt section capture, FLAGS/NUM_OF_CPU/FW_VERSION/PHY_SKU/HW_TYPE scalar capture, length-overflow bounds check). Wired into `IwlwifiBringUp` so a blob loaded via `FwLoad` is parsed in-place: structurally valid → `wireless_fw_state=Ready`, malformed → `Incompatible` (instead of the old "drop and continue in fw-pending"). Boot self-test (`IwlFirmwareSelfTest`) builds a synthetic 7-record TLV blob in 384 bytes and asserts every recognised field round-trips, plus 3 negative cases (bad magic, truncated header, length overflow). Format spec adapted clean-room from documented Intel ABI (also visible in Linux `iwl-drv.c` and OpenIntelWireless/itlwm). **Microcode upload + 802.11 MLME still deferred** — this slice closes only the parser half of the blocker. See `.claude/knowledge/iwl-fw-tlv-parser-v0.md` for the full rationale + edge-case list. |
| 2026-05-01 | P0 #5 Settings panel | `kernel/apps/settings.{h,cpp}` — theme prev/next/HighContrast/Default, opacity ±, TZ ±, LOG OUT, plus a readout pane (theme name, opacity, UTC + LOCAL clocks, TZ offset, user list). Reachable via Start menu and `t/h/-/+/0` keys. New `ThemeRole::Settings`; every theme palette extended. |
| 2026-05-01 | P3 #25 Notifications | `kernel/drivers/video/notify.{h,cpp}` — single-slot toast painted bottom-right above the taskbar, decays on the 1 Hz compose tick. Public API: `NotifyShow(text)`, `NotifyShowFor(text, ttl_ticks)`. Wired into theme-cycle hotkeys, Notes copy/paste, lock-screen, magnifier toggle. |
| 2026-05-01 | P1 #10 Lock screen | Ctrl+Alt+K reopens the GUI login gate via `AuthLogout` + `LoginStart(Gui)`. Bound separately from Ctrl+Alt+L (taskbar drag-lock) so existing chord muscle memory is intact. |
| 2026-05-01 | P1 #8 Clipboard wired into Notes | `NotesCopyToClipboard` / `NotesPasteFromClipboard` use the existing kernel clipboard (`WindowClipboardSetText`, exposed to Win32 PEs via OpenClipboard). Bound to Ctrl+C / Ctrl+V; Ctrl+C falls through to ShellInterrupt when Notes isn't focused. |
| 2026-05-01 | P1 #11 Account management | Settings panel grew a `USERS:` readout listing every account (name + role) and a `LOG OUT` button. Read-only for v0; mutations remain shell-command driven (`useradd`, `passwd`). |
| 2026-05-01 | P3 #23 Time zone | `kernel/time/timezone.{h,cpp}` — signed minutes offset ([-12 h, +14 h], 30-min steps). Settings shows UTC + LOCAL clocks and the live offset; TZ ± buttons step it. No zoneinfo, no DST, no persistence — documented limits. |
| 2026-05-01 | P3 #21 Accessibility (magnifier) | `kernel/drivers/video/magnifier.{h,cpp}` — Ctrl+Alt+M toggles a 200×150 inset at top-right showing 2× nearest-neighbour zoom around the cursor. Drops to bottom-right when cursor is in top-right quadrant so it never occludes its own source. Direct framebuffer reads via `FramebufferGet().virt`. |
| 2026-05-01 | P0 #1 Notes save / load | `kernel/apps/notes_persist.cpp` (new TU) + `kernel/apps/notes_internal.h` (private detail surface) — `NotesSave()` and `NotesLoad()` round-trip the live buffer through `Fat32CreateAtPath` / `Fat32DeleteAtPath` / `Fat32ReadFile` against `NOTES.TXT` on the FAT32 root volume. Wired to Ctrl+S / Ctrl+O when Notes is the active window (`kernel/core/main.cpp`). Boot self-test (`NotesPersistSelfTest`) runs after FAT32 probe and validates a save → load round-trip on a known marker. GAP: non-atomic save (delete-then-create); revisit when FS journaling lands. **The "blocked on FAT32 write" entry in this file was stale — the kernel-side write path was already complete; only app wiring was missing.** |
| 2026-05-01 | P1 #9 Screenshot | `kernel/apps/screenshot.{h,cpp}` — Ctrl+Alt+P captures the framebuffer to the next `SHOTNNNN.BMP` slot on the FAT32 root volume. 32-bpp top-down BMP (negative DIB height so source rows match framebuffer order, no flip pass). Streams in 64 KiB chunks via `Fat32CreateAtPath` (first) and `Fat32AppendAtPath` (rest) — kernel heap is too small to buffer a full 1024×768 frame at once. Boot self-test exercises the BMP write path with a 4×4 synthetic gradient, verifies on-disk size, and deletes the test file. The deferred "tmpfs slot cap" entry in this file was the pre-FAT32-write design; with persistent storage live, that constraint no longer applies. |
| 2026-05-01 | P3 #26 Persistent log viewer | `kernel/log/klog_persist.{h,cpp}` — installs a FAT32 file sink that replaces the early tmpfs sink (single-slot API). On install: truncates `KERNEL.LOG`, replays the log ring through the new writer (so the file captures pre-install Info+ history), then forwards every Info+ line as it arrives. 4 KiB scratch buffer + half-full flush threshold so the FAT mirror isn't beat per-line. The 1 Hz `ui-ticker` calls `KlogPersistFlush()` so a long-uptime log stays current within a second. New shell command `dmesg f` streams `KERNEL.LOG` through `Fat32ReadFileStream`. GAP: each boot truncates the file (no cross-boot rotation yet). Re-entrancy guard drops log lines emitted from inside `Fat32AppendAtPath` rather than recursing. |
| 2026-05-01 | P3 #27 Session restore | `kernel/core/session_restore.{h,cpp}` — round-trips theme + per-app window positions through `SESSION.CFG` on the FAT32 root. Plain ASCII `key=value\n` payload (≤ 1 KiB) so it's hand-readable from `dmesg f` style streaming. `SessionRestoreApply()` runs once after FAT32 probe and applies `ThemeSet` + `WindowMoveTo` for every recognised line; missing file = first-boot path, no-op. `SessionRestoreSave()` snapshots current state and writes if (and only if) the formatted payload differs byte-for-byte from the last successful save — so the 1 Hz autosave from the ui-ticker idles silently when nothing has changed. Wired into the three logout paths: shell `logout`, Settings → Log Out, Ctrl+Alt+K screen lock. Self-test exercises the parser end-to-end without touching the on-disk file (synthetic theme + window position, restored before exit). |
| 2026-05-01 | P2 #15 Start-menu /APPS enumeration | `kernel/drivers/video/start_menu_apps.{h,cpp}` — at boot, ensures `/APPS` exists on the FAT32 root, plants `APPS/SAMPLE.MNF` as a copy-paste template, then enumerates `APPS/*.MNF` shortcut manifests. Each manifest is `name=<label>\ntarget=<role>\n`; recognised targets are the eight ThemeRoles (calculator/notes/files/clock/settings/gfxdemo/taskmanager/logview). Discovered shortcuts are appended to the Start menu between the builtin items and the trailing help/cycle/about block. Action-id range 200..215 dispatches through `StartMenuAppsResolve` to the same window-raise path as builtin items. The loader runtime gate stays in place: real PE/ELF launching requires the loader, so v0 only honours role aliases — that's the "package manifest format" half of the original blocker, with the "PE/ELF launcher" half deferred to when the runtime lands. Self-test parses a synthetic manifest in memory and asserts the role round-trips. |

## Status — blocked on infrastructure

These items have a real user-visible gap, but a meaningful
implementation is gated on driver / firmware / protocol work
that the gap entry alone can't unblock. Listed with the blocker
so a future slice that lands the prerequisite knows to come back
and finish the user-facing tier.

| Item | Blocker | What lands when the blocker is gone |
|------|---------|------------------------------------|
| P0 #2 Audio output | Intel HDA codec discovery + CORB/RIRB stream programming (probe-only today; `kernel/drivers/audio/audio.cpp:43`) | Settings volume slider, system beep/chime on notifications, WAV / OGG playback app |
| P0 #4 Wi-Fi connect-to-SSID | Real-hardware verification cycles + DMA-coherent allocation API (`mm::AllocDmaCoherent` does not exist) + AES key wrap (RFC 3394) for encrypted M3 key data + IRQ wiring on per-vendor MSI/MSI-X. Data-decode tier (envelope parsers + beacon walker) AND control tier (crypto + EAPOL + 4-way handshake + wdev/MLME + per-vendor upload + ring scaffolds) all landed 2026-05-01. Every code path that depends on DMA short-circuits to `Unsupported` and records the intent in the wifi-diag ring | Network flyout SSID picker, Settings → Network → Wi-Fi tab, captive-portal handler |
| P2 #12 Multi-monitor / resolution change | Per-vendor GPU drivers (Intel/AMD/NVIDIA all probe-only per `render-drivers-v6.md`); ~~EDID parser~~ (landed 2026-05-01 — `kernel/drivers/gpu/edid.{h,cpp}` + 5-fixture boot self-test + `monitor` shell command, see `edid-parser-v0.md`); mode-set negotiation | Settings → Display tab with resolution / refresh-rate / monitor layout |
| P2 #13 Brightness | ACPI EC driver (does not exist) + per-vendor backlight register paths | Settings brightness slider; Fn-key brightness hotkeys |
| P2 #14 Battery + ACPI suspend | ACPI AML interpreter (only static tables parsed today); EC battery status registers; S3 / S0ix wake plumbing | Battery icon in tray, Settings → Power, lid-close suspend |
| P2 #15 PE/ELF launching from /APPS | The /APPS *.MNF enumeration landed; what's still missing is the loader runtime so a manifest with `kind=pe path=APPS/foo.exe` can actually launch a binary | Click an /APPS entry → load + run a PE32+ executable |
| P2 #16 Disk installer | GPT write (`kernel/fs/gpt.cpp` is probe-only) + FAT32 mkfs (no equivalent of `make-gpt-image.py`'s BPB-laydown logic in the kernel yet) + bootloader copy. Plan + verification ladder + risk notes captured in `.claude/knowledge/disk-installer-plan.md`. | Installer app that lays DuetOS down on an NVMe partition |
| P2 #17 System updater | Code-signing infrastructure + A/B kernel-slot layout | "Check for updates" surface; rollback |
| P2 #18 Bluetooth | Host-controller (HCI) driver + L2CAP / RFCOMM / GATT stack | Pair mouse / keyboard / headset / phone |
| P2 #19 Printer | USB printer class driver + IPP / PostScript / raster pipeline | Print from Notes |
| P2 #20 Webcam | UVC USB-Video class driver | Camera app, video calls |

## Status — deferred

These are tractable but each one is the "wrong size" for a
single-session slice. Listed so a future block of work can
schedule them.

| Item | Reason | Rough effort |
|------|--------|--------------|
| P0 #3 USB mouse | xHCI HID class needs report-descriptor parsing for mouse-class endpoints; the keyboard-class path landed in `xhci-hid-keyboard-v0.md` and is the template. No QEMU emulation of USB mouse — has to be tested on physical HW post-merge. | 200-300 LOC |
| P1 #6 Terminal emulator | Kernel shell is wired to a single global console (ConsoleWrite). A windowed terminal needs a console-multiplex refactor so the shell takes a per-session sink. | Multi-session refactor |
| P1 #7 Image / PDF / media viewers | Each format needs its own parser + frame loop. Image viewer is the smallest (PNG / BMP, ~500 LOC each). PDF is huge. Audio / video need P0 #2 first. | One-per-format |
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

### 4. Wi-Fi connect-to-SSID [PARTIAL — data-decode tier complete 2026-05-01; control tier still missing (real-HW gated)]
- **Today:** `iwlwifi`, `rtl88xx`, `bcm43xx` are chip-ID-probe-only
  shells (`wireless-drivers-v0.md`); each calls
  `core::FwLoad(...)` against the VFS-backed firmware loader
  scaffold. When a blob IS present, the matching driver parses
  it in-place via the per-vendor envelope parser:
    - iwlwifi: `IwlFirmwareParse` (TLV walker — see
      `iwl-fw-tlv-parser-v0.md`).
    - rtl88xx: `RtlFirmwareParse` (rtlwifi/rtw88/rtw89 32-byte
      header — see `wireless-fw-parsers-v0.md`).
    - bcm43xx: `BcmFirmwareParse` (b43 record stream — see
      `wireless-fw-parsers-v0.md`).
  The 802.11 frame-decode tier also landed: `kernel/net/wireless/`
  carries `ieee80211.h` (frame-control bits, type/subtype, IE
  IDs, cipher / AKM suites) + `beacon.{h,cpp}` (`BeaconParse`
  produces a `BeaconParsed` view with SSID, channel, RSN-derived
  security taxonomy, supported rates). Self-tests for all four
  parsers run at boot.
- **Still missing (gated on real hardware):** Microcode upload
  to the chip (per-silicon `CSR_RESET` / `CSR_GP_CNTRL.MAC_INIT`,
  secure-boot handshake, INST + DATA + SEC_RT copy into
  FW_LOAD_BUFFER, ALIVE wait). TX/RX ring setup per vendor
  (TFD/RBD for iwlwifi, descriptor rings for rtl88xx, DMA64
  for bcm43xx). 802.11 MLME state machine (scan transmission,
  authentication, association, EAPOL 4-way handshake with
  PTK/GTK derivation, key install via vendor MIC API). RX
  bottom-half that delivers received beacons / probe-responses
  to `BeaconParse`. UI integration — flyout SSID picker,
  Settings → Network → Wi-Fi tab, captive-portal handler.
- **Expected:** open the flyout, pick an SSID, type a password,
  get DHCP.
- **Owners:** `kernel/drivers/net/wireless/` (per-vendor upload +
  ring setup), `kernel/net/wireless/` (MLME state machine),
  `kernel/net/wifi.{h,cpp}` (cfg80211-equivalent registration),
  plus a real firmware-blob distribution channel (today
  `/lib/firmware` is a ramfs node — that's fine for dev,
  needs FAT32-mount support for shipping installs).

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

### 9. Screenshot tool [LANDED 2026-05-01]
- **Today:** Ctrl+Alt+P captures the framebuffer to the next
  available `SHOTNNNN.BMP` on the FAT32 root volume.
  Implementation in `kernel/apps/screenshot.{h,cpp}`. 32-bpp
  top-down BMP (negative DIB height so source rows match
  framebuffer order with no flip pass). Streams in 64 KiB
  chunks via `Fat32CreateAtPath` then `Fat32AppendAtPath` —
  the 2 MiB kernel heap is too small to buffer a full 1024×768
  frame at once. Boot self-test exercises the BMP write path
  with a 4×4 synthetic gradient.
- **Still missing:** No region-select / window-only capture.
  No annotation. No clipboard handoff. PNG output (BMP is
  ~3 MiB at 1024×768 vs ~150 KiB PNG-compressed) is gated on
  a zlib port — currently DuetOS doesn't have one.
- **Owners:** `kernel/apps/screenshot.{h,cpp}` for region
  capture + window mode; new `userland/libs/zlib*` for PNG.

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
