# End-user feature gaps v0

_Type: Observation + Decision (gap inventory)._
_Last updated: 2026-05-03._

## Status — landed slices

| Date | Item | Effect |
|------|------|--------|
| 2026-05-03 | P3 (new) Notes status footer + Calculator memory ops | Two coupled QOL slices in one batch. **(1) Notes status footer** — `kernel/apps/notes.{cpp}` + `notes_internal.h` + `notes_persist.cpp`. New `detail::g_dirty` flag flipped true on every mutation (`InsertAtCursor` / `DeleteAtCursor` / `BackspaceAtCursor`), cleared on successful `NotesSave` / `NotesLoad{File}` round-trip. Boot greeting in `NotesInit` resets the flag so the desktop comes up "clean". `DrawFn` reserves one glyph row + 2px separator at the bottom of the client area for a status band painted in `kStatusBg = 0x00C8C8B8`; format is `L:line/total  C:col  CHARS:NN  WORDS:NN` with logical (newline-delimited, NOT wrap-aware) line + col counts both 1-indexed, plus a right-aligned `*MOD` tag in red (`0x00B82020`) when dirty. New helpers: `LogicalCursor` (Zeller-style walk to current cursor index), `LogicalLineCount` (newline + 1, matches VS Code/vim convention), `WordCount` (whitespace-delimited maximal-run counter — space/tab/newline all count as separators). `AppendStr` / `AppendU32` are bounded sprintf-style formatters for the footer string. Self-test extended with 6 new checks: dirty starts false on a fresh test buffer, dirty true after edits, LogicalCursor 1:5 at the right index, LogicalLineCount = 2 for "abZc\nef", WordCount = 2 there + stays 2 after typing whitespace + bumps to 3 on a non-ws after ws. **(2) Calculator memory** — `kernel/apps/calculator.cpp`. `State` grew `i64 memory; bool memory_set` + 5 new keys: `m`/`M` MR (memory recall, pulls register into display, sets fresh_entry), `s`/`S` MS (display → memory), `l`/`L` MC (zero + drop indicator), `a`/`A` M+ (memory += display), `b`/`B` M- (memory -= display). `HandleClear` does NOT touch memory — only `MC` clears it, matching every physical bank calculator. `DrawFn` paints a small amber `M` indicator at the top-left of the display strip when memory is set + non-zero (skipped on zero so a stored-zero doesn't visually clutter). `CalculatorFeedChar` gate extended to accept the 10 new key codes. Self-test extended with a memory-ops walk: 50 MS → memory=50, C 25 A → memory=75, C 10 B → memory=65, m → display=65, l → memory_set false, m after MC is no-op (display unchanged at 65). Closes the user-visible "Notes has no edit-state cue" gap and the "Calculator has no memory register" gap in one slice. **Note**: notes.cpp is now ~705 LOC, calculator.cpp ~694 LOC — both over the 500-line guideline but each TU is one cohesive concern (one editor, one calculator). Logical splits exist (notes_input.cpp / notes_paint.cpp; calculator_arith.cpp / calculator_memory.cpp) but are deferred until a third concern lands per the bloat checklist. |
| 2026-05-03 | P3 (new) Calendar app + clipboard-history ring | Two coupled QOL slices in one batch. **(1) Calendar app** — new `kernel/apps/calendar.{h,cpp}` (~490 LOC). Windowed month-view sibling of the read-only `drivers/video/calendar` taskbar-clock popup. Bindings: `[`/`]` or Left/Right step a month, `{`/`}` or Up/Down step a year, `T` jumps back to today. The view tracks the live RTC until the user navigates; once they do, it stays where they left it (re-entering RTC tracking on `T`). Today's cell is highlighted with the theme accent, current-month weekends carry a faint inactive-tab tint, days from neighbouring months render dimmed. Year clamped to [1, 9999] so the navigation can't overflow. New `ThemeRole::Calendar = 12`, `kCount = 13`; all 10 theme palettes extended (info-panel family — same hex as Browser/About/Help across every theme). Start-menu `CALENDAR` entry; `start_menu_apps.cpp` accepts `target=calendar` / `cal`. Self-test exercises Zeller's-congruence weekday round-trip (Fri 2026-05-01, Sat 2000-01-01, Thu 2024-02-29), `DaysInMonth` with all four leap-year rules (4-yes, 100-no, 400-yes, default-no), and `Step` navigation across year boundaries + the [1, 9999] clamps. **(2) Clipboard history ring** — `kernel/drivers/video/widget.{h,cpp}` extended with an 8-entry ring (`kWindowClipboardHistoryDepth = 8`). `WindowClipboardSetText` snapshots the previous payload and pushes it onto the ring front before overwriting (deduped — identical-set is a no-op). New `WindowClipboardHistoryCount` / `WindowClipboardHistoryGet` / `WindowClipboardHistoryRotate` accessors. **Ctrl+Shift+V** in `main.cpp`'s key dispatch rotates the ring (active ↔ ring[0]; remaining shift down) so the user steps backwards through recent clips; toast shows a 40-char preview of the new active, with `clip history empty` when the ring has no entries. The handler runs before the bare Ctrl+V Notes-paste branch so the modifier combo is claimed. Help text + Help window's row table refreshed for the new binding; `PrintShortcutHelp` learns `CTRL+SHIFT+V`. Closes the "Notes paste only ever sees the last copy" gap. **Hard limit still in place**: ring entries cap at `kWindowClipboardMax` (1024 bytes) per slot — same as the active clipboard; long captures truncate identically. **Browser streaming download deferred** — needs a state machine to chunk HTTP body to disk during fetch; safer once QEMU testing is wired up. |
| 2026-05-02 | P0 (new) Basic browser + buffer-cap lift | New `kernel/apps/browser.{h,cpp}` — minimal HTTP-only browser. URL bar + four modes (View / UrlEdit / History / Bookmarks). HTML stripper drops tags + decodes entities (`&amp;` `&lt;` `&gt;` `&quot;` `&apos;` `&nbsp;` + numeric `&#NN;` / `&#xHH;`) + skips `<script>` content + emits newlines on block-level closes. History (32-deep ring with Chrome-style truncate-on-fork-back), bookmarks persisted to FAT32 `BOOKMARK.TXT` (load on first L, save after every mutation), Save (S) writes the body to next-free `DLNNNN.HTM` slot. Each fetch spawns a one-shot kernel task via `SchedCreate` so the input thread stays responsive while DNS + TCP run with timeout. **Buffer-cap lifts (in-tree API limitations the user asked to extend):** `net/stack.h` `kTcpActiveBufBytes` 2048 → **65536** so real HTML pages fit (most home pages are ~30 KiB), `kTcpMaxCannedReply` 512 → **4096** so HTTP requests with cookies / long URLs / additional headers fit. `net/socket.h` `kSocketTcpRxBufBytes` mirror updated. `fs/fat32_create.cpp` `kRenameBounceMax` 64 KiB → **256 KiB** so mid-size renames don't fall back to streaming. Browser scratch buffer (64 KiB) + bookmark serialize/parse buffers heap-allocated via KMalloc to keep the kernel stack small. `BookmarkContains` skips duplicate bookmark insertion. Self-test exercises URL parse (4 forms incl. https reject), dotted-quad parser (positive + 3 negative), HTML strip (entity decode + block break + script-content drop). New `ThemeRole::Browser = 11`, `kCount = 12`; all 10 themes extended. Help text + Help window's row table refreshed for the new bindings. **Hard limit still in place**: HTTPS not supported (no TLS); v0 strictly HTTP-GET. The 64 KiB single-slot TCP buffer covers most pages but downloading binaries larger than 64 KiB still truncates — full streaming download is the next slice. **Note**: `browser.cpp` is ~1400 LOC, well over the 500-line guideline. Single TU now; logical split candidates are `browser_url.cpp` (parse + dotted-quad), `browser_html.cpp` (strip + entities), `browser_net.cpp` (DNS + HTTP + worker), `browser_persist.cpp` (bookmarks + download), `browser_ui.cpp` (paint + dispatch). Deferred until a fifth concern lands. |
| 2026-05-02 | P0 (new) Trash bin + Files defaults to disk view | New `kernel/apps/trash.{h,cpp}` — Recycle-Bin tier on `/TRASH/`. Five primitives: `TrashEnsureDir` (lazy mkdir), `TrashMove(name)` (streaming copy via `Fat32ReadFileStream` + `Fat32CreateAtPath` + `Fat32AppendAtPath`, then source delete; falls back to `Fat32RenameAtPath` for files ≤64 KiB), `TrashRestore(name)` (reverse path), `TrashPermDelete(name)` (just `Fat32DeleteAtPath` on the trash entry), `TrashEmpty` (walk + delete every regular file). Streaming was required because screenshots (~3 MiB) exceed `kRenameBounceMax` (64 KiB); without it screenshots couldn't be trashed. Files app refactored: 3rd Mode (Trash) alongside Ramfs/Fat32, generalized Pending state machine (DeleteToTrash / PermDeleteFromTrash / EmptyTrash) replacing the single-purpose `delete_armed` boolean, new T toggle for trash view, R in trash view restores instead of rescans, E-then-Y empties the bin. Disk view's X-then-Y now SOFT-deletes (move to trash) instead of permanent delete — user has a recovery path. Default mode promoted to Fat32 disk view via new `FilesPromoteToDisk()` called from main.cpp after `Fat32Probe` (FilesInit runs before storage is up, so Init alone can't see the volume). TRASH directory hidden from the Fat32 view's listing so users reach it through T. Help text + Help window's row table refreshed for D/M/T/R/X/E bindings. Trash boot self-test plants a synthetic file, moves it to trash, verifies absence in root + presence in trash, restores it, byte-compares the restored content against the original payload, then re-trashes + perm-deletes. Closes the user-visible "delete is final" gap and the "Files only shows ramfs by default" gap in one batch. |
| 2026-05-02 | P3 (new) Help window + Calculator polish + git hash in About | Three small slices in one batch. (1) New `kernel/apps/help.{h,cpp}` — windowed shortcut reference paralleling About. Static row table grouped by section header (`is_section` flag flips the painter to the dim banner colour). F1 + Start-menu HELP both raise it AND keep the existing `PrintShortcutHelp` console output (window for discovery, console for scrollback). New `ThemeRole::Help = 10`, `kCount = 11`; all 10 themes extended (shares About's panel hue across every theme). `start_menu_apps.cpp` accepts `target=help` / `shortcuts`. Self-test asserts every section header is followed by at least one binding row. (2) `kernel/apps/calculator.cpp` grew three keyboard-only operators: `%` (with-pending-op uses bank-calculator `lhs * rhs / 100` semantics, no-pending-op divides display by 100), `n` / `N` / `_` (sign toggle), Backspace (pop last digit; clears display when fresh-entry). Self-test extended with 6 new cases covering all three. The legacy Backspace→Clear shim removed. (3) `CMakeLists.txt` captures `git rev-parse --short=10 HEAD` at configure time, appends `+` if the working tree is dirty, exposes via `DUETOS_GIT_HASH` define. About panel grew a `COMMIT:` row showing it. Falls back to `unknown` outside a git checkout. About window height bumped 200px → 220px to fit the new row. |
| 2026-05-02 | P3 (new) About / System Info window + help-text refresh | New `kernel/apps/about.{h,cpp}` — windowed system-info readout: build banner + flags (DEBUG/RELEASE + KASLR + ASSERT), uptime via `time::TickCount()` / `time::TickHz()` (HH:MM:SS, capped at 99:59:59), active theme name, framebuffer resolution + bpp, FAT32 mount status + root entry count, kernel-heap stats (used / free / pool, alloc / free / fragmentation counters), live window count vs total slots. Refreshes on every compositor tick so uptime + heap counters update visibly. New `ThemeRole::About = 9`, `kCount = 10`; all 10 themes' `role_title` + `role_client` extended. Start-menu `ABOUT` entry now raises this window instead of printing two console lines (action 1 dispatch updated; falls back to console if window registration somehow fails). `start_menu_apps.cpp` accepts `target=about` / `sysinfo` in /APPS/*.MNF. Self-test exercises u64-decimal, byte-suffix tier picker (B / KiB / MiB / GiB boundaries), uptime HH:MM:SS round-trip + cap + hz==0 sentinel. Help-text in `kernel/core/main.cpp::PrintShortcutHelp` refreshed to cover all bindings landed since the last update: Files D / M / R / X-then-Y, ImageView N / P / Left / Right / R, Settings REBOOT / SHUTDOWN / TZ / LOG OUT, Ctrl+Alt+M (magnifier), Ctrl+Alt+K (lock screen). Closes the "ABOUT prints two lines to a console nobody reads" gap and the "help text rotted as new bindings landed" gap in one slice. |
| 2026-05-02 | P0 #5 Settings — SHUTDOWN + REBOOT buttons | `kernel/apps/settings.{h,cpp}` grew two new buttons: `REBOOT` (calls `core::KernelReboot()` after `SessionRestoreSave()`) and `SHUTDOWN` (calls `acpi::AcpiShutdown()`, falls through to `arch::Halt()` on QEMU TCG where S5 isn't honoured). Both flush the session-restore payload to `SESSION.CFG` first so the next boot lands in the same layout. `kIdCount` bumped 9→11; Settings window grew 280px→340px to fit the column. Closes the user-visible "no clean exit from the desktop" gap — previously power off required dropping to the kernel shell. |
| 2026-05-02 | P0 #1 Files — X-then-Y delete + .TXT→Notes dispatch | `kernel/apps/files.cpp` extended the FAT32 disk view with file mutation: `X` arms a delete prompt for the selected file, `Y` confirms (calls `Fat32DeleteAtPath` + rescan + selection clamp), any other key cancels. Footer hint switches to `DELETE <name>? Y:CONFIRM ANY:CANCEL` when armed. Navigation cancels a stale arm so an arrow keypress unambiguously disarms. Cross-app dispatch grew `.TXT` → Notes: `Enter` on a `.TXT` entry calls new `apps::notes::NotesLoadFile(path)` (a path-aware extraction of the existing NotesLoad helper) and raises the Notes window via `ThemeRoleWindow + WindowRaise`, mirroring the existing `.BMP` → ImageView pattern. Self-test exercises ext-match for `.TXT` / `.CFG` / negative cases plus the delete-armed-then-disarm-on-arrow round trip. **NOTE:** `files.cpp` is now 665 LOC, over the 500-line guideline; logically cohesive (all "file browser actions" sharing state) but a split into `files_ramfs.cpp` / `files_fat32.cpp` is defensible and should be reconsidered if a fifth concern lands. |
| 2026-05-02 | P1 #7 Files app — FAT32 disk view + cross-app .BMP open | `kernel/apps/files.cpp` extended with a second backend mode: existing ramfs view kept (default), new FAT32 root view toggleable via 'D' (disk) / 'M' (memory) keys. Header shows `RAM:/` or `DISK:/` so users always know where they are. Disk view enumerates the FAT32 root via `Fat32ListDirByCluster`, paints each entry with the same `[D]/[F]` row format as ramfs, supports rescan via 'R'. **Cross-app dispatch**: hitting Enter on a `.BMP` entry calls new `ImageViewSelectByName()`, raises the ImageView window via `ThemeRoleWindow(ImageView) + WindowRaise` — so user takes a screenshot, opens Files, switches to disk view, hits Enter on `SHOT0001.BMP` and the screenshot opens. Boot self-test exercises ramfs descend+back, mode toggle, and the extension-match helper used by the dispatch. Closes the "Files is read-only / FAT32 invisible" half of the P0 #1 follow-up. |
| 2026-05-02 | P1 #7 Image viewer (BMP) | `kernel/apps/imageview.{h,cpp}` — native kernel app reads 32-bpp uncompressed BMPs from the FAT32 root and paints them in a window. Pairs naturally with the Screenshot app: every `Ctrl+Alt+P` capture lands as a `SHOTNNNN.BMP` this viewer accepts byte-for-byte. Decode is streaming via `Fat32ReadFileStream` so a 1024×768 (~3 MiB) capture fits in the 2 MiB kernel heap; nearest-neighbour downsample with aspect-preserving fit, no upscale; both top-down (negative `biHeight`) and bottom-up DIBs supported. New `ThemeRole::ImageView` + 10-theme palette extension; Start menu entry "IMAGE VIEWER"; arrow Left/Right + N/P/R keybinds; boot self-test exercises the BMP header round-trip + aspect-fit math + magic / 24-bpp / sign-flip negative cases. 24-bpp / PNG / JPEG / subdir walk deferred. See `.claude/knowledge/imageview-bmp-v0.md`. |
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
| P0 #4 Wi-Fi connect-to-SSID | Real-hardware verification cycles + DMA-coherent allocation API (`mm::AllocDmaCoherent` does not exist) + ~~AES key wrap (RFC 3394) for encrypted M3 key data~~ (primitives + EAPOL M3 KeyData unwrap landed 2026-05-03 — `aes-and-keywrap-v0.md` + `crc32-md5-base64-and-eapol-keywrap-v0.md`) + IRQ wiring on per-vendor MSI/MSI-X. Data-decode tier (envelope parsers + beacon walker) AND control tier (crypto + EAPOL + 4-way handshake + wdev/MLME + per-vendor upload + ring scaffolds) all landed 2026-05-01. Every code path that depends on DMA short-circuits to `Unsupported` and records the intent in the wifi-diag ring | Network flyout SSID picker, Settings → Network → Wi-Fi tab, captive-portal handler |
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
| P1 #7 Image / PDF / media viewers (PARTIAL — BMP landed 2026-05-02) | BMP is in (`kernel/apps/imageview.{h,cpp}`, see `imageview-bmp-v0.md`). PNG / JPEG each need their own parser TU; the existing app is structured to dispatch by extension. PDF is huge. Audio / video need P0 #2 first. | One-per-remaining-format |
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

### 1. Persistent file save / load [LANDED for Notes 2026-05-01; Files-FAT32 view 2026-05-02]
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
- **Today (2026-05-02):** Files app grew a FAT32 disk view —
  'D' switches into `DISK:/` mode (root listing, name + size +
  type tag), 'M' switches back to the ramfs view. 'R' rescans
  so newly-written files (fresh screenshots, log entries,
  saved notes) appear without restart. Enter on a `.BMP`
  dispatches to ImageView (raises the window + selects that
  file). See `imageview-bmp-v0.md` for the receiving end and
  the table row above.
- **Still missing:** `kernel/apps/files.{h,cpp}` has no
  copy / move / delete UI yet (FAT32 has the primitives; the
  app needs a confirmation modal + key bindings). FAT32
  subdirectory descent in disk view is deferred (root only
  in v0). `userland/libs/*` doesn't have a file-open-dialog
  primitive. Other apps (Settings, Calculator, Clock) don't
  persist any state yet.
- **Owners:** `kernel/apps/files.{h,cpp}` for the file-manager
  mutation UI; userland for the dialog primitive.

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

### 5. Settings panel [LANDED 2026-05-01; SHUTDOWN+REBOOT 2026-05-02]
- **Today:** v0 landed 2026-05-01 with theme cycle / opacity /
  high-contrast / default / log-out / TZ buttons. 2026-05-02
  added `REBOOT` (via `core::KernelReboot`) and `SHUTDOWN` (via
  `acpi::AcpiShutdown` → `arch::Halt`) so the user has a clean
  desktop-level exit path. Both flush `SessionRestoreSave()`
  first so window positions / theme survive the cycle. Window
  grew 280px → 340px to fit the 11-button column. `kIdCount`
  bumped 9 → 11.
- **Still missing:** Display brightness (no backlight driver).
  Sound (no audio driver). Keyboard layout (US hardcoded).
  Language (English hardcoded). Wi-Fi picker (no driver).
  Bluetooth pairing. Printer setup. Sleep / hibernate (S3
  / S0ix gated on ACPI AML).
- **Owners:** `kernel/apps/settings.{h,cpp}` (extend), plus the
  per-surface drivers when they land.

## P1 — common app expectations (hit in the first hour)

### 6. Terminal emulator (userland shell) [DEFERRED — console multiplex refactor]
- **Today:** `Ctrl+Alt+T` opens the kernel shell (ring-0).
  `userland/shell/` is a stub ELF; no real shell binary.
- **Expected:** a windowed terminal app that runs commands as a
  user-mode process.
- **Owners:** `userland/shell/`, plus a PTY layer (does not exist).

### 7. Image / PDF / media viewers [PARTIAL — BMP landed 2026-05-02]
- **Today (2026-05-02):** BMP viewer landed at
  `kernel/apps/imageview.{h,cpp}`. Pairs with Screenshot:
  every `Ctrl+Alt+P` capture is a 32-bpp top-down BMP this
  viewer reads byte-for-byte. Streaming decode via
  `Fat32ReadFileStream`, aspect-preserving NN downsample, no
  upscale. N/P/R + Left/Right keybinds, Start-menu entry,
  boot self-test. See `.claude/knowledge/imageview-bmp-v0.md`.
- **Still missing:** PNG / JPEG / GIF (each wants its own
  parser TU; the existing app dispatches by extension once
  parsers exist). PDF (huge). Audio / video need P0 #2 first.
  `mini_browser` is a smoke test, not a default browser app
  (`mini-browser-runs-on-duetos-v0.md`).
- **Expected:** native PNG/JPEG/PDF viewer apps; audio/video
  player once HDA lands.
- **Owners:** `kernel/apps/imageview*.cpp` (extend with PNG /
  JPEG dispatch); separate apps for PDF and media.

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
