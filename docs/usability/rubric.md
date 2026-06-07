# DuetOS Usability & Fidelity Rubric

> **Phase 1 output of the usability campaign** (`docs/superpowers/plans/2026-06-07-duetos-usability-campaign.md`).
> The grading bar for every surface, derived from peer OSes (SerenityOS, Haiku, Windows/Win32) and the documented NT/Win32 contract.

## How to grade

- **Native apps** (everything except the Win32/NT section): mark each criterion
  **meets** / **partial** / **missing** / **broken**.
- **Win32/NT fidelity** (PE surface): mark each criterion
  **matches** / **diverges** / **unimplemented**.

Every criterion cites the reference behavior it is derived from. A criterion graded
`meets`/`matches` is still recorded (as a coverage tick); only `partial`/`missing`/
`broken`/`diverges`/`unimplemented` produce a row in `findings.md`.

## Scoping caveats discovered during research (read before grading)

1. **External Windows `.exe`s are not yet runnable.** All 154 runnable PEs are embedded
   boot smokes (`crt_smoke`, `console_smoke`, `env_smoke`, `fs_smoke`, `heap_smoke`,
   `process_smoke`, `ntdll_smoke`, `hello_winapi`, …). The FAT32 file-based `PEEXEC`
   path (to run help.exe/sort/where/timeout/clip) is **not wired in**. The Phase-3 PE
   chaos vector is therefore limited to the embedded set unless PEEXEC is built first —
   that limitation is itself a campaign finding, not something to paper over.
2. **Win32 divergences must be live-verified.** The divergence table in the Win32 section
   reflects the *kernel thunk fallback* bodies. But PE imports bind to the **userland
   `kernel32.dll` EAT first** (per established pe-smoke behavior), which may carry real
   bodies that override the fallback. Treat the table as *candidate* divergences to
   confirm against a live boot before filing — do not file them as ground truth.

---

## Productivity

### calculator
- [ ] **Sequential vs precedence eval is consistent and documented** — `2+3*4` yields either 20 (left-to-right, Windows standard mode) or 14 (full precedence); whichever it is, it must be consistent. *source: [Windows Calculator — Wikipedia](https://en.wikipedia.org/wiki/Windows_Calculator)*
- [ ] **Keyboard digit & operator entry** — 0–9, +, -, *, /, Enter/=, Backspace all work from the physical keyboard. *source: [WinAero shortcuts](https://winaero.com/useful-calculator-keyboard-shortcuts-in-windows-10/)*
- [ ] **Decimal point input** — `.` inserts a decimal separator; `1/4 = 0.25`. *source: [MakeUseOf](https://www.makeuseof.com/windows-calculator-keyboard-shortcuts/)*
- [ ] **Divide-by-zero error state** — `X / 0 =` shows a readable error and remains usable (no crash/Infinity). *source: [microsoft/calculator #107](https://github.com/microsoft/calculator/issues/107)*
- [ ] **Clear (C/Esc) and Clear Entry (CE)** — full reset vs clear-current-operand are distinct. *source: [WinAero shortcuts](https://winaero.com/useful-calculator-keyboard-shortcuts-in-windows-10/)*
- [ ] **Backspace deletes last digit** without cancelling the pending operator. *source: [MakeUseOf](https://www.makeuseof.com/windows-calculator-keyboard-shortcuts/)*
- [ ] **Result is immediately reusable** — after `=`, typing an operator continues the chain. *source: [Windows Calculator — Wikipedia](https://en.wikipedia.org/wiki/Windows_Calculator)*

### notes
- [ ] **Freeform text input** at the cursor, no mode switch. *source: [SerenityOS TextEditor](https://man.serenityos.org/man1/Applications/TextEditor.html)*
- [ ] **Backspace & Delete** at buffer edges don't crash. *source: [SerenityOS TextEditor.cpp](https://github.com/SerenityOS/serenity/blob/master/Userland/Libraries/LibGUI/TextEditor.cpp)*
- [ ] **Arrow-key cursor movement**; Home/End to line bounds. *source: [SerenityOS TextEditor](https://man.serenityos.org/man1/Applications/TextEditor.html)*
- [ ] **Save** writes to a named file; reopening returns saved content exactly. *source: [Windows Notepad](https://www.bleepingcomputer.com/news/microsoft/windows-10-notepad-is-getting-better-utf-8-encoding-support/)*
- [ ] **Open/load existing file** shows persisted (non-blank) content. *source: [SerenityOS TextEditor](https://man.serenityos.org/man1/Applications/TextEditor.html)*
- [ ] **Dirty-state indicator** for unsaved changes, clears on save. *source: [Windows Notepad](https://www.techbloat.com/get-help-with-notepad-in-windows-10-2.html)*
- [ ] **Multi-line support** — Enter inserts newline; scrolls past visible area. *source: [SerenityOS TextEditor.cpp](https://github.com/SerenityOS/serenity/blob/master/Userland/Libraries/LibGUI/TextEditor.cpp)*

### calendar
- [ ] **Correct current date highlighted**, matches system clock (no off-by-one/epoch). *source: [MS Learn CalendarView](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/calendar-view)*
- [ ] **Month grid renders correctly** — days aligned to weekday columns, no blank rows. *source: [Page Flows](https://pageflows.com/resources/exploring-calendar-design/)*
- [ ] **Prev/next month navigation** re-renders correctly (incl. Feb leap year). *source: [MS Learn CalendarView](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/calendar-view)*
- [ ] **Month/year label updates** on navigation. *source: [Page Flows](https://pageflows.com/resources/exploring-calendar-design/)*
- [ ] **Return-to-today** control. *source: [MS Learn CalendarView](https://learn.microsoft.com/en-us/windows/apps/develop/ui/controls/calendar-view)*

### clock
- [ ] **Correct time on launch** (±2s, not frozen/epoch). *source: [myclockapp.com](https://myclockapp.com/)*
- [ ] **Live update every second** without interaction. *source: [digitalclock.live](https://digitalclock.live/)*
- [ ] **HH:MM always legible** at default size (12:00, 23:59). *source: [hugedigitalclock.com](https://hugedigitalclock.com/blog/app-features/8-key-features-of-the-huge-digital-clock-app/)*
- [ ] **No drift over 5 min** (±2s). *source: [digitalclock.live](https://digitalclock.live/)*

### charmap
- [ ] **Full glyph grid renders** — distinct glyphs for Basic Latin/Latin-1. *source: [umatechnology.org](https://umatechnology.org/what-is-charmap-exe-how-to-properly-use-it/)*
- [ ] **Single-char select & copy** to clipboard, pasteable. *source: [windowsreport.com](https://windowsreport.com/charmap-exe/)*
- [ ] **Glyph detail** — code point (U+00A9) + Unicode name. *source: [grokipedia](https://grokipedia.com/page/Character_Map_(Windows))*
- [ ] **Font selection** re-renders grid; missing glyphs show notdef not crash. *source: [umatechnology.org](https://umatechnology.org/what-is-charmap-exe-how-to-properly-use-it/)*
- [ ] **Keyboard search / go-to code point**, or arrow-nav + Enter select. *source: [GNOME Characters](https://help.gnome.org/gnome-help/tips-specialchars.html)*

---

## File Management

### files (file manager)
- [ ] Navigate into a subdirectory by double-click and return to parent (Up / Backspace). *source: [Haiku Tracker](https://www.haiku-os.org/docs/userguide/en/tracker.html)*
- [ ] Back / Forward history navigation. *source: [SerenityOS FileManager #80](https://github.com/SerenityOS/serenity/pull/80)*
- [ ] Multi-select with Shift-click (range) and Ctrl-click (toggle). *source: [Haiku Tracker](https://www.haiku-os.org/docs/userguide/en/tracker.html)*
- [ ] Rename in place (F2 / slow double-click). *source: Haiku Tracker; SerenityOS FileManager*
- [ ] Cut/Copy/Paste with a visible progress indicator. *source: Haiku Tracker; SerenityOS FileOperationProgressWidget*
- [ ] Delete to trash (not immediate permanent delete) via Del / context menu. *source: Haiku Tracker; Windows Recycle Bin*
- [ ] Show name, size, type, modified-date columns in list view. *source: Haiku Tracker; Windows Explorer*
- [ ] Type-ahead jump to first filename match. *source: [Haiku Tracker](https://www.haiku-os.org/docs/userguide/en/tracker.html)*

### trash
- [ ] List trashed items with original location + deletion date. *source: [XDG Trash spec](https://specifications.freedesktop.org/trash-spec/trashspec-1.0.html); Windows Recycle Bin*
- [ ] Restore selected item(s) to original path. *source: Windows Recycle Bin Restore; XDG trash spec*
- [ ] Permanently delete selected items. *source: Windows Recycle Bin; Haiku Trash*
- [ ] Empty trash (bulk permanent delete). *source: Windows "Empty Recycle Bin"; Haiku empty trash*
- [ ] Confirm before permanent delete / empty. *source: Windows confirmation; SerenityOS delete dialog*

### hexview
- [ ] Dual-pane hex + ASCII with left offset column. *source: [Haiku DiskProbe](https://www.haiku-os.org/docs/userguide/en/applications/diskprobe.html)*
- [ ] Jump to arbitrary byte offset (Go To dialog). *source: [SerenityOS HexEditor](https://github.com/SerenityOS/serenity/tree/master/Userland/Applications/HexEditor)*
- [ ] Find a byte pattern / ASCII string. *source: SerenityOS HexEditor FindDialog*
- [ ] Keyboard cursor nav in both panes; Tab switches panes. *source: Haiku DiskProbe*
- [ ] Value inspector: selected bytes as u8/u16/u32/u64 (LE+BE). *source: SerenityOS ValueInspectorModel; Haiku DiskProbe*
- [ ] Read-only by default; explicit save to write. *source: Haiku DiskProbe*

### imageview
- [ ] Open PNG, JPEG, BMP, GIF (minimum). *source: [Haiku ShowImage](https://www.haiku-os.org/docs/userguide/en/applications/showimage.html); [SerenityOS ImageViewer](https://man.serenityos.org/man1/Applications/ImageViewer.html)*
- [ ] Zoom in/out, fit-to-window, 1:1 reset. *source: Haiku ShowImage; SerenityOS ImageViewer*
- [ ] Rotate 90° CW and CCW. *source: SerenityOS ImageViewer; Haiku ShowImage*
- [ ] Prev/next image in folder via arrow keys. *source: SerenityOS ImageViewer; Haiku ShowImage*
- [ ] Fullscreen toggle. *source: SerenityOS ImageViewer; Haiku ShowImage*
- [ ] Pan a zoomed image by click-drag. *source: Haiku ShowImage*

---

## Settings

### display
- [ ] Resolution selector applies on confirm (with revert-timeout safety). *source: [Haiku Screen](https://www.haiku-os.org/docs/userguide/en/preferences/screen.html); Windows Display*
- [ ] Color depth / refresh rate selectable where supported. *source: Haiku Screen*
- [ ] Wallpaper (image or solid) takes effect immediately. *source: [Haiku Backgrounds](https://www.haiku-os.org/docs/userguide/en/preferences/backgrounds.html)*
- [ ] UI theme / accent color changes without reboot. *source: [Haiku Appearance](https://www.haiku-os.org/docs/userguide/en/preferences/appearance.html)*
- [ ] **Setting persists after re-opening the panel** (resolution, wallpaper, theme). *source: Haiku Screen; Windows*
- [ ] Safe-mode fallback so a bad resolution can't brick the session. *source: Haiku Screen; Windows VGA fallback*

### datetime
- [ ] Manual date/time set via widgets takes effect immediately. *source: [Haiku Time](https://www.haiku-os.org/docs/userguide/en/preferences/time.html); [MS Support](https://support.microsoft.com/en-us/windows/set-time-date-and-time-zone-settings-in-windows-dfaa7122-479f-5b98-2a7b-fa0b6e01b261)*
- [ ] Timezone selector updates the displayed clock without restart. *source: Haiku Time; Windows Central*
- [ ] NTP / "set automatically" toggle present. *source: Haiku Time*
- [ ] Tray/taskbar clock reflects the change within 1s. *source: Haiku Time*
- [ ] **Setting persists after re-opening the panel** (time + timezone). *source: Haiku Time; Windows*

### keyboard
- [ ] Key-repeat rate takes effect in a live test field. *source: [Haiku Input](https://www.haiku-os.org/docs/userguide/en/preferences/input.html); Windows Typing*
- [ ] Key-repeat delay independently adjustable. *source: Haiku Input*
- [ ] Keymap/layout selectable and applies immediately. *source: [Haiku Keymap](https://www.haiku-os.org/docs/userguide/en/preferences/keymap.html)*
- [ ] **Setting persists after re-opening the panel** (rate, delay, keymap). *source: Haiku Input; Windows*

### mouse
- [ ] Pointer speed applies immediately. *source: [Haiku Input](https://www.haiku-os.org/docs/userguide/en/preferences/input.html); [Windows mouse](https://support.microsoft.com/en-us/windows/change-mouse-settings-e81356a4-0e74-fe38-7d01-9d79fbf8712b)*
- [ ] Acceleration independently adjustable. *source: Haiku Input*
- [ ] Double-click speed adjustable with a live test target. *source: Haiku Input; [NinjaOne](https://www.ninjaone.com/blog/how-to-change-the-mouse-double-click-speed/)*
- [ ] Primary/secondary button swap configurable. *source: Haiku Input; Windows Mouse*
- [ ] **Setting persists after re-opening the panel** (speed, accel, dbl-click). *source: Haiku Input; Windows*

### sound
- [ ] Master volume takes effect immediately (audible). *source: [Haiku Media](https://www.haiku-os.org/docs/userguide/en/preferences/media.html); Windows Sound*
- [ ] Mute silences immediately; unmute restores level. *source: Haiku tray; [Windows 11](https://www.ninjaone.com/blog/mute-and-unmute-sound-output-in-windows-11/)*
- [ ] Output device selection when multiple outputs exist. *source: Haiku Media; Windows Sound*
- [ ] Per-application volume mixing accessible. *source: Haiku Media; [Windows Volume Mixer](https://onewebcare.com/windows/adjusting-volume-for-app/)*
- [ ] **Setting persists after re-opening the panel** (level + mute). *source: Haiku Media; Windows*

---

## System

### taskman
- [ ] Process list with name, PID, CPU%, memory; refreshes ≥1/s. *source: [HowToGeek Task Manager](https://www.howtogeek.com/405806/windows-task-manager-the-complete-guide/)*
- [ ] Column-header sort (asc/desc, active column indicated). *source: [HP Task Manager](https://www.hp.com/us-en/shop/tech-takes/how-to-use-task-manager-like-a-pro)*
- [ ] Kill selected process; it disappears within one refresh. *source: [TechCult](https://techcult.com/kill-resource-intensive-processes-with-task-manager/)*
- [ ] Per-process CPU/memory values are accurate (heavy proc ranks higher). *source: [MS Learn](https://learn.microsoft.com/en-us/troubleshoot/windows-server/support-tools/support-tools-task-manager)*
- [ ] Process list is live, not blank/static. *source: [Haiku ProcessController](https://www.haiku-os.org/docs/userguide/en/desktop-applets/processcontroller.html)*
- [ ] Feedback on kill failure (error, not silent). *source: [Haiku forum](https://discuss.haiku-os.org/t/how-to-terminate-a-freezing-program-on-haiku/9676)*

### sysmon
- [ ] Live CPU% bar/graph, updates ≥1/s. *source: [Haiku ActivityMonitor](https://www.haiku-os.org/docs/userguide/en/applications/activitymonitor.html)*
- [ ] Live memory usage (used vs total). *source: Haiku ActivityMonitor*
- [ ] Per-core breakdown (≥2-core differentiation). *source: [Windows Resource Monitor](https://en.wikipedia.org/wiki/Resource_Monitor)*
- [ ] Scrolling history graph (≥30s window). *source: Haiku ActivityMonitor*
- [ ] Numeric readout alongside graph. *source: [gHacks](https://www.ghacks.net/2017/12/28/a-detailed-windows-resource-monitor-guide/)*
- [ ] No crash/blank on idle. *source: Haiku ActivityMonitor*

### devicemgr
- [ ] Hierarchical device tree by bus/class. *source: [MS Learn Device Tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/device-tree)*
- [ ] Device name + class shown. *source: [MS Learn Device Manager](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-manager-details-tab)*
- [ ] Device status (functioning/error/no-driver). *source: [Lenovo Glossary](https://www.lenovo.com/us/en/glossary/device-manager/)*
- [ ] Hardware ID exposed (PCI VID:DID, USB VID:PID, ACPI HID). *source: [Dell](https://www.dell.com/support/kbdoc/en-us/000131022/how-to-find-drivers-for-devices-using-a-hardware-id)*
- [ ] Bound driver name shown (or "no driver"). *source: [Haiku Devices GSoC](https://www.haiku-os.org/blog/aquamatic123/2026-05-07_gsoc_2026_expanding_the_functionality_of_the_haiku_devices_application/)*
- [ ] Refresh / re-enumerate without restart. *source: Haiku Devices GSoC*

### terminal
- [ ] Char display + newline; clean normal output. *source: [xterm](https://x.org/releases/X11R6.8.2/doc/xterm.1.html)*
- [ ] Line editing: backspace + left/right arrows. *source: [GNU Readline](https://web.mit.edu/gnu/doc/html/rlman_1.html)*
- [ ] Ctrl+C interrupts foreground process, returns prompt. *source: [SerenityOS Terminal](https://man.serenityos.org/man1/Applications/Terminal.html)*
- [ ] Min command set: ls, cd, cat, echo, pwd, clear. *source: [Terminal nav](https://medium.com/towardsdev/basic-terminal-navigation-in-linux-pwd-ls-cd-cat-less-clear-history-89ec87e598b6)*
- [ ] Scrollback (≥500 lines). *source: xterm*
- [ ] Command history recall (up/down). *source: [SerenityOS #25039](https://github.com/SerenityOS/serenity/issues/25039)*
- [ ] Tab completion (filenames / builtins). *source: SerenityOS LibLine*

---

## Net / Security

### browser
- [ ] URL entry + Enter fetches and renders a page. *source: [Ladybird MVP](https://kevinliu.me/posts/building-a-browser/)*
- [ ] Readable text + basic layout (simple page legible; Acid3 not required). *source: [Ladybird newsletter](https://ladybird.org/newsletter/2026-05-31/)*
- [ ] Clickable hyperlink navigates; address bar updates. *source: [daily.dev](https://daily.dev/blog/make-a-web-browser-beginners-guide/)*
- [ ] Back navigation works. *source: [Ladybird MVP](https://kevinliu.me/posts/building-a-browser/)*
- [ ] Reload re-fetches current URL. *source: [Ladybird](https://github.com/LadybirdBrowser/ladybird)*
- [ ] Page `<title>` shown in window/tab. *source: [daily.dev](https://daily.dev/blog/make-a-web-browser-beginners-guide/)*

### netstatus
- [ ] Interface list enumerated (Ethernet/Wi-Fi/loopback). *source: [Haiku Network](https://www.haiku-os.org/docs/userguide/en/preferences/network.html)*
- [ ] IP address + subnet mask shown. *source: [Keenetic/Windows](https://help.keenetic.com/hc/en-us/articles/213965849)*
- [ ] Default gateway shown. *source: [Windows Central](https://www.windowscentral.com/how-check-network-connection-details-windows-11)*
- [ ] DNS server(s) shown. *source: Haiku Network*
- [ ] Link/connection state indicated. *source: [Windows NCSI](https://learn.microsoft.com/en-us/windows-server/networking/ncsi/ncsi-overview)*

### firewall
- [ ] Enable/disable toggle with unambiguous state. *source: [GUFW](https://manpages.ubuntu.com/manpages/bionic/man8/gufw.8.html); [Windows Defender FW](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules)*
- [ ] Existing rules listed (direction, port/addr, action). *source: Windows Defender FW; GUFW*
- [ ] Add a rule (port + allow/block) that takes effect. *source: [GUFW](https://phoenixnap.com/kb/gufw)*
- [ ] Remove a rule. *source: [GUFW](https://help.ubuntu.com/community/Gufw)*
- [ ] Default inbound policy visible. *source: [ufw essentials](https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands)*

---

## Win32 / NT Fidelity (PE surface)

> Grade: **matches** / **diverges** / **unimplemented**. Scope = APIs the embedded
> classic-import smoke PEs actually call, per `wiki/reference/Win32-Surface-Status.md`
> and `kernel/subsystems/win32/thunks_table.inc`. **These divergences reflect the kernel
> thunk fallback and MUST be live-verified** (imports may bind to the userland kernel32.dll
> EAT first — see caveat #2 at the top of this file).

DLLs present/thunked: kernel32 (413), ntdll (111), msvcrt (55), ucrtbase (61),
vcruntime140 (25), advapi32 (51), user32 (100), gdi32 (47).

### kernel32 — console & I/O
- [ ] `GetStdHandle` returns a usable non-INVALID handle. *source: [WriteConsole](https://learn.microsoft.com/en-us/windows/console/writeconsole)* — candidate: REAL
- [ ] `WriteConsoleW`/`WriteConsoleA` writes nChars, sets `*written`. *source: [WriteConsole](https://learn.microsoft.com/en-us/windows/console/writeconsole)* — candidate: REAL (`written` fidelity unverified)
- [ ] `WriteFile`/`ReadFile` transfer bytes, set `*written`/`*read`, return TRUE. *source: [WriteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)* — candidate: REAL
- [ ] `GetConsoleMode`/`GetConsoleScreenBufferInfo` fill nonzero values, return TRUE. *source: [GetConsoleMode](https://learn.microsoft.com/en-us/windows/console/getconsolemode)* — candidate: REAL
- [ ] `GetConsoleCP`/`GetConsoleOutputCP` return nonzero CP. *source: [GetConsoleCP](https://learn.microsoft.com/en-us/windows/console/getconsolecp)* — candidate: PIN (constant)

### kernel32 — command line & environment
- [ ] `GetCommandLineW`/`A` return non-NULL, non-empty. *source: [GetCommandLineW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew)* — candidate: REAL
- [ ] `GetEnvironmentVariableW`/`A` return value's char count if set, else 0+ERROR_ENVVAR_NOT_FOUND. *source: [GetEnvironmentVariableW](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablew)* — candidate: **DIVERGES** (fallback returns 0 always; live-verify against userland EAT)
- [ ] `SetEnvironmentVariableW`/`A` persist value readable by Get. *source: [SetEnvironmentVariable](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-setenvironmentvariablew)* — candidate: **DIVERGES** (write discarded in fallback)
- [ ] `GetEnvironmentStringsW`/`FreeEnvironmentStringsW` return block / TRUE. *source: [GetEnvironmentStrings](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentstringsw)* — candidate: REAL (block may be empty)
- [ ] `ExpandEnvironmentStringsW` expands %VAR%, returns char count. *source: [ExpandEnvironmentStrings](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-expandenvironmentstringsw)* — candidate: **DIVERGES** (returns 0)

### kernel32 — process & identity
- [ ] `GetCurrentProcess(Id)`/`GetCurrentThreadId` return valid/nonzero. *source: [GetCurrentProcessId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid)* — candidate: REAL
- [ ] `ExitProcess` terminates; exit code visible to parent. *source: [ExitProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-exitprocess)* — candidate: REAL
- [ ] `GetVersionExW`/`GetSystemInfo`/`GetComputerNameW` fill valid fields. *source: [GetVersionExW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getversionexw)* — candidate: REAL
- [ ] `GetSystemDirectoryW`/`GetWindowsDirectoryW` write paths. *source: [GetSystemDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemdirectoryw)* — candidate: PIN (both return Windows dir — System32 not distinct)

### kernel32 — file I/O
- [ ] `CreateFileW`(OPEN_EXISTING) returns valid handle or INVALID. *source: [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)* — candidate: REAL (CreateFileA always INVALID — DIVERGES)
- [ ] `GetFileSizeEx`/`SetFilePointerEx`/`CloseHandle` work. *source: [GetFileSizeEx](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfilesizeex)* — candidate: REAL
- [ ] `SetFilePointer`(non-zero seek) returns new position. *source: [SetFilePointer](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfilepointer)* — candidate: **DIVERGES** (returns 0 always)
- [ ] `GetFileAttributesW` returns valid attrs for existing path. *source: [GetFileAttributesW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileattributesw)* — candidate: **DIVERGES** (always INVALID_FILE_ATTRIBUTES)
- [ ] `FindFirstFileW`/`FindNextFileW` enumerate. *source: [FindFirstFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-findfirstfilew)* — candidate: **DIVERGES** (always INVALID_HANDLE_VALUE)
- [ ] `GetCurrentDirectoryW`/`GetFullPathNameW` write CWD/path. *source: [GetCurrentDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectoryw)* — candidate: GetCurrentDir REAL; GetFullPathName **DIVERGES** (0)

### kernel32 — memory, sync, module, strings
- [ ] `GetProcessHeap`/`HeapAlloc`/`HeapFree`/`HeapReAlloc`/`HeapSize` work. *source: [HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)* — candidate: REAL
- [ ] `VirtualAlloc`/`VirtualFree`/`VirtualProtect` work. *source: [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)* — candidate: REAL
- [ ] `WaitForSingleObject`/`WaitForMultipleObjects`, events, mutexes, `CreateThread`, `Sleep`, critical sections, TLS. *source: [WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)* — candidate: REAL
- [ ] `GetLastError`/`SetLastError` per-thread; `FormatMessageA` writes text. *source: [GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)* — candidate: REAL (FormatMessageW → 0)
- [ ] `GetModuleHandleW`/`GetProcAddress`/`GetModuleFileNameW`. *source: [GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)* — candidate: REAL
- [ ] `LoadLibraryW` returns HMODULE for preloaded DLL. *source: [LoadLibraryW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw)* — candidate: **DIVERGES** (always NULL)
- [ ] `MultiByteToWideChar`/`WideCharToMultiByte`(CP_UTF8). *source: [MultiByteToWideChar](https://learn.microsoft.com/en-us/windows/win32/api/stringapiset/nf-stringapiset-multibytetowidechar)* — candidate: REAL

### msvcrt / ucrtbase — CRT
- [ ] `__getmainargs`/`__wgetmainargs` fill argc/argv/envp; argv[0]=exe, argv[argc]=NULL. *source: [argc/argv](https://learn.microsoft.com/en-us/cpp/c-runtime-library/argc-argv-wargv)* — candidate: REAL
- [ ] `_initterm`/`_initterm_e` run init arrays. *source: [_initterm](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/initterm-initterm-e)* — candidate: REAL
- [ ] `malloc`/`free`/`realloc`, `strlen`/`strcmp`/`strcpy`, `memcpy`/`memmove`/`memset`. *source: [malloc](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/malloc)* — candidate: REAL
- [ ] `sprintf`/`_snprintf` format correctly. *source: [printf](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/printf-printf-l-wprintf-wprintf-l)* — candidate: REAL; **direct `printf` → DIVERGES (silent no-op)**
- [ ] `atoi` parses decimal incl. negative. *source: [atoi](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/atoi-atoi-l-wtoi-wtoi-l)* — candidate: **DIVERGES** (returns 0)
- [ ] `strtoul` parses unsigned decimal. *source: [strtoul](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoul-strtoul-l-wcstoul-wcstoul-l)* — candidate: REAL

### vcruntime140 — stack & SEH
- [ ] `__chkstk` page-probes large allocs without #PF. *source: [chkstk](https://learn.microsoft.com/en-us/cpp/runtime-checks/stack-checking)* — candidate: REAL
- [ ] `_CxxThrowException`/`__C_specific_handler` propagate to catch. *source: [SEH](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/cxxthrowexception)* — candidate: **DIVERGES** (terminates; no unwind — catch never entered)

### ntdll — primitives (marked REAL in wiki)
- [ ] `NtAllocateVirtualMemory`/`NtFreeVirtualMemory` STATUS_SUCCESS + valid base. *source: [NtAllocateVirtualMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntallocatevirtualmemory)* — candidate: REAL
- [ ] `NtQueryPerformanceCounter`/`NtQuerySystemTime`/`RtlGetVersion`. *source: [NtQuerySystemTime](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntquerysystemtime)* — candidate: REAL
- [ ] `RtlInitUnicodeString` sets Length(bytes)+Buffer. *source: [RtlInitUnicodeString](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitunicodestring)* — candidate: **DIVERGES** (void no-op; Length stays 0)
- [ ] `RtlAllocateHeap`/`RtlFreeHeap` ≡ HeapAlloc/HeapFree. *source: [RtlAllocateHeap](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlallocateheap)* — candidate: REAL
- [ ] `NtWaitForSingleObject`(direct) blocks, returns STATUS_WAIT_0. *source: [NtWaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntwaitforsingleobject)* — candidate: **DIVERGES** (STATUS_NOT_IMPLEMENTED)
- [ ] `RtlNtStatusToDosError`(non-zero) maps to Win32 error. *source: [RtlNtStatusToDosError](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror)* — candidate: **DIVERGES** (always 0)

### Candidate divergence summary (live-verify each before filing)

| API | Expected | Fallback actual |
|-----|----------|-----------------|
| `GetEnvironmentVariableW/A` | char count of value | 0 (not-found) |
| `SetEnvironmentVariableW/A` | persists value | write discarded |
| `ExpandEnvironmentStringsW` | expands %VAR% | 0 |
| `GetFileAttributesW` | attribute DWORD | INVALID_FILE_ATTRIBUTES |
| `FindFirstFileW`/`ExW` | enumerator handle | INVALID_HANDLE_VALUE |
| `GetFullPathNameW` | char count + path | 0 |
| `SetFilePointer` (non-zero) | new position | 0 |
| `LoadLibraryW/A/ExW` | HMODULE | NULL |
| `CreateFileA` | handle | INVALID_HANDLE_VALUE |
| `atoi` | decimal integer | 0 |
| `printf` (direct) | formatted output | silent no-op |
| `RtlInitUnicodeString` | Length+Buffer | no-op |
| `_CxxThrowException` | unwind to catch | terminate |
| `NtWaitForSingleObject` (direct) | STATUS_WAIT_0 | STATUS_NOT_IMPLEMENTED |
| `RtlNtStatusToDosError` (non-zero) | Win32 error | 0 |
| `GetSystemDirectoryW` | `...\System32` | Windows dir |

---

## Utility apps (common-sense bar, not externally researched)

These weren't part of the peer-OS research fan-out; grade against the obvious expectation
(opens cleanly, shows the content its name promises, closes cleanly).

### help
- [ ] Opens and displays readable help/documentation content (not blank/garbled).
- [ ] Scrolls if content exceeds the window.

### about
- [ ] Shows OS name + a version/build string + closes cleanly.

### screenshot
- [ ] Captures the current screen and saves/shows a result (the file or a preview appears).

### notify_center
- [ ] Opens and lists notifications (or an empty-state message); dismiss works.

### dbg
- [ ] Opens without crashing; primary view renders (this is a developer/diagnostic tool — bar is "doesn't fault, shows its panes").
