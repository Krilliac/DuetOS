# ToaruOS Clean-Room Port Plan

> **Audience:** Contributors landing slices that draw on ToaruOS prior art.
>
> **Status:** Active multi-session port.

## What this page is

A clean-room port plan for the subset of ToaruOS features that
fill a real gap in DuetOS. "Clean-room" is a specific engineering
discipline; this page records both the methodology and the
prioritized slice list.

ToaruOS is NCSA-licensed (BSD-style permissive). MIT and NCSA are
compatibility-compatible — attribution is the only legal requirement.
We are not relying on the legal permission as the reason to port;
we re-implement clean-room because (a) ToaruOS's design choices
(round-robin scheduler, userland Yutani compositor, POSIX-shaped
syscalls) diverge from DuetOS pillars and direct paste would import
those choices, and (b) the audit trail is simpler when our tree has
no third-party-derived files.

## Clean-room methodology

1. **Read for design, not for code.** When investigating a ToaruOS
   component, summarise the architecture (algorithm, data
   structures, state machine, file layout) into our wiki in our
   own words BEFORE writing any DuetOS code. The wiki summary is
   the work product of "reading."
2. **Implement from the wiki summary, not from the ToaruOS source.**
   The implementer references the wiki page, project pillars
   ([Project Pillars](../getting-started/Project-Pillars.md)), and
   existing DuetOS primitives (`Result<T,E>`, `KLOG_*`, `mm::*`,
   `sched::*`, capability gates). Open ToaruOS source only if a
   specific design question is unresolved — and if you do, return
   to step 1 and update the wiki summary so the next implementer
   doesn't have to.
3. **No file-level transplants.** Never paste a ToaruOS source
   file into our tree, even with comments edited. A function
   signature should differ in argument order, return shape, error
   reporting, namespace, naming convention, or all of the above.
   `Result<T, ErrorCode>` is the return shape; `bool`/`int`/`errno`
   are not.
4. **Cite in commit messages.** The first commit that lands a
   ported feature mentions "studied ToaruOS &lt;subsystem&gt; for the
   design" in the body. The wiki page records this too. We don't
   require attribution under the NCSA license unless we copy code,
   which we don't — but the citation makes the audit trail
   self-evident.
5. **Adapt to capability gating.** ToaruOS has no `kCap*` model;
   every effect a ported feature has on the system goes through a
   cap-gated syscall. Where ToaruOS does `open(O_RDWR)` we do
   `SYS_FILE_OPEN` with `kCapFsWrite`; where it does `mmap` we do
   `SYS_VMM_MAP` with `kCapMmAllocRing3`; etc. The kernel keeps
   authority.
6. **Honour the in-kernel architectural choice.** DuetOS's
   compositor, toolkit, menus, and font system are in-kernel.
   ToaruOS's are userland. We do not port Yutani's protocol; we
   extend the in-kernel compositor (`kernel/drivers/video/`).
7. **One symptom-cluster per slice.** A slice solves one
   subsystem-shaped problem (terminal, audio, decoder). The slice
   commit message says what landed, what's still gap, and what
   the next slice in the same area would do.

## Inventory: ToaruOS vs DuetOS gaps

Drawn from a full traversal of the ToaruOS tree (May 2026) and the
DuetOS in-tree survey. The "Skip" rows are documented so future
contributors don't relitigate them.

| Area | ToaruOS has | DuetOS has | Decision |
|---|---|---|---|
| Hybrid kernel core | Misaka | Native | **Skip** — already mature |
| Scheduler | Round-robin FIFO | MLFQ + per-CPU runqueues | **Skip** — DuetOS is ahead |
| Compositor / WM | Yutani (userland, PEX/packetfs IPC) | In-kernel `kernel/drivers/video/` | **Skip arch port** — different by design |
| GUI toolkit | `libtoaru_decorations`, `menu`, `button`, `markup` | In-kernel widgets, menus, buttons, dialogs | **Skip** — already mature |
| Native GUI apps | ~150 apps incl. file-browser, calculator, image viewer | ~20+ native apps under `kernel/apps/` | **Skip** — comparable surface |
| Windowed terminal emulator | `lib/termemu.c` + vendored terminal app | None — shell runs on framebuffer console | **PORT (slice 1)** |
| VT/ANSI escape parser | `lib/termemu.c` (xterm-flavoured) | None | **PORT (slice 1)** |
| Userland audio mixer / server | Per-driver in `modules/`; userland routing | Wiki only — HDA driver arms streams but no buffer pumping | **PORT (slice 2)** |
| JPEG decoder | `lib/jpeg.c` | Header parser only (`kernel/util/jpeg.cpp` = 28 LoC) | **PORT (slice 3)** |
| VBox guest additions | `modules/vbox.c` | None | **PORT (slice 4)** |
| VMware tools | `modules/vmware.c` | None | **PORT (slice 4)** |
| Userland dynamic linker | `libc/dlfcn/dl.c` (~1096 LoC) | None — DuetOS focuses on PE | **Skip** — out of pillar scope |
| Kuroko bytecode language | Vendored | None | **Skip** — Win32 PEs don't need it |
| `tarfs` ramdisk | `kernel/vfs/` | DuetFS, FAT32, ext4, NTFS | **Skip** — DuetOS is ahead |
| Network stack (IPv4 only) | `kernel/net/` | TCP + parsers + 802.11 stack | **Skip** — DuetOS is ahead |
| PNG decoder | `lib/png.c` | `kernel/util/png.cpp` (full decoder) | **Skip** — DuetOS has it |
| TrueType rendering | `lib/graphics.c` | `kernel/drivers/video/ttf.cpp` | **Skip** — DuetOS has it |
| Image viewer / file browser / calculator | Userland apps | In-kernel apps | **Skip** — DuetOS has them |

## Slice plan

### Status — port closed (2026-05-14)

Four slices landed; slice 4 deliberately deferred. The
maintainable subset of ToaruOS prior-art has been folded into
DuetOS. The clean-room methodology held: no source lines copied,
every component re-implemented from spec / DuetOS primitives.

| # | Slice | Status | Commit |
|---|---|---|---|
| 1 | Windowed terminal emulator + VT/ANSI parser | ✅ landed | `ddcc129` |
| 2 | In-kernel audio backend over HDA | ✅ landed | `5f5f3b4` |
| 3a | Console hide + terminal-shell merge | ✅ landed | `76c0379` |
| 3b | BSOD framebuffer panic UI + 8042 reset | ✅ landed | `0a5d98e` |
| 3 (rev) | Baseline JPEG decoder + ImageView wire-up | ✅ landed | `ee5ab45` |
| 4 | VBox / VMware guest additions | ⏸ deferred | — |

Non-port follow-ups that landed alongside the slices:
- `fad2ba0` — `panic-test` shell command + BSOD capture harness
- `30d65f1` — BSOD enhancements (build/uptime/CPU/task/CR/backtrace)
- `d0d13cf` — BSOD mitigations / heap / faults / held-locks / stack-top

### Why slice 4 was deferred

Guest additions (seamless cursor, host clipboard, dynamic
resolution, shared folders, drag-and-drop) are pure
developer-experience features. Three different vendor protocols
(VBox, VMware, virtio) would be ~1.5k LoC cumulatively. None has
a caller today: DuetOS doesn't have an interactive desktop demo
loop that needs window-resize, and the dev workflow is "headless
QEMU + serial + screendump" which guest additions don't change.
Per anti-bloat: "if you can't name the caller, don't write it."

Revisit when one of these triggers:
- A live demo / public release uses an interactive VirtualBox or
  VMware window where window-resize / clipboard would be
  noticeable friction.
- A QEMU-only dev iteration starts regularly copying large
  datasets between host and guest.
- The compositor gains a clipboard manager that wants to bridge
  to a host clipboard.

### Slice 1 — Windowed terminal emulator (landed)

**Goal**: a windowed terminal app under `kernel/apps/terminal.cpp`
that hosts a character-cell grid, parses a useful subset of
VT/ANSI escape sequences, renders via the existing TTF rasterizer,
and exposes a simple `WriteUtf8`/`FeedKey` API so a future slice
can wire it to the kernel shell, to a PE console, or to a remote
shell session.

**Files added**:
- `kernel/util/vt_parser.h` + `vt_parser.cpp` — UTF-8 + VT/ANSI
  parser as a callback-driven state machine; no allocations.
- `kernel/apps/terminal.h` + `terminal.cpp` — windowed app:
  cell grid, repaint, keyboard input, mirror-of-kernel-shell.
- Start-menu registration so the app shows in the system menu.

**Out of scope for slice 1** (some landed in 3a, others remain
follow-ups, not GAP markers in code — anti-bloat rule):
- Wiring to the kernel shell — landed in slice 3a via the
  `ConsoleRegisterMirror` hook (no shell refactor needed).
- Wiring to PE consoles (Win32 `WriteConsoleW`, `ReadConsoleA`).
- Mouse selection / clipboard.
- True SGR colour palette (slice 1 ships monochrome).
- Scrollback beyond what fits in the cell-grid backing store.

### Slice 2 — Audio path (landed)

In-kernel audio backend under `kernel/subsystems/audio/` that
owns the BDL + audio buffer ring above the HDA driver, exposes
`Init / Start / Stop / WritePcmS16Stereo / WriteSine`. v0 format
is fixed S16LE / 48 kHz / stereo. Confirmed end-to-end via the
StreamArm path on QEMU; codec walker on emulator returns 0
function groups so output is blocked there, but on real hardware
the path completes.

Out of scope (still): mixer (multi-producer summing), `SYS_AUDIO_*`
syscalls for ring-3 producers, `winmm!waveOutWrite` thunking,
IRQ-driven refill (IOC + interrupt path), format / sample-rate
conversion, microphone / capture path.

### Slice 3a — Console hide + terminal-shell merge (landed)

Three architectural changes addressing the "framebuffer console
hogs the desktop" + "merge the two terminals" concerns:

- `ConsoleSetPaintEnabled(bool)` — paint-toggle; off by default
  after the windowed Terminal initialises so the 80×40 region is
  reclaimed for the desktop.
- `ConsoleRegisterMirror(fn)` — single-slot callback teed for
  every shell-buffer write. The windowed Terminal registers as
  the mirror; the framebuffer console and the windowed terminal
  show the SAME shell content byte-for-byte without refactoring
  the 3,819 ConsoleWrite* call sites in the shell.
- Terminal keystrokes route directly to `ShellFeedChar` /
  `ShellSubmit` / `ShellBackspace` / `ShellHistoryPrev` /
  `ShellHistoryNext`.
- Ctrl+Alt+C + `console show|hide` shell command toggle paint
  state on demand.

### Slice 3b — BSOD framebuffer panic UI (landed)

`kernel/diag/bsod.{h,cpp}` — fullscreen panic panel hooked into
both `Panic()` and `PanicWithValue()` after the serial dump.
Layout (final, ~30 text rows of dense info):

- Title strip + subsystem / message / optional value
- Build flavor + git hash + date, uptime, CPU, current task
- RIP with symbol + `at file:line` continuation line
- RSP, RBP, CR2, CR3, CR4
- Mitigations one-liner (SMEP/SMAP/UMIP/IBRS/EIBRS/STIBP/RETPOLINE)
- Memory snapshot (heap used/free, frag, frames free)
- Fault counters (AV/NX/W/SO/RES/GP/UD)
- 6-frame symbolised RBP-chain backtrace
- Held locks (auto-skipped when none)
- 8-qword stack-top hex dump in two columns
- 10-line klog tail (ANSI escapes stripped)
- Footer "PRESS ANY KEY TO REBOOT"

Reboot via 8042 controller reset (write 0xFE to port 0x64).
`cli` before paint so the timer IRQ can't recompose the desktop
on top of the BSOD. Falls through to plain `Halt()` if the
framebuffer is unavailable.

Verified visually via `tools/test/capture-bsod.py` —
`panic-test` shell command triggers a real panic; the harness
sends it over the serial pump, waits for `[bsod] rendered`, and
issues a QEMU monitor `screendump` to capture the panel.

### Slice 3 (rev) — Baseline JPEG decoder (landed)

Promoted `kernel/util/jpeg.cpp` from 28-line header-validator
wrapper to a ~1k-line in-tree Baseline-DCT (SOF0) decoder. Full
ISO/IEC 10918-1 Baseline path: marker walking, 8/16-bit
quantisation tables, Huffman tables with 9-bit fast lookup,
byte-stuffing-aware bit reader, DC predictor + AC run/length,
integer fixed-point IDCT, grayscale + YCbCr→RGB output with NN
chroma upsampling. Wired into `kernel/apps/imageview.cpp`
alongside the existing BMP / TGA / PNG paths; `.JPG` / `.JPEG`
extensions classify, `DecodeJpeg` reads the file, calls the
decoder, NN-downsamples to the window. Selftest embeds a real
161-byte 16×16 grayscale Baseline JPEG (ImageMagick-generated)
and decodes it end-to-end.

Out of scope (still): progressive JPEG (SOF2 — rejected),
arithmetic-coded JPEG (SOF9..SOFE — rejected), 12/16-bit
precision, bilinear chroma upsample, EXIF orientation.

## Related Pages

- [External References](../reference/External-References.md)
- [Project Pillars](../getting-started/Project-Pillars.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
- [Audio](../drivers/Audio.md)
- [Anti-Bloat Guidelines](../tooling/Anti-Bloat-Guidelines.md)
