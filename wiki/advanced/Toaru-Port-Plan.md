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

### Slice 1 — Windowed terminal emulator (this slice)

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
  cell grid, repaint, keyboard input, demo echo loop.
- Start-menu registration so the app shows in the system menu.

**Out of scope for slice 1** (recorded as follow-ups, not GAP
markers in code — anti-bloat rule):
- Wiring to the kernel shell — the shell's hard-coupled
  `ConsoleWrite*` calls span ~20k LoC; refactor is its own slice.
- Wiring to PE consoles (Win32 `WriteConsoleW`, `ReadConsoleA`).
- Mouse selection / clipboard.
- True SGR colour palette (initial slice ships monochrome).
- Scrollback beyond what fits in the cell-grid backing store.

### Slice 2 — Audio path (future)

Bring up an in-kernel audio mixer + ring buffer that consumes
PCM submissions and feeds the HDA driver's BDL with real audio
data. End state: `winmm!waveOutWrite` produces sound. Reference:
ToaruOS `modules/hda.c` + `apps/play.c` audio submission path
(adapted to our cap-gated `SYS_AUDIO_*` surface — not
implemented yet, will be added in this slice).

### Slice 3 — JPEG decoder (future)

Promote `kernel/util/jpeg.cpp` from a header-only parser to a
full Baseline JPEG (SOF0) decoder. Reference: ToaruOS `lib/jpeg.c`.
Wire into the Image Viewer app when complete.

### Slice 4 — VBox / VMware guest additions (future)

Recognise the QEMU/VirtualBox/VMware hypervisor host, expose a
guest-tools driver that handles seamless cursor integration and
clipboard sharing. Reference: ToaruOS `modules/vbox.c`,
`modules/vmware.c`. Low priority (developer-experience win, not
production).

## Related Pages

- [External References](../reference/External-References.md)
- [Project Pillars](../getting-started/Project-Pillars.md)
- [Subsystem Isolation](../kernel/Subsystem-Isolation.md)
- [Compositor and Window Manager](../subsystems/Compositor.md)
- [Audio](../drivers/Audio.md)
- [Anti-Bloat Guidelines](../tooling/Anti-Bloat-Guidelines.md)
